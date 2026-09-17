#!/usr/bin/env python3
"""Read-only web/API server for the acl-report SQLite database.

Serves a small JSON API over a scan database produced by importer.py and
static files from ./web (both resolved relative to this script).

    python server.py [--database PATH] [--host 127.0.0.1] [--port 8000]
                     [--allow-remote] [--self-test]

The database is opened read-only, one connection per request. Refuses to
bind to a non-loopback address unless --allow-remote is given, because ACL
data is sensitive.

Stdlib only; portable across Linux and Windows.
"""

from __future__ import annotations

import argparse
import functools
import ipaddress
import json
import mimetypes
import os
import re
import sqlite3
import sys
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB = os.path.join(SCRIPT_DIR, "report.db")
DEFAULT_WEB_DIR = os.path.join(SCRIPT_DIR, "web")

MAX_LIMIT = 200          # hard cap for search/principal paging
DEFAULT_LIMIT = 50
MAX_CHILDREN_LIMIT = 5000
DEFAULT_CHILDREN_LIMIT = 2000
MAX_ANCESTOR_DEPTH = 1024   # recursion cap; node chains are far shallower
MAX_Q_LEN = 200
MAX_KEY_LEN = 512


# Schema copied verbatim from importer.py (SCHEMA). Kept self-contained so
# --self-test can build a matching database without importing the importer.
SCHEMA_SQL = """
CREATE TABLE scan_meta(
  id INTEGER PRIMARY KEY CHECK(id=1),
  imported_at TEXT NOT NULL,
  source_dir TEXT NOT NULL,
  summary_json TEXT NOT NULL
);
CREATE TABLE nodes(
  id INTEGER PRIMARY KEY,
  parent_id INTEGER,
  path TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  depth INTEGER NOT NULL,
  exist_subdir INTEGER,
  enabled_acl INTEGER,
  owner TEXT,
  posix_group TEXT,
  file_permission TEXT,
  access_permission INTEGER,
  file_system TEXT,
  volume INTEGER,
  inherit_parent INTEGER,
  ace_count INTEGER NOT NULL DEFAULT 0,
  acl_success INTEGER,
  acl_error TEXT,
  has_scan_error INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE aces(
  id INTEGER PRIMARY KEY,
  node_id INTEGER NOT NULL,
  ace_index INTEGER NOT NULL,
  effect TEXT NOT NULL,
  deny INTEGER NOT NULL,
  entry_type_name TEXT NOT NULL,
  principal_name TEXT NOT NULL,
  principal_key TEXT NOT NULL,
  auth_type_name TEXT NOT NULL,
  unresolved INTEGER NOT NULL,
  inheritance_name TEXT NOT NULL,
  no_propagate INTEGER NOT NULL,
  inherited_from TEXT,
  is_explicit INTEGER NOT NULL,
  perm INTEGER NOT NULL,
  perm_hex TEXT NOT NULL,
  rights TEXT NOT NULL,
  full_control INTEGER NOT NULL
);
CREATE TABLE principals(
  principal_key TEXT NOT NULL,
  principal_name TEXT NOT NULL,
  entry_type_name TEXT NOT NULL,
  ace_count INTEGER NOT NULL,
  PRIMARY KEY(principal_key, principal_name, entry_type_name)
);
CREATE TABLE scan_errors(
  id INTEGER PRIMARY KEY,
  node_id INTEGER,
  scanned_at TEXT,
  operation TEXT NOT NULL,
  path TEXT NOT NULL,
  kind TEXT,
  error_message TEXT NOT NULL
);
"""


class ApiError(Exception):
    """A structured client-facing error."""

    def __init__(self, status, code, message):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


# ---------------------------------------------------------------------------
# Database access
# ---------------------------------------------------------------------------

def _db_uri(path):
    """Build a read-only SQLite URI that works on POSIX and Windows."""
    p = os.path.abspath(path).replace("\\", "/")
    if not p.startswith("/"):
        p = "/" + p  # Windows: C:/... -> /C:/...
    return "file://" + urllib.parse.quote(p, safe="/:") + "?mode=ro"


def open_db(path):
    conn = sqlite3.connect(_db_uri(path), uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA query_only = 1")
    except sqlite3.Error:
        conn.close()
        raise
    return conn


# ---------------------------------------------------------------------------
# Query helpers (pure functions over a connection, exercised by --self-test)
# ---------------------------------------------------------------------------

def _ace_dict(row):
    """ACE row as a dict, plus an 'inherited' convenience flag for the UI."""
    item = dict(row)
    item["inherited"] = not bool(item.get("is_explicit"))
    return item


def q_status(conn):
    meta = conn.execute("SELECT * FROM scan_meta WHERE id = 1").fetchone()
    counts = {
        "nodes": conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
        "roots": conn.execute("SELECT COUNT(*) FROM nodes WHERE parent_id IS NULL").fetchone()[0],
        "aces": conn.execute("SELECT COUNT(*) FROM aces").fetchone()[0],
        "scan_errors": conn.execute("SELECT COUNT(*) FROM scan_errors").fetchone()[0],
        "linked_errors": conn.execute(
            "SELECT COUNT(*) FROM scan_errors WHERE node_id IS NOT NULL").fetchone()[0],
        "nodes_with_error": conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE has_scan_error = 1").fetchone()[0],
        "principals": conn.execute(
            "SELECT COUNT(DISTINCT principal_key) FROM principals").fetchone()[0],
    }
    meta_dict = dict(meta) if meta is not None else None

    summary = None
    if meta_dict is not None:
        try:
            parsed = json.loads(meta_dict.get("summary_json") or "")
            summary = parsed if isinstance(parsed, dict) else None
        except (ValueError, TypeError):
            summary = None

    payload = {"scan_meta": meta_dict, "summary": summary, "counts": counts}
    # Flatten a few fields the frontend status bar reads at the top level.
    payload["node_count"] = counts["nodes"]
    payload["nodes"] = counts["nodes"]
    payload["aces"] = counts["aces"]
    payload["scan_errors"] = counts["scan_errors"]
    payload["error_count"] = counts["scan_errors"]
    payload["principal_count"] = counts["principals"]
    if meta_dict is not None:
        payload["scanned_at"] = meta_dict.get("imported_at")
    if summary is not None:
        roots = summary.get("roots")
        if isinstance(roots, list) and roots:
            payload["root"] = roots[0]
        payload["host"] = summary.get("nas")
        payload["scanned_at"] = summary.get("finished_at") or payload.get("scanned_at")
    return payload


_NODE_COLS = (
    "n.id, n.parent_id, n.path, n.name, n.depth, n.exist_subdir, n.enabled_acl,"
    " n.owner, n.posix_group, n.file_permission, n.access_permission,"
    " n.file_system, n.volume, n.inherit_parent, n.ace_count, n.acl_success,"
    " n.acl_error, n.has_scan_error,"
    " EXISTS(SELECT 1 FROM nodes c WHERE c.parent_id = n.id) AS has_children"
)


def q_children(conn, parent_id, limit):
    if parent_id is None:
        where, params = "n.parent_id IS NULL", ()
    else:
        where, params = "n.parent_id = ?", (parent_id,)
    rows = conn.execute(
        "SELECT %s FROM nodes n WHERE %s"
        " ORDER BY n.name COLLATE NOCASE, n.name LIMIT ?" % (_NODE_COLS, where),
        params + (limit + 1,),
    ).fetchall()
    truncated = len(rows) > limit
    children = []
    for row in rows[:limit]:
        item = dict(row)
        item["has_children"] = bool(item["has_children"])
        children.append(item)
    return {
        "parent_id": parent_id,
        "children": children,
        "count": len(children),
        "truncated": truncated,
    }


def q_node(conn, node_id):
    row = conn.execute("SELECT * FROM nodes WHERE id = ?", (node_id,)).fetchone()
    if row is None:
        raise ApiError(404, "node_not_found", "No node with id %d" % node_id)
    node = dict(row)
    node["has_children"] = bool(conn.execute(
        "SELECT 1 FROM nodes WHERE parent_id = ? LIMIT 1", (node_id,)).fetchone())
    aces = conn.execute(
        "SELECT * FROM aces WHERE node_id = ? ORDER BY ace_index", (node_id,)
    ).fetchall()
    errors = conn.execute(
        "SELECT * FROM scan_errors WHERE node_id = ? OR (node_id IS NULL AND path = ?)"
        " ORDER BY id",
        (node_id, node["path"]),
    ).fetchall()
    return {
        "node": node,
        "aces": [_ace_dict(r) for r in aces],
        "scan_errors": [dict(r) for r in errors],
    }


def _like_contains(q):
    esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + esc + "%"


def q_search_paths(conn, q, limit):
    pattern = _like_contains(q)
    rows = conn.execute(
        "SELECT %s FROM nodes n"
        " WHERE n.path LIKE ? ESCAPE '\\' OR n.name LIKE ? ESCAPE '\\'"
        " ORDER BY n.depth, n.path COLLATE NOCASE LIMIT ?" % _NODE_COLS,
        (pattern, pattern, limit),
    ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["has_children"] = bool(item["has_children"])
        results.append(item)
    return {"query": q, "results": results, "count": len(results)}


def q_ancestors(conn, node_id):
    """Root-to-target chain for a node, using a parent_id recursive CTE.

    The recursion is depth-capped so a malformed cycle in the data cannot
    spin forever; the cap is far above any real path depth.
    """
    rows = conn.execute(
        "WITH RECURSIVE chain(id, parent_id, level) AS ("
        "  SELECT n.id, n.parent_id, 0 FROM nodes n WHERE n.id = ?"
        "  UNION ALL"
        "  SELECT p.id, p.parent_id, chain.level + 1"
        "    FROM nodes p JOIN chain ON p.id = chain.parent_id"
        "   WHERE chain.level < ?"
        ") SELECT %s FROM chain JOIN nodes n ON n.id = chain.id"
        " ORDER BY chain.level DESC" % _NODE_COLS,
        (node_id, MAX_ANCESTOR_DEPTH),
    ).fetchall()
    if not rows:
        raise ApiError(404, "node_not_found", "No node with id %d" % node_id)
    ancestors = []
    for row in rows:
        item = dict(row)
        item["has_children"] = bool(item["has_children"])
        ancestors.append(item)
    return {"ancestors": ancestors}


def q_search_principals(conn, q, limit):
    key_pattern = _like_contains(q.casefold())
    name_pattern = _like_contains(q)
    rows = conn.execute(
        "SELECT principal_key, principal_name, entry_type_name, ace_count"
        " FROM principals"
        " WHERE principal_key LIKE ? ESCAPE '\\' OR principal_name LIKE ? ESCAPE '\\'"
        " ORDER BY ace_count DESC, principal_name COLLATE NOCASE LIMIT ?",
        (key_pattern, name_pattern, limit),
    ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        # Aliases so both the descriptive and terse keys are available.
        item["key"] = item["principal_key"]
        item["name"] = item["principal_name"]
        item["type"] = item["entry_type_name"]
        results.append(item)
    return {"query": q, "results": results}


_DIRECT_ENTRY_SQL = (
    "SELECT a.id, a.node_id, n.path AS node_path, n.name AS node_name,"
    " a.ace_index, a.effect, a.deny, a.entry_type_name, a.principal_name,"
    " a.principal_key, a.auth_type_name, a.unresolved, a.inheritance_name,"
    " a.no_propagate, a.inherited_from, a.is_explicit, a.perm, a.perm_hex,"
    " a.rights, a.full_control"
    " FROM aces a LEFT JOIN nodes n ON n.id = a.node_id"
    " WHERE a.principal_key = ?"
)


def principal_lookup_key(key):
    """Match the importer's canonical form: trimmed + Unicode casefolded."""
    return key.strip().casefold()


def q_principal(conn, key, limit, offset):
    canon = principal_lookup_key(key)
    total = conn.execute(
        "SELECT COUNT(*) FROM aces a WHERE a.principal_key = ?", (canon,),
    ).fetchone()[0]
    rows = conn.execute(
        _DIRECT_ENTRY_SQL + " ORDER BY n.path COLLATE NOCASE, a.ace_index LIMIT ? OFFSET ?",
        (canon, limit, offset),
    ).fetchall()
    return {
        "key": key,
        "principal_key": canon,
        "total": total,
        "limit": limit,
        "offset": offset,
        "entries": [_ace_dict(r) for r in rows],
        "note": (
            "Direct ACL entries for this principal only; these are not effective "
            "access. Inherited and group-derived permissions are not resolved."
        ),
    }


# ---------------------------------------------------------------------------
# Request parameter validation
# ---------------------------------------------------------------------------

_INT_RE = re.compile(r"-?\d{1,18}\Z")


def param_int(qs, name, default=None, required=False, minimum=None):
    values = qs.get(name)
    raw = values[0].strip() if values else ""
    if not raw:
        if required:
            raise ApiError(400, "missing_param", "Query parameter '%s' is required" % name)
        return default
    if not _INT_RE.match(raw):
        raise ApiError(400, "invalid_int", "Query parameter '%s' must be an integer" % name)
    value = int(raw)
    if minimum is not None and value < minimum:
        raise ApiError(400, "out_of_range", "Query parameter '%s' must be >= %d" % (name, minimum))
    return value


def param_limit(qs, default=DEFAULT_LIMIT, maximum=MAX_LIMIT):
    value = param_int(qs, "limit", default=default, minimum=1)
    return min(value, maximum)


def param_q(qs):
    values = qs.get("q")
    raw = values[0].strip() if values else ""
    if not raw:
        raise ApiError(400, "missing_param", "Query parameter 'q' is required")
    if len(raw) > MAX_Q_LEN:
        raise ApiError(400, "query_too_long", "Query 'q' must be at most %d characters" % MAX_Q_LEN)
    return raw


def param_key(qs):
    values = qs.get("key")
    raw = values[0].strip() if values else ""
    if not raw:
        raise ApiError(400, "missing_param", "Query parameter 'key' is required")
    if len(raw) > MAX_KEY_LEN:
        raise ApiError(400, "query_too_long", "Query 'key' must be at most %d characters" % MAX_KEY_LEN)
    return raw


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    server_version = "acl-report/1.0"
    protocol_version = "HTTP/1.1"
    db_path = DEFAULT_DB
    web_dir = DEFAULT_WEB_DIR

    def __init__(self, *args, db_path=None, web_dir=None, **kwargs):
        if db_path is not None:
            self.db_path = db_path
        if web_dir is not None:
            self.web_dir = web_dir
        super().__init__(*args, **kwargs)

    # -- plumbing -----------------------------------------------------------

    def _security_headers(self, content_type, length):
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline';"
            " script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none';"
            " frame-ancestors 'none'",
        )

    def _send_json(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self._security_headers("application/json; charset=utf-8", len(data))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_error(self, code, message=None, explain=None):
        """Structured JSON for protocol-level errors too."""
        short = self.responses.get(code, ("Error", ""))[0]
        try:
            self._send_json(code, {"error": {"code": "http_%d" % code,
                                              "message": message or short}})
        except Exception:
            pass

    def _connect(self):
        if not os.path.isfile(self.db_path):
            raise ApiError(503, "database_missing", "Database not found: %s" % self.db_path)
        try:
            return open_db(self.db_path)
        except sqlite3.Error as exc:
            raise ApiError(503, "database_unavailable", "Cannot open database: %s" % exc)

    def _query(self, fn, *args):
        conn = self._connect()
        try:
            return fn(conn, *args)
        finally:
            conn.close()

    # -- routing ------------------------------------------------------------

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        path = urllib.parse.unquote(parts.path)
        qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        try:
            if path.startswith("/api/"):
                self._send_json(200, self._handle_api(path, qs))
            else:
                self._serve_static(parts.path)
        except ApiError as exc:
            self._send_json(exc.status, {"error": {"code": exc.code, "message": exc.message}})
        except sqlite3.Error as exc:
            self._send_json(500, {"error": {"code": "database_error", "message": str(exc)}})
        except BrokenPipeError:
            pass
        except Exception:
            import traceback
            traceback.print_exc(file=sys.stderr)
            self._send_json(500, {"error": {"code": "internal_error",
                                             "message": "Internal server error"}})

    def do_HEAD(self):
        self.do_GET()

    def _reject_method(self):
        self._send_json(405, {"error": {"code": "method_not_allowed",
                                         "message": "Only GET is supported"}})

    do_POST = do_PUT = do_DELETE = do_PATCH = _reject_method

    def _handle_api(self, path, qs):
        routes = {
            "/api/status": lambda qs: self._query(q_status),
            "/api/children": self._api_children,
            "/api/node": self._api_node,
            "/api/ancestors": self._api_ancestors,
            "/api/search/paths": self._api_search_paths,
            "/api/search/principals": self._api_search_principals,
            "/api/principal": self._api_principal,
        }
        route = routes.get(path)
        if route is None:
            raise ApiError(404, "unknown_endpoint", "No API endpoint at %s" % path)
        return route(qs)

    def _api_children(self, qs):
        parent_id = param_int(qs, "parent_id", default=None, minimum=0)
        limit = param_limit(qs, default=DEFAULT_CHILDREN_LIMIT, maximum=MAX_CHILDREN_LIMIT)
        return self._query(q_children, parent_id, limit)

    def _api_node(self, qs):
        node_id = param_int(qs, "id", required=True, minimum=0)
        return self._query(q_node, node_id)

    def _api_ancestors(self, qs):
        node_id = param_int(qs, "id", required=True, minimum=0)
        return self._query(q_ancestors, node_id)

    def _api_search_paths(self, qs):
        q = param_q(qs)
        return self._query(q_search_paths, q, param_limit(qs))

    def _api_search_principals(self, qs):
        q = param_q(qs)
        return self._query(q_search_principals, q, param_limit(qs))

    def _api_principal(self, qs):
        key = param_key(qs)
        limit = param_limit(qs)
        offset = param_int(qs, "offset", default=0, minimum=0)
        return self._query(q_principal, key, limit, offset)

    # -- static files -------------------------------------------------------

    def _serve_static(self, raw_path):
        rel = urllib.parse.unquote(raw_path).replace("\\", "/")
        if rel.endswith("/") or rel == "":
            rel += "index.html"
        segments = [seg for seg in rel.split("/") if seg not in ("", ".")]
        if any(seg == ".." for seg in segments):
            raise ApiError(403, "forbidden", "Path traversal is not allowed")

        base = os.path.realpath(self.web_dir)
        target = os.path.realpath(os.path.join(base, *segments)) if segments else base
        if target != base and not target.startswith(base + os.sep):
            raise ApiError(403, "forbidden", "Path traversal is not allowed")
        if not os.path.isfile(target):
            raise ApiError(404, "not_found", "Static file not found: %s" % rel)

        ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json",
                                                   "image/svg+xml"):
            ctype += "; charset=utf-8"
        with open(target, "rb") as fh:
            data = fh.read()
        self.send_response(200)
        self._security_headers(ctype, len(data))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)


def make_handler(db_path, web_dir):
    return functools.partial(Handler, db_path=db_path, web_dir=web_dir)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def is_loopback(host):
    if not host:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def serve(db_path, host, port, web_dir=DEFAULT_WEB_DIR):
    httpd = ThreadingHTTPServer((host, port), make_handler(db_path, web_dir))
    httpd.daemon_threads = True
    return httpd


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Read-only web/API server for an acl-report SQLite database.")
    parser.add_argument("--database", default=DEFAULT_DB,
                        help="Path to the acl-report SQLite database (default: %(default)s)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default: %(default)s)")
    parser.add_argument("--port", type=int, default=8000,
                        help="Bind port (default: %(default)s)")
    parser.add_argument("--allow-remote", action="store_true",
                        help="Allow binding to a non-loopback address")
    parser.add_argument("--self-test", action="store_true",
                        help="Run a self-test against a temporary database and exit")
    args = parser.parse_args(argv)

    if args.self_test:
        return run_self_test()

    if not is_loopback(args.host) and not args.allow_remote:
        parser.error(
            "refusing to bind to non-loopback address %r; ACL data is sensitive. "
            "Pass --allow-remote to override." % args.host)

    if not os.path.isfile(args.database):
        sys.stderr.write("note: database %s not found; API will return 503 until it exists\n"
                         % args.database)

    httpd = serve(args.database, args.host, args.port)
    sys.stderr.write("acl-report server listening on http://%s:%d/ (db=%s)\n"
                     % (args.host, args.port, args.database))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
    return 0


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_SELFTEST_SUMMARY = {
    "finished_at": "2026-01-01T00:00:10+00:00",
    "nas": "https://example.invalid",
    "roots": ["/data"],
    "discovery": {"directories": 4, "files": 0, "list_error": 1},
    "acl": {"acl_ok": 3, "acl_error": 1, "skipped": 0, "remaining": 0},
}


def _seed_selftest_db(path):
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA_SQL)
        conn.execute(
            "INSERT INTO scan_meta(id, imported_at, source_dir, summary_json)"
            " VALUES(1,?,?,?)",
            ("2026-01-01T00:00:11+00:00", "/tmp/acl-selftest-source",
             json.dumps(_SELFTEST_SUMMARY)),
        )
        conn.executemany(
            "INSERT INTO nodes(id, parent_id, path, name, depth, exist_subdir,"
            " enabled_acl, owner, posix_group, file_permission, access_permission,"
            " file_system, volume, inherit_parent, ace_count, acl_success, acl_error,"
            " has_scan_error) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (1, None, "/data", "data", 0, 1, 1, "admin", "users", "rwx", 3,
                 "ext4", 1, 0, 2, 1, None, 0),
                (2, 1, "/data/team", "team", 1, 1, 1, "admin", "users", "rwx", 3,
                 "ext4", 1, 0, 1, 1, None, 0),
                (3, 2, "/data/team/docs", "docs", 2, 1, 1, "admin", "users", "rwx", 3,
                 "ext4", 1, 0, 1, 1, None, 0),
                (4, 1, "/data/od", "od", 1, 1, 0, "admin", "users", "rwx", 3,
                 "ext4", 1, 0, 0, 0, "HTTP 500", 1),
            ],
        )
        conn.executemany(
            "INSERT INTO aces(id, node_id, ace_index, effect, deny, entry_type_name,"
            " principal_name, principal_key, auth_type_name, unresolved,"
            " inheritance_name, no_propagate, inherited_from, is_explicit, perm,"
            " perm_hex, rights, full_control) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [
                (1, 1, 0, "allow", 0, "user", "DOM\\Bob", "dom\\bob", "domain", 0,
                 "subfolders and files", 0, None, 1, 16383, "0x3fff", "read;write", 1),
                (2, 1, 1, "deny", 1, "group", "DOM\\Domain Users", "dom\\domain users",
                 "domain", 0, "this folder", 0, None, 1, 1, "0x1", "deny", 0),
                (3, 2, 0, "allow", 0, "user", "DOM\\Bob", "dom\\bob", "domain", 0,
                 "this folder", 0, "/data", 0, 5, "0x5", "read", 0),
            ],
        )
        conn.execute(
            "INSERT INTO scan_errors(id, node_id, scanned_at, operation, path, kind,"
            " error_message) VALUES(?,?,?,?,?,?,?)",
            (1, 4, "2026-01-01T00:00:03+00:00", "get_acl", "/data/od", "directory",
             "HTTP 500 from acl.cgi: boom"),
        )
        conn.executemany(
            "INSERT INTO principals(principal_key, principal_name, entry_type_name,"
            " ace_count) VALUES(?,?,?,?)",
            [
                ("dom\\bob", "DOM\\Bob", "user", 2),
                ("dom\\domain users", "DOM\\Domain Users", "group", 1),
            ],
        )
        conn.commit()
    finally:
        conn.close()


def _http_get(base, path):
    try:
        with urllib.request.urlopen(base + path, timeout=10) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def _pure_self_test(db_path):
    """Exercise the query helpers. Returns nothing; raises on failure."""
    conn = open_db(db_path)
    try:
        status = q_status(conn)
        assert status["counts"] == {
            "nodes": 4, "roots": 1, "aces": 3, "scan_errors": 1,
            "linked_errors": 1, "nodes_with_error": 1, "principals": 2,
        }, status["counts"]
        assert status["root"] == "/data" and status["host"] == "https://example.invalid"
        assert status["scanned_at"] == "2026-01-01T00:00:10+00:00"
        assert status["node_count"] == 4 and status["error_count"] == 1
        assert status["summary"]["acl"]["acl_ok"] == 3

        roots = q_children(conn, None, 100)
        assert [c["id"] for c in roots["children"]] == [1], roots
        assert roots["children"][0]["has_children"] is True
        assert roots["children"][0]["has_scan_error"] == 0
        kids = q_children(conn, 1, 100)
        assert [c["id"] for c in kids["children"]] == [4, 2], kids  # ordered by name
        assert {c["id"]: c["has_children"] for c in kids["children"]} == {4: False, 2: True}
        assert q_children(conn, 3, 100)["children"] == []
        assert q_children(conn, 1, 1)["truncated"] is True

        leaf = q_node(conn, 3)
        assert leaf["node"]["path"] == "/data/team/docs"
        assert leaf["node"]["has_children"] is False
        assert leaf["aces"] == [] and leaf["scan_errors"] == []
        detail = q_node(conn, 2)
        assert detail["node"]["has_children"] is True
        assert len(detail["aces"]) == 1 and detail["aces"][0]["effect"] == "allow"
        assert detail["aces"][0]["inherited"] is True  # is_explicit == 0
        assert detail["aces"][0]["inherited_from"] == "/data"
        root_aces = q_node(conn, 1)["aces"]
        assert [a["inherited"] for a in root_aces] == [False, False]  # is_explicit == 1
        od = q_node(conn, 4)
        assert len(od["scan_errors"]) == 1 and od["scan_errors"][0]["node_id"] == 4
        assert od["node"]["acl_success"] == 0 and od["node"]["has_scan_error"] == 1

        chain = q_ancestors(conn, 3)["ancestors"]
        assert [a["id"] for a in chain] == [1, 2, 3], chain  # exact root -> target order
        assert [a["path"] for a in chain] == ["/data", "/data/team", "/data/team/docs"], chain
        assert [a["depth"] for a in chain] == [0, 1, 2], chain
        assert [a["has_children"] for a in chain] == [True, True, False], chain
        assert [a["id"] for a in q_ancestors(conn, 1)["ancestors"]] == [1]  # root is its own chain
        assert [a["id"] for a in q_ancestors(conn, 4)["ancestors"]] == [1, 4]
        try:
            q_ancestors(conn, 99999)
            raise AssertionError("expected ApiError")
        except ApiError as exc:
            assert exc.status == 404 and exc.code == "node_not_found"

        # Defensive: a malformed parent cycle must terminate at the depth cap.
        cycle = sqlite3.connect(":memory:")
        cycle.row_factory = sqlite3.Row
        try:
            cycle.executescript(SCHEMA_SQL)
            cycle.execute(
                "INSERT INTO nodes(id, parent_id, path, name, depth, ace_count, has_scan_error)"
                " VALUES(1, 2, '/a', 'a', 0, 0, 0), (2, 1, '/b', 'b', 0, 0, 0)")
            looped = q_ancestors(cycle, 1)["ancestors"]
            assert len(looped) == MAX_ANCESTOR_DEPTH + 1, len(looped)
        finally:
            cycle.close()

        paths = q_search_paths(conn, "team", 200)
        assert sorted(r["id"] for r in paths["results"]) == [2, 3], paths
        assert q_search_paths(conn, "%", 200)["results"] == []  # wildcard escaped

        principals = q_search_principals(conn, "bob", 200)
        assert len(principals["results"]) == 1, principals
        entry = principals["results"][0]
        assert entry["principal_key"] == "dom\\bob" and entry["ace_count"] == 2, entry
        assert entry["entry_type_name"] == "user" and entry["type"] == "user"
        assert entry["principal_name"] == "DOM\\Bob" and entry["name"] == "DOM\\Bob"
        assert entry["key"] == "dom\\bob"
        groups = q_search_principals(conn, "DOMAIN", 200)
        assert len(groups["results"]) == 1, groups
        assert groups["results"][0]["principal_key"] == "dom\\domain users"
        assert groups["results"][0]["entry_type_name"] == "group"

        direct = q_principal(conn, "DOM\\Bob", 200, 0)
        assert direct["total"] == 2 and len(direct["entries"]) == 2, direct
        assert direct["principal_key"] == "dom\\bob"
        assert all(e["node_path"] for e in direct["entries"])
        assert "not effective" in direct["note"]
        assert q_principal(conn, "  dom\\bob  ", 1, 1)["entries"][0]["node_path"]
        assert q_principal(conn, "dom\\BOB", 200, 0)["total"] == 2  # casefolded
        assert q_principal(conn, "nobody", 200, 0)["total"] == 0

        for probe in (lambda: param_q({}), lambda: param_key({}),
                      lambda: param_int({"id": ["abc"]}, "id", required=True),
                      lambda: param_int({"offset": ["-1"]}, "offset", minimum=0),
                      lambda: param_int({}, "id", required=True),
                      lambda: param_q({"q": ["x" * (MAX_Q_LEN + 1)]})):
            try:
                probe()
                raise AssertionError("expected ApiError")
            except ApiError:
                pass
        assert param_limit({"limit": ["100000"]}) == MAX_LIMIT
        assert param_int({"limit": [""]}, "limit", default=7) == 7
    finally:
        conn.close()


def _http_self_test(db_path, web_dir):
    """Exercise the live HTTP endpoints. Returns the bound server."""
    httpd = serve(db_path, "127.0.0.1", 0, web_dir)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        code, headers, body = _http_get(base, "/api/status")
        assert code == 200, (code, body)
        status = json.loads(body)
        assert status["counts"]["aces"] == 3 and status["node_count"] == 4
        assert headers.get("Cache-Control", "").startswith("no-store")
        assert headers.get("X-Content-Type-Options") == "nosniff"

        assert json.loads(_http_get(base, "/api/children")[2])["count"] == 1
        assert json.loads(_http_get(base, "/api/children?parent_id=1")[2])["count"] == 2
        assert json.loads(_http_get(base, "/api/node?id=3")[2])["node"]["id"] == 3
        chain = json.loads(_http_get(base, "/api/ancestors?id=3")[2])["ancestors"]
        assert [a["id"] for a in chain] == [1, 2, 3], chain
        assert [a["path"] for a in chain] == ["/data", "/data/team", "/data/team/docs"], chain
        assert chain[1]["has_children"] is True and chain[2]["has_children"] is False
        assert json.loads(_http_get(base, "/api/search/paths?q=team")[2])["count"] == 2
        principal_hits = json.loads(_http_get(base, "/api/search/principals?q=bob")[2])
        assert principal_hits["results"][0]["ace_count"] == 2
        assert json.loads(_http_get(base, "/api/principal?key=DOM%5CBob")[2])["total"] == 2

        code, _, body = _http_get(base, "/api/node?id=abc")
        assert code == 400 and json.loads(body)["error"]["code"] == "invalid_int", (code, body)
        code, _, body = _http_get(base, "/api/node?id=99999")
        assert code == 404 and json.loads(body)["error"]["code"] == "node_not_found", (code, body)
        code, _, body = _http_get(base, "/api/ancestors?id=99999")
        assert code == 404 and json.loads(body)["error"]["code"] == "node_not_found", (code, body)
        code, _, body = _http_get(base, "/api/ancestors?id=abc")
        assert code == 400 and json.loads(body)["error"]["code"] == "invalid_int", (code, body)
        code, _, body = _http_get(base, "/api/ancestors")
        assert code == 400 and json.loads(body)["error"]["code"] == "missing_param", (code, body)
        code, _, body = _http_get(base, "/api/search/paths")
        assert code == 400 and json.loads(body)["error"]["code"] == "missing_param", (code, body)
        code, _, body = _http_get(base, "/api/unknown")
        assert code == 404 and json.loads(body)["error"]["code"] == "unknown_endpoint", (code, body)

        code, headers, body = _http_get(base, "/")
        assert code == 200 and b"acl-report" in body, (code, body)
        assert headers.get("Content-Type", "").startswith("text/html")
        code, _, _ = _http_get(base, "/%2e%2e/%2e%2e/etc/passwd")
        assert code in (403, 404), code
        code, _, body = _http_get(base, "/missing.css")
        assert code == 404 and json.loads(body)["error"]["code"] == "not_found"
    finally:
        httpd.shutdown()
        httpd.server_close()


def run_self_test():
    tmp = tempfile.mkdtemp(prefix="acl-report-selftest-")
    db_path = os.path.join(tmp, "acl.db")
    web_dir = os.path.join(tmp, "web")
    os.makedirs(web_dir)
    with open(os.path.join(web_dir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write("<!doctype html><title>acl-report</title>")
    _seed_selftest_db(db_path)

    _pure_self_test(db_path)
    print("query self-tests OK")

    try:
        _http_self_test(db_path, web_dir)
    except PermissionError as exc:
        # Sandboxes without socket privileges cannot run the HTTP checks.
        print("http self-tests SKIPPED (socket unavailable: %s)" % exc)
        print("self-test OK (query helpers only)")
        return 0

    print("http self-tests OK")
    print("self-test OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
