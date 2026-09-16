#!/usr/bin/env python3
"""Stream a filesystem ACL scan export into a normalized SQLite database.

Reads a scan output directory (summary.json, manifest.jsonl, paths.csv,
aces.csv, errors.jsonl) and builds a fresh SQLite database beside the target
path. Large files are streamed line by line and written in batches; indexes are
created after the bulk load; integrity is verified with PRAGMA integrity_check;
the finished temp database is then swapped into place with os.replace(), so the
target path is only ever the previous database or the new one, never partial.

Standard library only.

Canonical paths are kept exactly as the scanner produced them (slash separated,
no trailing slash on directory nodes). principal_key is normalized with Unicode
casefold plus whitespace trimming only; missing domain separators are not
invented (see principal_key()).

Usage:
    python importer.py SOURCE_DIR [--database PATH] [--progress N]
    python importer.py --self-test
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
import sys
import tempfile
import time
from datetime import datetime, timezone

# --------------------------------------------------------------------------
# Schema contract
# --------------------------------------------------------------------------

SCHEMA = """
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

# Built only after the bulk load.
INDEX_TEMPLATES = (  # %s is the table name
    "CREATE INDEX idx_%s_parent ON %s(parent_id)",
    "CREATE INDEX idx_%s_depth ON %s(depth)",
    "CREATE INDEX idx_%s_name ON %s(name)",
    "CREATE INDEX idx_%s_owner ON %s(owner)",
    "CREATE INDEX idx_%s_group ON %s(posix_group)",
    "CREATE INDEX idx_%s_fs ON %s(file_system)",
    "CREATE INDEX idx_%s_ace_count ON %s(ace_count)",
    "CREATE INDEX idx_%s_has_error ON %s(has_scan_error)",
)
ACES_INDEXES = (
    "CREATE INDEX idx_aces_node ON aces(node_id)",
    "CREATE INDEX idx_aces_principal ON aces(principal_key)",
    "CREATE INDEX idx_aces_name ON aces(principal_name)",
    "CREATE INDEX idx_aces_auth ON aces(auth_type_name)",
)
ERR_INDEXES = (
    "CREATE INDEX idx_scan_errors_node ON scan_errors(node_id)",
)

NODE_COLUMNS = (
    "id", "parent_id", "path", "name", "depth", "exist_subdir", "enabled_acl",
    "owner", "posix_group", "file_permission", "access_permission",
    "file_system", "volume", "inherit_parent", "ace_count", "acl_success",
    "acl_error", "has_scan_error",
)
ACE_COLUMNS = (
    "id", "node_id", "ace_index", "effect", "deny", "entry_type_name",
    "principal_name", "principal_key", "auth_type_name", "unresolved",
    "inheritance_name", "no_propagate", "inherited_from", "is_explicit",
    "perm", "perm_hex", "rights", "full_control",
)
ERROR_COLUMNS = (
    "id", "node_id", "scanned_at", "operation", "path", "kind", "error_message",
)

REQUIRED_FILES = (
    "summary.json", "manifest.jsonl", "paths.csv", "aces.csv", "errors.jsonl",
)


# --------------------------------------------------------------------------
# Parsing helpers
# --------------------------------------------------------------------------

def _raise_csv_field_limit():
    """Allow very large single CSV fields (error pages can be long)."""
    limit = sys.maxsize
    while True:
        try:
            csv.field_size_limit(limit)
            return
        except OverflowError:
            limit //= 10


_raise_csv_field_limit()


def parse_bool(value):
    """Safely coerce a scanner value to 1/0/None.

    Accepts Python bools, ints, and strings such as "true"/"False"/"1"/"0";
    anything unrecognized (including None and empty string) yields None.
    """
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, int):
        return 1 if value else 0
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "y", "on"):
            return 1
        if v in ("0", "false", "no", "n", "off"):
            return 0
    return None


def parse_int(value):
    """Coerce a scanner value to int or None (empty/garbage -> None)."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        try:
            return int(v, 10)
        except ValueError:
            try:
                return int(float(v))
            except ValueError:
                return None
    return None


def parse_text(value):
    """Return a stripped string, or None when empty/missing."""
    if value is None:
        return None
    text = value if isinstance(value, str) else str(value)
    text = text.strip()
    return text or None


def principal_key(name):
    """Normalize a principal name: Unicode casefold + whitespace trimming.

    Deliberately does NOT split or synthesize a domain separator. A scanner
    name like "FOCACCIAGROUP\\Marketing" keeps its existing separator; a bare
    "asustorz" stays bare. Only surrounding whitespace is removed and the
    comparison form is casefolded.
    """
    return (name or "").strip().casefold()


def node_name(path):
    """Last path segment; empty for the filesystem root."""
    trimmed = path.rstrip("/")
    if not trimmed:
        return ""
    return trimmed.rsplit("/", 1)[-1]


def node_depth(path, fallback=None):
    """Depth inferred from a canonical path (segment count minus one)."""
    if fallback is not None:
        return fallback
    trimmed = path.rstrip("/")
    if not trimmed or trimmed == "/":
        return 0
    return trimmed.lstrip("/").count("/")


class ImportError_(RuntimeError):
    """Fatal problem with the source data or the target database."""


class Progress:
    """Throttled progress reporter; silent when interval <= 0."""

    def __init__(self, interval):
        self.interval = interval or 0
        self._last = 0.0
        self._label = ""

    def bump(self, label, count, force=False):
        if self.interval <= 0:
            return
        now = time.monotonic()
        if not force and label == self._label and (now - self._last) < self.interval:
            return
        self._label = label
        self._last = now
        print(f"[importer] {label}: {count:,}", file=sys.stderr)


# --------------------------------------------------------------------------
# Source reading
# --------------------------------------------------------------------------

def check_source_dir(source_dir):
    if not os.path.isdir(source_dir):
        raise ImportError_(f"source directory does not exist: {source_dir}")
    missing = [f for f in REQUIRED_FILES
               if not os.path.isfile(os.path.join(source_dir, f))]
    if missing:
        raise ImportError_(
            "missing required source file(s) in "
            f"{source_dir}: {', '.join(missing)}")


def iter_jsonl(path):
    """Yield parsed JSON objects from a JSONL file, skipping blank lines.

    Reads line by line via a buffered text stream so arbitrarily large files
    never load fully into memory.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def read_summary(path):
    """Read summary.json, returning (raw_text, parsed_dict_or_None)."""
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        raw = handle.read()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = None
    if not isinstance(parsed, dict):
        parsed = None
    return raw, parsed


def meta_from_manifest(obj):
    """Pull scalar node columns out of one manifest.jsonl record."""
    metadata = obj.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
    path = parse_text(obj.get("path")) or parse_text(metadata.get("file_path"))
    if not path:
        path = "/"
    path = path.rstrip("/") or "/"
    is_dir = metadata.get("is_dir")
    return {
        "path": path,
        "name": parse_text(metadata.get("filename")) or node_name(path),
        "depth": parse_int(obj.get("depth")),
        "exist_subdir": parse_bool(metadata.get("exist_subdir")),
        "enabled_acl": parse_bool(metadata.get("enabled_acl")),
        "owner": parse_text(metadata.get("owner")),
        "posix_group": parse_text(metadata.get("group")),
        "file_permission": parse_text(metadata.get("file_permission")),
        "access_permission": parse_int(metadata.get("access_permission")),
        "file_system": parse_text(metadata.get("file_system")),
        "volume": parse_int(metadata.get("volume")),
        "is_dir": is_dir,
    }


def iter_manifest_nodes(path):
    """Yield node metadata dicts for every non-pseudo-root manifest record."""
    for obj in iter_jsonl(path):
        if obj.get("pseudo_root"):
            continue
        yield meta_from_manifest(obj)


def iter_paths_rows(path):
    """Yield ACL status rows from paths.csv as (path, column-dict)."""
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_path = parse_text(row.get("path"))
            if row_path:
                yield row_path, row


def iter_aces_rows(path):
    """Yield ACE rows from aces.csv as (path, column-dict)."""
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row_path = parse_text(row.get("path"))
            if row_path:
                yield row_path, row


def iter_error_rows(path):
    """Yield normalized error dicts from errors.jsonl."""
    for obj in iter_jsonl(path):
        row_path = parse_text(obj.get("path"))
        if row_path is None:
            metadata = obj.get("metadata")
            if isinstance(metadata, dict):
                row_path = parse_text(metadata.get("file_path"))
        message = obj.get("error")
        if message is None:
            message = obj.get("message")
        yield {
            "scanned_at": parse_text(obj.get("scanned_at")),
            "operation": parse_text(obj.get("operation")) or "unknown",
            "path": row_path or "",
            "kind": parse_text(obj.get("kind")),
            "error_message": parse_text(message) or "",
        }


# --------------------------------------------------------------------------
# Database build
# --------------------------------------------------------------------------

DEFAULT_BATCH = 1000


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _prepare(conn):
    """Configure the connection for a fast, single-writer bulk load."""
    conn.execute("PRAGMA journal_mode=OFF")
    conn.execute("PRAGMA synchronous=OFF")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-65536")
    conn.executescript(SCHEMA)


def _stream_insert(conn, sql, rows_iter, batch, progress=None, label=""):
    """Insert an iterable of row tuples in batches; return the row count."""
    buf = []
    count = 0
    for row in rows_iter:
        buf.append(row)
        count += 1
        if len(buf) >= batch:
            conn.executemany(sql, buf)
            buf.clear()
            if progress is not None:
                progress.bump(label, count)
    if buf:
        conn.executemany(sql, buf)
    if progress is not None and count:
        progress.bump(label, count, force=True)
    return count


def _node_rows(source_dir):
    """Yield node tuples in NODE_COLUMNS order from manifest.jsonl."""
    for node_id, meta in enumerate(
            iter_manifest_nodes(os.path.join(source_dir, "manifest.jsonl")), start=1):
        path = meta["path"]
        depth = meta["depth"]
        if depth is None:
            depth = node_depth(path)
        yield (
            node_id, None, path, meta["name"] or node_name(path), depth,
            meta["exist_subdir"], meta["enabled_acl"], meta["owner"],
            meta["posix_group"], meta["file_permission"],
            meta["access_permission"], meta["file_system"], meta["volume"],
            None, 0, None, None, 0,
        )


def _ace_rows(source_dir, node_ids):
    """Yield ACE tuples in ACE_COLUMNS order from aces.csv.

    ACEs whose path has no corresponding node are skipped, since aces.node_id
    is NOT NULL.
    """
    ace_id = 0
    for row_path, row in iter_aces_rows(os.path.join(source_dir, "aces.csv")):
        node_id = node_ids.get(row_path)
        if node_id is None:
            continue
        ace_id += 1
        name = parse_text(row.get("name")) or ""
        yield (
            ace_id, node_id, parse_int(row.get("ace_index")) or 0,
            parse_text(row.get("effect")) or "",
            parse_bool(row.get("deny")) or 0,
            parse_text(row.get("entry_type_name")) or "",
            name, principal_key(name),
            parse_text(row.get("auth_type_name")) or "",
            parse_bool(row.get("unresolved")) or 0,
            parse_text(row.get("inheritance_name")) or "",
            parse_bool(row.get("no_propagate")) or 0,
            parse_text(row.get("inherited_from")),
            parse_bool(row.get("is_explicit")) or 0,
            parse_int(row.get("perm")) or 0,
            parse_text(row.get("perm_hex")) or "",
            parse_text(row.get("rights")) or "",
            parse_bool(row.get("full_control_marker")) or 0,
        )


def _parent_path(path):
    """Parent canonical path, or None for a filesystem root."""
    if not path or path == "/":
        return None
    idx = path.rfind("/")
    if idx < 0:
        return None
    if idx == 0:
        return "/"
    return path[:idx]


def _exec_columns(columns):
    cols = ",".join(columns)
    marks = ",".join("?" * len(columns))
    return cols, marks


def load_acl_status(conn, source_dir, progress):
    """Apply paths.csv ACL status onto nodes (inherit_parent, ace_count, ...)."""
    status = {}
    count = 0
    for row_path, row in iter_paths_rows(os.path.join(source_dir, "paths.csv")):
        status[row_path] = (
            parse_int(row.get("inherit_parent")),
            parse_int(row.get("ace_count")),
            parse_bool(row.get("success")),
            parse_text(row.get("error")),
        )
        count += 1
        progress.bump("paths.csv", count)
    if status:
        conn.executemany(
            "UPDATE nodes SET inherit_parent=?, ace_count=COALESCE(?, ace_count), "
            "acl_success=?, acl_error=? WHERE path=?",
            [(ip, ac, ok, err, p) for p, (ip, ac, ok, err) in status.items()])
    progress.bump("paths.csv", count, force=True)
    return count


def load_scan_errors(conn, source_dir, node_ids, progress):
    """Insert errors.jsonl rows, linking node_id by path when possible."""
    state = {"n": 0}

    def rows():
        for err in iter_error_rows(os.path.join(source_dir, "errors.jsonl")):
            state["n"] += 1
            yield (
                state["n"], node_ids.get(err["path"]), err["scanned_at"],
                err["operation"], err["path"], err["kind"], err["error_message"],
            )

    cols, marks = _exec_columns(ERROR_COLUMNS)
    total = _stream_insert(
        conn, f"INSERT INTO scan_errors({cols}) VALUES({marks})",
        rows(), DEFAULT_BATCH, progress, "errors.jsonl")
    return total


def resolve_parents(conn):
    """Fill parent_id after load, independent of manifest ordering.

    Streams nodes through an on-disk temp table so it works regardless of how
    many nodes exist and does not assume manifest is parent-first.
    """
    conn.execute("CREATE TEMP TABLE path_id(path TEXT PRIMARY KEY, nid INTEGER)")
    conn.executemany("INSERT OR IGNORE INTO path_id VALUES(?,?)",
                     conn.execute("SELECT path,id FROM nodes"))
    conn.execute("CREATE TEMP TABLE child_parent("
                 "child_id INTEGER PRIMARY KEY, parent_path TEXT)")
    cur = conn.execute("SELECT id,path FROM nodes")
    buf = []
    for node_id, path in cur:
        buf.append((node_id, _parent_path(path)))
        if len(buf) >= DEFAULT_BATCH:
            conn.executemany("INSERT INTO child_parent VALUES(?,?)", buf)
            buf.clear()
    if buf:
        conn.executemany("INSERT INTO child_parent VALUES(?,?)", buf)
    conn.execute(
        "UPDATE nodes SET parent_id=("
        "  SELECT path_id.nid FROM path_id "
        "  WHERE path_id.path=child_parent.parent_path) "
        "FROM child_parent WHERE nodes.id=child_parent.child_id")


def link_errors(conn):
    """Backfill node_id for errors that were inserted before nodes existed,
    and flag nodes that have any linked scan error."""
    conn.execute(
        "UPDATE scan_errors SET node_id=("
        "  SELECT path_id.nid FROM path_id "
        "  WHERE path_id.path=scan_errors.path) "
        "WHERE node_id IS NULL")
    conn.execute(
        "UPDATE nodes SET has_scan_error=1 "
        "WHERE id IN (SELECT node_id FROM scan_errors WHERE node_id IS NOT NULL)")


def build_principals(conn):
    """Aggregate ACE counts per (principal_key, principal_name, entry_type_name).

    The aces table holds millions of rows but only a few hundred distinct
    principals, so the read path searches this tiny rollup instead of scanning
    aces. Principal search matches on principal_key/principal_name, and the
    (key, name, type) grain preserves exactly the rows the old GROUP BY over
    aces produced.
    """
    conn.execute(
        "INSERT INTO principals(principal_key, principal_name, entry_type_name, ace_count) "
        "SELECT principal_key, principal_name, entry_type_name, COUNT(*) "
        "FROM aces GROUP BY principal_key, principal_name, entry_type_name")


def create_indexes(conn):
    for table in ("nodes",):
        for template in INDEX_TEMPLATES:
            conn.execute(template % (table, table))
    for statement in ACES_INDEXES + ERR_INDEXES:
        conn.execute(statement)


def write_meta(conn, source_dir, summary_raw):
    conn.execute(
        "INSERT INTO scan_meta(id, imported_at, source_dir, summary_json) "
        "VALUES(1,?,?,?)",
        (utc_now(), os.path.abspath(source_dir), summary_raw))


def integrity_check(conn):
    row = conn.execute("PRAGMA integrity_check").fetchone()
    result = row[0] if row else "no result"
    if result != "ok":
        raise ImportError_(f"integrity_check failed: {result}")
    return result


def db_counts(conn):
    return {
        "nodes": conn.execute("SELECT count(*) FROM nodes").fetchone()[0],
        "aces": conn.execute("SELECT count(*) FROM aces").fetchone()[0],
        "principals": conn.execute("SELECT count(*) FROM principals").fetchone()[0],
        "scan_errors": conn.execute("SELECT count(*) FROM scan_errors").fetchone()[0],
        "linked_errors": conn.execute(
            "SELECT count(*) FROM scan_errors WHERE node_id IS NOT NULL").fetchone()[0],
        "nodes_with_error": conn.execute(
            "SELECT count(*) FROM nodes WHERE has_scan_error=1").fetchone()[0],
    }


def build_database(source_dir, db_path, batch=DEFAULT_BATCH, progress=None):
    """Build a fresh database atomically at db_path from source_dir.

    The database is constructed beside the target in a temporary file and
    swapped in with os.replace() only after it is complete and passes
    integrity_check. On any failure the temp file is removed and db_path is
    left untouched.
    """
    progress = progress if progress is not None else Progress(0)
    check_source_dir(source_dir)

    target_dir = os.path.dirname(os.path.abspath(db_path)) or "."
    os.makedirs(target_dir, exist_ok=True)
    summary_raw, _summary = read_summary(os.path.join(source_dir, "summary.json"))

    fd, tmp_path = tempfile.mkstemp(
        prefix=".acl-import-", suffix=".tmp", dir=target_dir)
    os.close(fd)
    conn = sqlite3.connect(tmp_path)
    try:
        _prepare(conn)
        node_cols, node_marks = _exec_columns(NODE_COLUMNS)
        node_count = _stream_insert(
            conn, f"INSERT INTO nodes({node_cols}) VALUES({node_marks})",
            _node_rows(source_dir), batch, progress, "manifest.jsonl")

        node_ids = dict(conn.execute("SELECT path,id FROM nodes"))
        ace_cols, ace_marks = _exec_columns(ACE_COLUMNS)
        ace_count = _stream_insert(
            conn, f"INSERT INTO aces({ace_cols}) VALUES({ace_marks})",
            _ace_rows(source_dir, node_ids), batch, progress, "aces.csv")

        load_acl_status(conn, source_dir, progress)
        load_scan_errors(conn, source_dir, node_ids, progress)
        resolve_parents(conn)
        link_errors(conn)
        build_principals(conn)
        create_indexes(conn)
        write_meta(conn, source_dir, summary_raw)
        conn.commit()
        integrity = integrity_check(conn)
        stats = db_counts(conn)
        conn.execute("PRAGMA optimize")
        conn.close()
        conn = None
        os.replace(tmp_path, db_path)
    except BaseException:
        if conn is not None:
            conn.close()
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    stats.update({"imported": node_count, "aces_read": ace_count,
                  "integrity": integrity, "database": os.path.abspath(db_path)})
    return stats


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------

def write_fixture(source_dir):
    """Write a tiny synthetic scan export, deliberately out of parent order."""
    os.makedirs(source_dir, exist_ok=True)

    def jline(obj):
        return json.dumps(obj, ensure_ascii=False)

    # Child appears before its parent to exercise ordering-independent linkage.
    manifest = [
        {"path": "/data/team/docs", "depth": 2, "pseudo_root": False,
        "metadata": {"filename": "docs", "is_dir": 1, "exist_subdir": 0,
                     "enabled_acl": True, "file_system": "ext4", "volume": 1,
                      "owner": r"DOM\alice", "group": r"DOM\Domain Users",
                      "file_permission": "000", "access_permission": 8191}},
        {"path": "/data", "depth": 0, "pseudo_root": False,
        "metadata": {"file_path": "/data", "is_dir": 1, "exist_subdir": 1,
                     "enabled_acl": True, "file_system": "ext4", "volume": 1,
                      "owner": r"DOM\alice", "group": r"DOM\Domain Users",
                      "file_permission": "755", "access_permission": 8191}},
        {"path": "/data/team", "depth": 1, "pseudo_root": False,
         "metadata": {"filename": "team", "is_dir": 1, "exist_subdir": 1,
                      "enabled_acl": "true", "file_system": "ext4",
                      "volume": 1, "owner": r"DOM\alice",
                      "group": r"DOM\Domain Users", "file_permission": "755",
                      "access_permission": 8191}},
        {"path": "/data/od", "depth": 1, "pseudo_root": False,
         "metadata": {"filename": "od", "is_dir": 1, "exist_subdir": 0,
                      "enabled_acl": False, "volume": 1}},
        {"path": "/data/ghost", "depth": 1, "pseudo_root": True,
         "metadata": {"filename": "ghost", "is_dir": 1}},
    ]
    with open(os.path.join(source_dir, "manifest.jsonl"), "w",
              encoding="utf-8") as handle:
        for record in manifest:
            handle.write(jline(record) + "\n")

    paths_rows = [
        ("2026-01-01T00:00:00+00:00", "/data", "directory", "", 0, 2, "True", ""),
        ("2026-01-01T00:00:01+00:00", "/data/team", "directory", "", 0, 1,
         "True", ""),
        ("2026-01-01T00:00:02+00:00", "/data/team/docs", "directory", "", 0, 0,
         "True", ""),
        ("2026-01-01T00:00:03+00:00", "/data/od", "directory", "", 0, None,
         "False", "HTTP 500 from acl.cgi: boom"),
    ]
    with open(os.path.join(source_dir, "paths.csv"), "w", encoding="utf-8",
              newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["scanned_at", "path", "kind", "enabled_acl",
                         "inherit_parent", "ace_count", "success", "error"])
        writer.writerows(paths_rows)

    aces_header = ["scanned_at", "path", "kind", "inherit_parent", "ace_index",
                   "deny", "effect", "entry_type", "entry_type_name", "name",
                   "auth_type", "auth_type_name", "unresolved", "inheritance",
                   "inheritance_name", "no_propagate", "inherited_from",
                   "is_explicit", "perm", "perm_hex", "perm_type", "rights",
                   "full_control_marker"]
    aces_rows = [
        ("2026-01-01T00:00:00+00:00", "/data", "directory", 0, 0, 0, "allow",
         2, "group", "DOM\\Domain Users", 1, "domain", 0, 1,
         "this_folder_subfolders_and_files", 0, "", "False", 2047, "0x7ff",
         20, "list;write", "False"),
        ("2026-01-01T00:00:00+00:00", "/data", "directory", 0, 1, 1, "deny",
         1, "user", "  DOM\\Bob  ", 1, "domain", 0, 0, "this_folder_only", 0,
         "", "True", 4, "0x4", 18, "read", "False"),
        ("2026-01-01T00:00:01+00:00", "/data/team", "directory", 0, 0, 0,
         "allow", 1, "user", "asustorz", 0, "local", 0, 1,
         "this_folder_subfolders_and_files", 0,
         "/data/", "False", 16383, "0x3fff", 18, "full", "True"),
        # Orphan ACE: path has no node, must be skipped (node_id is NOT NULL).
        ("2026-01-01T00:00:09+00:00", "/nowhere", "directory", 0, 0, 0,
         "allow", 1, "user", "ghost", 0, "local", 0, 0, "this_folder_only", 0,
         "", "True", 1, "0x1", 18, "read", "False"),
    ]
    with open(os.path.join(source_dir, "aces.csv"), "w",
              encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(aces_header)
        writer.writerows(aces_rows)

    errors = [
        {"record_type": "error", "scanned_at": "2026-01-01T00:00:03+00:00",
         "operation": "get_acl", "path": "/data/od", "kind": "directory",
         "error": "HTTP 500 from acl.cgi: boom\nsecond line"},
    ]
    with open(os.path.join(source_dir, "errors.jsonl"), "w",
              encoding="utf-8") as handle:
        for record in errors:
            handle.write(jline(record) + "\n")

    summary = {
        "finished_at": "2026-01-01T00:00:10+00:00",
        "nas": "https://example.invalid",
        "roots": ["/data"],
        "discovery": {"directories": 4, "files": 0, "list_error": 1},
        "acl": {"acl_ok": 3, "acl_error": 1, "skipped": 0, "remaining": 0},
    }
    with open(os.path.join(source_dir, "summary.json"), "w",
              encoding="utf-8") as handle:
        json.dump(summary, handle, indent=2)


def self_test():
    """Build a tiny fixture in a temporary directory and assert the results."""
    with tempfile.TemporaryDirectory(prefix="acl-importer-selftest-") as tmp:
        source_dir = os.path.join(tmp, "source")
        db_path = os.path.join(tmp, "out", "acl.db")
        write_fixture(source_dir)
        build_database(source_dir, db_path)

        conn = sqlite3.connect(db_path)
        try:
            by_path = {path: (nid, parent)
                       for nid, parent, path in
                       conn.execute("SELECT id,parent_id,path FROM nodes")}
            # Ordering-independent parent linkage.
            assert by_path["/data"][1] is None, "root parent must be NULL"
            assert by_path["/data/team"][1] == by_path["/data"][0]
            assert by_path["/data/team/docs"][1] == by_path["/data/team"][0]
            assert "/data/ghost" not in by_path, "pseudo_root must be skipped"

            # paths.csv status applied.
            inherit, ace_count, acl_ok, acl_err = conn.execute(
                "SELECT inherit_parent,ace_count,acl_success,acl_error "
                "FROM nodes WHERE path='/data'").fetchone()
            assert (inherit, ace_count, acl_ok) == (0, 2, 1)
            assert acl_err is None
            od = conn.execute(
                "SELECT acl_success,has_scan_error FROM nodes WHERE path='/data/od'"
            ).fetchone()
            assert od[0] == 0 and od[1] == 1, "error node must be flagged"

            # Boolean parsing of the string form.
            assert conn.execute(
                "SELECT enabled_acl FROM nodes WHERE path='/data/team'"
            ).fetchone()[0] == 1
            assert conn.execute(
                "SELECT enabled_acl FROM nodes WHERE path='/data/od'"
            ).fetchone()[0] == 0

            # ACEs imported; orphan skipped; principal_key casefolded + trimmed.
            assert conn.execute("SELECT count(*) FROM aces").fetchone()[0] == 3
            keys = dict(conn.execute(
                "SELECT principal_name,principal_key FROM aces"))
            assert keys["DOM\\Bob"] == "dom\\bob", keys
            assert keys["DOM\\Domain Users"] == "dom\\domain users"

            # Principals rollup mirrors the aces GROUP BY.
            assert conn.execute(
                "SELECT count(*) FROM principals").fetchone()[0] == 3
            assert dict(conn.execute(
                "SELECT principal_key,ace_count FROM principals")) == {
                "dom\\bob": 1, "dom\\domain users": 1, "asustorz": 1}

            # Errors linked by path.
            assert conn.execute(
                "SELECT count(*) FROM scan_errors WHERE node_id IS NOT NULL"
            ).fetchone()[0] == 1

            # Meta + integrity.
            assert conn.execute("SELECT count(*) FROM scan_meta").fetchone()[0] == 1
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"

            # Indexes exist.
            names = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'")}
            assert "idx_nodes_parent" in names
            assert "idx_aces_node" in names
        finally:
            conn.close()

        # Temp database must not linger beside the target.
        leftovers = [n for n in os.listdir(os.path.dirname(db_path))
                     if n.startswith(".acl-import-")]
        assert not leftovers, f"temp db left behind: {leftovers}"

    print("self-test: OK")
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def default_database_path(source_dir):
    name = os.path.basename(os.path.abspath(source_dir).rstrip("/")) or "acl"
    return os.path.join(source_dir, f"{name}.db")


def _positive_int(value):
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def build_parser():
    parser = argparse.ArgumentParser(
        prog="importer.py",
        description="Import a filesystem ACL scan export into SQLite.",
        epilog="Example: python importer.py ./scan --database ./acl.db --progress 5")
    parser.add_argument("source_dir", nargs="?",
                        help="scan output directory")
    parser.add_argument("--database", metavar="PATH",
                        help="target SQLite path "
                             "(default: <source_dir>/<name>.db)")
    parser.add_argument("--progress", type=int, default=0, metavar="N",
                        help="print progress every N seconds (default: 0, off)")
    parser.add_argument("--batch", type=_positive_int, default=DEFAULT_BATCH,
                        metavar="N", help=argparse.SUPPRESS)
    parser.add_argument("--self-test", action="store_true",
                        help="run an internal demo on a temporary fixture and exit")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.self_test:
        return self_test()
    if not args.source_dir:
        parser.error("SOURCE_DIR is required (or use --self-test)")

    database = args.database or default_database_path(args.source_dir)
    progress = Progress(args.progress)
    try:
        stats = build_database(args.source_dir, database, batch=args.batch,
                               progress=progress)
    except ImportError_ as exc:
        print(f"importer: error: {exc}", file=sys.stderr)
        return 1
    except sqlite3.Error as exc:
        print(f"importer: error: database build failed: {exc}", file=sys.stderr)
        return 1

    print(f"nodes={stats['nodes']:,} aces={stats['aces']:,} "
          f"errors={stats['scan_errors']:,} "
          f"(linked={stats['linked_errors']:,}, "
          f"nodes_flagged={stats['nodes_with_error']:,})")
    print(f"integrity={stats['integrity']}")
    print(f"database={stats['database']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
