#!/usr/bin/env python3
"""Focused, no-dependency checks for q_ancestors and GET /api/ancestors.

Covers the exact root-to-target order, the 404 path, and the defensive
recursion cap. The HTTP checks skip where sockets are unavailable.

    python3 tests/test_ancestors.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER_PATH = os.path.join(os.path.dirname(HERE), "server.py")


def load_server():
    spec = importlib.util.spec_from_file_location("acl_report_server", SERVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _http_check(server, db_path):
    web_dir = tempfile.mkdtemp(prefix="acl-ancestors-web-")
    httpd = server.serve(db_path, "127.0.0.1", 0, web_dir)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        code, _, body = server._http_get(base, "/api/ancestors?id=3")
        assert code == 200, (code, body)
        payload = json.loads(body)
        assert [a["id"] for a in payload["ancestors"]] == [1, 2, 3], payload
        assert payload["ancestors"][1]["has_children"] is True

        code, _, body = server._http_get(base, "/api/ancestors?id=99999")
        assert code == 404 and json.loads(body)["error"]["code"] == "node_not_found", (code, body)
        code, _, body = server._http_get(base, "/api/ancestors?id=abc")
        assert code == 400 and json.loads(body)["error"]["code"] == "invalid_int", (code, body)
        code, _, body = server._http_get(base, "/api/ancestors")
        assert code == 400 and json.loads(body)["error"]["code"] == "missing_param", (code, body)
    finally:
        httpd.shutdown()
        httpd.server_close()


def main():
    server = load_server()
    tmp = tempfile.mkdtemp(prefix="acl-ancestors-test-")
    db_path = os.path.join(tmp, "acl.db")
    server._seed_selftest_db(db_path)

    conn = server.open_db(db_path)
    try:
        chain = server.q_ancestors(conn, 3)["ancestors"]
        assert [a["id"] for a in chain] == [1, 2, 3], chain
        assert [a["path"] for a in chain] == ["/data", "/data/team", "/data/team/docs"], chain
        assert [a["depth"] for a in chain] == [0, 1, 2], chain
        assert [a["has_children"] for a in chain] == [True, True, False], chain
        assert [a["id"] for a in server.q_ancestors(conn, 1)["ancestors"]] == [1]
        assert [a["id"] for a in server.q_ancestors(conn, 4)["ancestors"]] == [1, 4]
        try:
            server.q_ancestors(conn, 99999)
            raise AssertionError("missing node should raise ApiError")
        except server.ApiError as exc:
            assert exc.status == 404 and exc.code == "node_not_found", (exc.status, exc.code)
    finally:
        conn.close()

    # A malformed parent cycle must stop at the cap, not spin forever.
    cycle = sqlite3.connect(":memory:")
    cycle.row_factory = sqlite3.Row
    try:
        cycle.executescript(server.SCHEMA_SQL)
        cycle.execute(
            "INSERT INTO nodes(id, parent_id, path, name, depth, ace_count, has_scan_error)"
            " VALUES(1, 2, '/a', 'a', 0, 0, 0), (2, 1, '/b', 'b', 0, 0, 0)"
        )
        assert len(server.q_ancestors(cycle, 1)["ancestors"]) == server.MAX_ANCESTOR_DEPTH + 1
    finally:
        cycle.close()

    print("ancestor query checks OK")

    try:
        _http_check(server, db_path)
    except OSError as exc:
        print("ancestor HTTP checks SKIPPED (socket unavailable: %s)" % exc)
        print("ancestor tests OK (query layer only)")
        return 0

    print("ancestor HTTP checks OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
