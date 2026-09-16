#!/usr/bin/env python3
"""Read-only recursive ASUSTOR Windows ACL inventory.

This program only calls these ADM File Explorer actions:

* fileExplorer.cgi: act=file_list
* acl.cgi: act=get&type=as_adv

It deliberately contains no ACL set/reset/chown functionality.
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import csv
import getpass
import json
import os
import ssl
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple


PERMISSIONS: Sequence[Tuple[int, str]] = (
    (1, "list_folder_or_read_data"),
    (2, "create_file_or_write_data"),
    (4, "create_folder_or_append_data"),
    (8, "read_extended_attributes"),
    (16, "write_extended_attributes"),
    (32, "traverse_folder_or_execute_file"),
    (64, "delete_subfolders_and_files"),
    (128, "read_attributes"),
    (256, "write_attributes"),
    (512, "delete"),
    (1024, "read_permissions"),
    (2048, "change_permissions"),
    (4096, "take_ownership"),
    (8192, "full_control_marker"),
)

ENTRY_TYPES = {
    0: "creator_owner",
    1: "user",
    2: "group",
    3: "everyone",
}

AUTH_TYPES = {
    -1: "special",
    0: "local",
    1: "domain",
    2: "ldap",
}

INHERITANCE_TYPES = {
    0: "this_folder_only",
    1: "this_folder_subfolders_and_files",
    2: "this_folder_and_subfolders",
    3: "this_folder_and_files",
    4: "subfolders_and_files_only",
    5: "subfolders_only",
    6: "files_only",
}


class ApiError(RuntimeError):
    pass


class AuthenticationError(ApiError):
    pass


class LoginError(AuthenticationError):
    pass


class SessionExpired(AuthenticationError):
    pass


class RequestHardTimeout(TimeoutError):
    pass


class TransientRequestError(TimeoutError):
    pass


def _direct_http_post(
    url: str,
    body: bytes,
    headers: Dict[str, str],
    network_timeout: float,
    insecure: bool,
    ca_cert: Optional[str],
) -> Tuple[int, bytes]:
    if insecure:
        context = ssl._create_unverified_context()
    else:
        context = ssl.create_default_context(cafile=ca_cert)
    request = urllib.request.Request(url, data=body, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(
            request, timeout=network_timeout, context=context
        ) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096)


def _http_worker_main() -> int:
    """Internal subprocess entry point; request secrets arrive only over stdin."""
    try:
        job = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        status, raw = _direct_http_post(
            url=str(job["url"]),
            body=base64.b64decode(job["body"]),
            headers=dict(job["headers"]),
            network_timeout=float(job["network_timeout"]),
            insecure=bool(job["insecure"]),
            ca_cert=job.get("ca_cert"),
        )
        result = {
            "ok": True,
            "status": status,
            "body": base64.b64encode(raw).decode("ascii"),
        }
    except Exception as exc:
        result = {
            "ok": False,
            "error_type": type(exc).__name__,
            # Do not include URLs, bodies, request objects, passwords, or SIDs.
            "error": str(getattr(exc, "reason", "request failed")),
        }
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    return 0 if result["ok"] else 1


def isolated_http_post(
    url: str,
    body: bytes,
    headers: Dict[str, str],
    network_timeout: float,
    hard_timeout: float,
    insecure: bool,
    ca_cert: Optional[str],
    isolate: bool = True,
) -> Tuple[int, bytes]:
    if not isolate:
        return _direct_http_post(
            url, body, headers, network_timeout, insecure, ca_cert
        )

    job = json.dumps(
        {
            "url": url,
            "body": base64.b64encode(body).decode("ascii"),
            "headers": headers,
            "network_timeout": network_timeout,
            "insecure": insecure,
            "ca_cert": ca_cert,
        },
        separators=(",", ":"),
    ).encode("utf-8")
    process = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), "--_http-worker"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, _stderr = process.communicate(job, timeout=hard_timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.communicate(timeout=2)
        except subprocess.TimeoutExpired:
            # An uninterruptible child must not hold the inventory coordinator.
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        raise RequestHardTimeout(
            f"request exceeded hard timeout of {hard_timeout:g} seconds"
        )

    try:
        result = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiError("Isolated request worker returned invalid output") from exc
    if result.get("ok") is not True:
        error_type = result.get("error_type", "request error")
        error = result.get("error", "request failed")
        if error_type in {
            "TimeoutError",
            "URLError",
            "ConnectionError",
            "ConnectionResetError",
            "ConnectionRefusedError",
            "BrokenPipeError",
        }:
            raise TransientRequestError(f"{error_type}: {error}")
        raise ApiError(f"{error_type}: {error}")
    return int(result["status"]), base64.b64decode(result["body"])


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def decode_permissions(value: Any) -> List[str]:
    try:
        mask = int(value)
    except (TypeError, ValueError):
        return []
    return [name for bit, name in PERMISSIONS if mask & bit]


def compact_metadata(row: Dict[str, Any]) -> Dict[str, Any]:
    wanted = (
        "filename",
        "file_path",
        "file_path_hex",
        "is_dir",
        "exist_subdir",
        "enabled_acl",
        "file_system",
        "volume",
        "owner",
        "group",
        "file_permission",
        "access_permission",
        "share_folder_type",
        "item_type",
        "is_under_encrypted_share",
        "is_under_myarchive",
        "is_under_external_device",
        "is_under_cifs_drive",
    )
    return {key: row.get(key) for key in wanted if key in row}


class SessionManager:
    """Thread-safe fixed or automatically renewed ADM session."""

    def __init__(
        self,
        nas: str,
        ssl_context: ssl.SSLContext,
        timeout: float,
        hard_timeout: float,
        retries: int,
        login_path: str = "/portal/apis/login.cgi",
        sid: Optional[str] = None,
        account: Optional[str] = None,
        password: Optional[str] = None,
        insecure: bool = False,
        ca_cert: Optional[str] = None,
        isolate_requests: bool = True,
    ) -> None:
        self.nas = nas.rstrip("/")
        self.ssl_context = ssl_context
        self.timeout = timeout
        self.hard_timeout = hard_timeout
        self.retries = retries
        self.login_path = "/" + login_path.strip("/")
        self.account = account
        self.password = password
        self.insecure = insecure
        self.ca_cert = ca_cert
        self.isolate_requests = isolate_requests
        self._sid = sid
        self._generation = 0
        self._lock = threading.Lock()
        self._renewals = 0
        self._refresh_error: Optional[AuthenticationError] = None

        managed_fields = (account is not None, password is not None)
        if any(managed_fields) and not all(managed_fields):
            raise ValueError("Managed login requires both account and password")
        if not self.managed and not sid:
            raise ValueError("A fixed SID or managed login credentials are required")

    @property
    def managed(self) -> bool:
        return self.account is not None and self.password is not None

    @property
    def renewals(self) -> int:
        with self._lock:
            return self._renewals

    def ensure_login(self) -> None:
        if not self.managed:
            return
        with self._lock:
            if not self._sid:
                self._login_locked()

    def snapshot(self) -> Tuple[str, int]:
        with self._lock:
            if not self._sid:
                raise SessionExpired("No active ADM session")
            return self._sid, self._generation

    def renew_if_needed(self, observed_generation: int) -> None:
        if not self.managed:
            raise SessionExpired(
                "ADM session expired (error 5000). Restart with a fresh SID, "
                "or use --account for automatic renewal."
            )
        with self._lock:
            if self._generation != observed_generation:
                return
            if self._refresh_error is not None:
                raise self._refresh_error
            try:
                self._login_locked()
                self._renewals += 1
            except AuthenticationError as exc:
                self._refresh_error = exc
                raise

    def _login_locked(self) -> None:
        query = urllib.parse.urlencode({"act": "login", "_dc": int(time.time() * 1000)})
        url = f"{self.nas}{self.login_path}?{query}"
        body = urllib.parse.urlencode(
            {
                "account": self.account or "",
                "password": self.password or "",
                "two-step-auth": "true",
                "stay": "yes",
            }
        ).encode("utf-8")
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
            "User-Agent": "asustor-acl-inventory/3.0",
            "X-Requested-With": "XMLHttpRequest",
        }

        last_error: Optional[BaseException] = None
        for attempt in range(self.retries + 1):
            try:
                status, raw = isolated_http_post(
                    url=url,
                    body=body,
                    headers=headers,
                    network_timeout=self.timeout,
                    hard_timeout=self.hard_timeout,
                    insecure=self.insecure,
                    ca_cert=self.ca_cert,
                    isolate=self.isolate_requests,
                )
                if status >= 400:
                    raise LoginError(f"ADM login returned HTTP {status}")
                result = json.loads(raw.decode("utf-8"))
                if not isinstance(result, dict):
                    raise LoginError("Unexpected ADM login response type")
                if result.get("success") is not True:
                    code = result.get("error_code", "unknown")
                    raise LoginError(f"ADM login failed with error code {code}")
                sid = result.get("sid")
                if not isinstance(sid, str) or not sid:
                    raise LoginError("ADM login succeeded without returning a SID")
                self._sid = sid
                self._generation += 1
                self._refresh_error = None
                return
            except LoginError:
                raise
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ApiError) as exc:
                last_error = exc
            if attempt < self.retries:
                time.sleep(min(2**attempt, 8))

        raise LoginError(f"ADM login request failed: {last_error}")


class AdmClient:
    def __init__(
        self,
        nas: str,
        sid: str,
        api_prefix: str,
        insecure: bool,
        ca_cert: Optional[str],
        timeout: float,
        retries: int,
        delay: float,
        session_manager: Optional[SessionManager] = None,
        hard_timeout: float = 90.0,
        isolate_requests: bool = True,
    ) -> None:
        self.nas = nas.rstrip("/")
        self.sid = sid
        self.api_prefix = "/" + api_prefix.strip("/")
        self.timeout = timeout
        self.hard_timeout = hard_timeout
        self.retries = retries
        self.delay = delay
        self.insecure = insecure
        self.ca_cert = ca_cert
        self.isolate_requests = isolate_requests

        if insecure and ca_cert:
            raise ValueError("--insecure and --ca-cert cannot be used together")
        if insecure:
            self.ssl_context = ssl._create_unverified_context()
        else:
            self.ssl_context = ssl.create_default_context(cafile=ca_cert)
        self.session = session_manager or SessionManager(
            nas=self.nas,
            ssl_context=self.ssl_context,
            timeout=timeout,
            hard_timeout=hard_timeout,
            retries=retries,
            sid=sid,
            insecure=insecure,
            ca_cert=ca_cert,
            isolate_requests=isolate_requests,
        )

    def _request_json(
        self,
        script: str,
        query: Dict[str, Any],
        form: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        auth_retry = 0
        while True:
            sid, generation = self.session.snapshot()
            request_query = dict(query)
            request_query["sid"] = sid
            encoded_query = urllib.parse.urlencode(request_query)
            url = f"{self.nas}{self.api_prefix}/{script}?{encoded_query}"
            body = urllib.parse.urlencode(form or {}).encode("utf-8")
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "User-Agent": "asustor-acl-inventory/3.0",
            }

            last_error: Optional[BaseException] = None
            result: Optional[Dict[str, Any]] = None
            for attempt in range(self.retries + 1):
                if self.delay:
                    time.sleep(self.delay)
                try:
                    status, raw = isolated_http_post(
                        url=url,
                        body=body,
                        headers=headers,
                        network_timeout=self.timeout,
                        hard_timeout=self.hard_timeout,
                        insecure=self.insecure,
                        ca_cert=self.ca_cert,
                        isolate=self.isolate_requests,
                    )
                    if status >= 400:
                        detail = raw.decode("utf-8", "replace")[:4096]
                        raise ApiError(f"HTTP {status} from {script}: {detail}")
                    decoded = json.loads(raw.decode("utf-8"))
                    if not isinstance(decoded, dict):
                        raise ApiError(f"Unexpected JSON response type from {script}")
                    result = decoded
                    break
                except ApiError:
                    raise
                except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
                    last_error = exc

                if attempt < self.retries:
                    time.sleep(min(2**attempt, 8))

            if result is None:
                raise ApiError(str(last_error or f"Request to {script} failed"))
            if result.get("success") is False:
                code = result.get("error_code", "unknown")
                if code == 5000 and auth_retry == 0:
                    self.session.renew_if_needed(generation)
                    auth_retry += 1
                    continue
                if code == 5000:
                    raise SessionExpired("ADM rejected the renewed session with error 5000")
                raise ApiError(f"ADM API error {code}: {result}")
            return result

    def get_acl(self, virtual_path: str) -> Dict[str, Any]:
        return self._request_json(
            "acl.cgi",
            {"act": "get", "type": "as_adv"},
            {"path": virtual_path},
        )

    def list_path(self, virtual_path: str, page_size: int) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        start = 0
        page = 1
        while True:
            result = self._request_json(
                "fileExplorer.cgi",
                {
                    "act": "file_list",
                    "sortway": "name",
                    "dirway": "ASC",
                    "path": virtual_path,
                    "filter": "",
                    "page": page,
                    "start": start,
                    "limit": page_size,
                    "sort": json.dumps(
                        [{"property": "name", "direction": "ASC"}],
                        separators=(",", ":"),
                    ),
                    "showhome": "true",
                    "showrecyclebin": "false",
                },
            )
            page_rows = result.get("data")
            if not isinstance(page_rows, list):
                raise ApiError(f"file_list returned no data array for {virtual_path!r}")
            rows.extend(item for item in page_rows if isinstance(item, dict))

            count = len(page_rows)
            total = result.get("all", result.get("total"))
            start += count
            page += 1
            if count == 0:
                break
            if isinstance(total, int) and start >= total:
                break
            if count < page_size:
                break
        return rows


class InventoryWriter:
    PATH_FIELDS = (
        "scanned_at",
        "path",
        "kind",
        "enabled_acl",
        "inherit_parent",
        "ace_count",
        "success",
        "error",
    )
    ACE_FIELDS = (
        "scanned_at",
        "path",
        "kind",
        "inherit_parent",
        "ace_index",
        "deny",
        "effect",
        "entry_type",
        "entry_type_name",
        "name",
        "auth_type",
        "auth_type_name",
        "unresolved",
        "inheritance",
        "inheritance_name",
        "no_propagate",
        "inherited_from",
        "is_explicit",
        "perm",
        "perm_hex",
        "perm_type",
        "rights",
        "full_control_marker",
    )

    def __init__(self, output_dir: Path) -> None:
        self.output_dir = output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = output_dir / "inventory.jsonl"
        self.errors_path = output_dir / "errors.jsonl"
        self.paths_path = output_dir / "paths.csv"
        self.aces_path = output_dir / "aces.csv"

        self.jsonl = self.jsonl_path.open("a", encoding="utf-8", newline="")
        self.errors = self.errors_path.open("a", encoding="utf-8", newline="")
        paths_new = not self.paths_path.exists() or self.paths_path.stat().st_size == 0
        aces_new = not self.aces_path.exists() or self.aces_path.stat().st_size == 0
        self.paths_file = self.paths_path.open("a", encoding="utf-8", newline="")
        self.aces_file = self.aces_path.open("a", encoding="utf-8", newline="")
        self.paths_csv = csv.DictWriter(self.paths_file, fieldnames=self.PATH_FIELDS)
        self.aces_csv = csv.DictWriter(self.aces_file, fieldnames=self.ACE_FIELDS)
        if paths_new:
            self.paths_csv.writeheader()
        if aces_new:
            self.aces_csv.writeheader()

    def close(self) -> None:
        for handle in (self.jsonl, self.errors, self.paths_file, self.aces_file):
            handle.flush()
            handle.close()

    def _flush(self) -> None:
        self.jsonl.flush()
        self.errors.flush()
        self.paths_file.flush()
        self.aces_file.flush()

    def write_acl(
        self,
        virtual_path: str,
        kind: str,
        metadata: Dict[str, Any],
        acl: Dict[str, Any],
    ) -> None:
        scanned_at = utc_now()
        entries = acl.get("data") if isinstance(acl.get("data"), list) else []
        record = {
            "record_type": "acl",
            "scanned_at": scanned_at,
            "path": virtual_path,
            "kind": kind,
            "metadata": compact_metadata(metadata),
            "acl": acl,
        }
        self.jsonl.write(json.dumps(record, ensure_ascii=False) + "\n")
        self.paths_csv.writerow(
            {
                "scanned_at": scanned_at,
                "path": virtual_path,
                "kind": kind,
                "enabled_acl": metadata.get("enabled_acl", ""),
                "inherit_parent": acl.get("inherit_parent", ""),
                "ace_count": len(entries),
                "success": acl.get("success", True),
                "error": "",
            }
        )

        for index, ace in enumerate(entries):
            if not isinstance(ace, dict):
                continue
            perm = ace.get("perm")
            try:
                perm_number = int(perm)
                perm_hex = hex(perm_number)
            except (TypeError, ValueError):
                perm_number = 0
                perm_hex = ""
            inherited_from = ace.get("inherited_from", "")
            entry_type = ace.get("entry_type")
            auth_type = ace.get("auth_type")
            inheritance = ace.get("inheritance")
            self.aces_csv.writerow(
                {
                    "scanned_at": scanned_at,
                    "path": virtual_path,
                    "kind": kind,
                    "inherit_parent": acl.get("inherit_parent", ""),
                    "ace_index": index,
                    "deny": ace.get("deny", ""),
                    "effect": "deny" if ace.get("deny") else "allow",
                    "entry_type": entry_type,
                    "entry_type_name": ENTRY_TYPES.get(entry_type, "unknown"),
                    "name": ace.get("name", ""),
                    "auth_type": auth_type,
                    "auth_type_name": AUTH_TYPES.get(auth_type, "unknown"),
                    "unresolved": ace.get("unresolved", ""),
                    "inheritance": inheritance,
                    "inheritance_name": INHERITANCE_TYPES.get(
                        inheritance, "unknown"
                    ),
                    "no_propagate": ace.get("no_propagate", ""),
                    "inherited_from": inherited_from,
                    "is_explicit": inherited_from == "",
                    "perm": perm,
                    "perm_hex": perm_hex,
                    "perm_type": ace.get("perm_type", ""),
                    "rights": ";".join(decode_permissions(perm_number)),
                    "full_control_marker": bool(perm_number & 8192),
                }
            )
        self._flush()

    def write_error(
        self,
        operation: str,
        virtual_path: str,
        kind: str,
        error: BaseException,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        scanned_at = utc_now()
        record = {
            "record_type": "error",
            "scanned_at": scanned_at,
            "operation": operation,
            "path": virtual_path,
            "kind": kind,
            "metadata": compact_metadata(metadata or {}),
            "error": str(error),
        }
        line = json.dumps(record, ensure_ascii=False) + "\n"
        self.jsonl.write(line)
        self.errors.write(line)
        if operation == "get_acl":
            self.paths_csv.writerow(
                {
                    "scanned_at": scanned_at,
                    "path": virtual_path,
                    "kind": kind,
                    "enabled_acl": (metadata or {}).get("enabled_acl", ""),
                    "inherit_parent": "",
                    "ace_count": "",
                    "success": False,
                    "error": str(error),
                }
            )
        self._flush()


def load_completed_paths(jsonl_path: Path) -> Set[str]:
    completed: Set[str] = set()
    if not jsonl_path.exists():
        return completed
    with jsonl_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("record_type") == "acl" and record.get("path"):
                completed.add(str(record["path"]))
    return completed


Node = Tuple[str, int, Dict[str, Any], bool]


def manifest_config(
    nas: str,
    roots: Sequence[str],
    include_files: bool,
    max_depth: Optional[int],
) -> Dict[str, Any]:
    return {
        "schema": 1,
        "nas": nas.rstrip("/"),
        "roots": list(roots),
        "include_files": include_files,
        "max_depth": max_depth,
    }


def load_manifest(output_dir: Path, expected_config: Dict[str, Any]) -> Optional[List[Node]]:
    meta_path = output_dir / "manifest-meta.json"
    data_path = output_dir / "manifest.jsonl"
    if not meta_path.exists() or not data_path.exists():
        return None
    try:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        if meta.get("config") != expected_config or meta.get("complete") is not True:
            return None
        nodes: List[Node] = []
        with data_path.open("r", encoding="utf-8") as handle:
            for line in handle:
                item = json.loads(line)
                nodes.append(
                    (
                        str(item["path"]),
                        int(item["depth"]),
                        dict(item.get("metadata") or {}),
                        bool(item.get("pseudo_root")),
                    )
                )
        return nodes
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def save_manifest(
    output_dir: Path, config: Dict[str, Any], nodes: Sequence[Node]
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    data_path = output_dir / "manifest.jsonl"
    temp_path = output_dir / "manifest.jsonl.tmp"
    with temp_path.open("w", encoding="utf-8", newline="") as handle:
        for path, depth, metadata, pseudo_root in nodes:
            handle.write(
                json.dumps(
                    {
                        "path": path,
                        "depth": depth,
                        "metadata": compact_metadata(metadata),
                        "pseudo_root": pseudo_root,
                    },
                    ensure_ascii=False,
                )
                + "\n"
            )
    temp_path.replace(data_path)
    meta = {
        "created_at": utc_now(),
        "complete": True,
        "config": config,
        "paths": len(nodes),
    }
    (output_dir / "manifest-meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def mark_manifest_incomplete(output_dir: Path, config: Dict[str, Any]) -> None:
    meta = {
        "created_at": utc_now(),
        "complete": False,
        "config": config,
        "reason": "directory discovery did not complete without errors",
    }
    (output_dir / "manifest-meta.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def discover_paths(
    client: AdmClient,
    writer: InventoryWriter,
    roots: Iterable[str],
    include_files: bool,
    page_size: int,
    max_depth: Optional[int],
    list_workers: int,
) -> Tuple[List[Node], Dict[str, int]]:
    frontier: List[Node] = []
    for root in roots:
        root = root.strip()
        if not root:
            continue
        frontier.append((root, 0, {"file_path": root, "is_dir": 1}, root == "share"))

    visited: Set[str] = set()
    nodes: List[Node] = []
    stats = {"list_error": 0, "directories": 0, "files": 0}
    level = 0

    while frontier:
        current: List[Node] = []
        for node in frontier:
            path = node[0]
            if path not in visited:
                visited.add(path)
                current.append(node)
                nodes.append(node)
                if not node[3]:
                    if node[2].get("is_dir") == 1:
                        stats["directories"] += 1
                    else:
                        stats["files"] += 1

        list_targets: List[Node] = []
        for node in current:
            path, depth, metadata, pseudo_root = node
            if metadata.get("is_dir") != 1:
                continue
            if max_depth is not None and depth >= max_depth:
                continue
            if not pseudo_root and metadata.get("exist_subdir") == 0 and not include_files:
                continue
            list_targets.append(node)

        next_frontier: List[Node] = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=list_workers) as executor:
            futures = {
                executor.submit(client.list_path, node[0], page_size): node
                for node in list_targets
            }
            for future in concurrent.futures.as_completed(futures):
                path, depth, metadata, _pseudo_root = futures[future]
                try:
                    children = future.result()
                except AuthenticationError as exc:
                    writer.write_error("authentication", path, "directory", exc, metadata)
                    for pending in futures:
                        pending.cancel()
                    raise
                except Exception as exc:
                    writer.write_error("file_list", path, "directory", exc, metadata)
                    stats["list_error"] += 1
                    continue
                for child in children:
                    child_path = child.get("file_path")
                    if not isinstance(child_path, str) or not child_path:
                        continue
                    is_dir = child.get("is_dir") == 1
                    if is_dir or include_files:
                        next_frontier.append((child_path, depth + 1, child, False))

        level += 1
        print(
            f"Discovery level {level}: {len(nodes)} paths found",
            file=sys.stderr,
            flush=True,
        )
        frontier = next_frontier

    return nodes, stats


def format_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes}m"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def scan_acls(
    client: AdmClient,
    writer: InventoryWriter,
    nodes: Sequence[Node],
    completed: Set[str],
    acl_workers: int,
    report_every: int,
) -> Dict[str, int]:
    targets = [node for node in nodes if not node[3] and node[0] not in completed]
    skipped = sum(1 for node in nodes if not node[3] and node[0] in completed)
    stats = {"acl_ok": 0, "acl_error": 0, "skipped": skipped, "remaining": len(targets)}
    if not targets:
        return stats

    started = time.monotonic()
    processed = 0
    iterator = iter(targets)
    pending: Dict[concurrent.futures.Future, Node] = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=acl_workers) as executor:
        def submit_one() -> bool:
            try:
                node = next(iterator)
            except StopIteration:
                return False
            pending[executor.submit(client.get_acl, node[0])] = node
            return True

        for _ in range(min(len(targets), acl_workers * 2)):
            if not submit_one():
                break

        while pending:
            done, _ = concurrent.futures.wait(
                pending, return_when=concurrent.futures.FIRST_COMPLETED
            )
            for future in done:
                path, _depth, metadata, _pseudo_root = pending.pop(future)
                kind = "directory" if metadata.get("is_dir") == 1 else "file"
                try:
                    acl = future.result()
                    writer.write_acl(path, kind, metadata, acl)
                    completed.add(path)
                    stats["acl_ok"] += 1
                except AuthenticationError as exc:
                    writer.write_error("authentication", path, kind, exc, metadata)
                    for queued in pending:
                        queued.cancel()
                    raise
                except Exception as exc:
                    writer.write_error("get_acl", path, kind, exc, metadata)
                    stats["acl_error"] += 1
                processed += 1
                submit_one()

                if processed == 1 or processed % report_every == 0 or processed == len(targets):
                    elapsed = time.monotonic() - started
                    rate = processed / elapsed if elapsed else 0
                    left = len(targets) - processed
                    eta = format_duration(left / rate) if rate else "unknown"
                    print(
                        f"ACL progress: {processed}/{len(targets)} this run; "
                        f"{rate:.2f}/s; ETA {eta}; last {path}",
                        file=sys.stderr,
                        flush=True,
                    )

    stats["remaining"] = 0
    return stats


def read_password_file(path: Path) -> str:
    try:
        info = path.stat()
    except OSError as exc:
        raise SystemExit(f"Cannot read password file {path}: {exc}")
    if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
        raise SystemExit(
            f"Password file {path} is accessible by group/others; run: chmod 600 {path}"
        )
    try:
        password = path.read_text(encoding="utf-8").splitlines()[0]
    except (OSError, IndexError) as exc:
        raise SystemExit(f"Cannot read password from {path}: {exc}")
    if not password:
        raise SystemExit(f"Password file {path} is empty")
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Recursively inventory ASUSTOR Windows ACLs using read-only ADM APIs."
    )
    parser.add_argument("--nas", required=True, help="NAS base URL, e.g. https://nas:8001")
    parser.add_argument(
        "--root",
        action="append",
        default=None,
        help="ADM virtual root. Repeatable. Default: share (all visible shares)",
    )
    parser.add_argument(
        "--api-prefix",
        default="/portal/apis/fileExplorer",
        help="ADM File Explorer API prefix",
    )
    parser.add_argument(
        "--account",
        help="ADM account for automatic login/renewal; password is never accepted on CLI",
    )
    parser.add_argument(
        "--password-file",
        type=Path,
        help="Read ADM password from a mode-0600 file instead of prompting",
    )
    parser.add_argument(
        "--login-path",
        default="/portal/apis/login.cgi",
        help="ADM login API path",
    )
    tls = parser.add_mutually_exclusive_group()
    tls.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification (LAN interception risk)",
    )
    tls.add_argument("--ca-cert", help="CA certificate file used to verify the NAS")
    parser.add_argument(
        "--output",
        type=Path,
        help="Output directory; existing successful paths are resumed",
    )
    parser.add_argument(
        "--include-files",
        action="store_true",
        help="Also retrieve file ACLs; default is directories only",
    )
    parser.add_argument(
        "--page-size",
        type=int,
        default=500,
        help="Directory listing page size. Default: 500",
    )
    parser.add_argument(
        "--max-depth",
        type=int,
        help="Stop descending beyond this depth (0 scans only the roots)",
    )
    parser.add_argument(
        "--acl-workers",
        type=int,
        default=8,
        help="Concurrent ACL reads. Default: 8; this NAS was stable at 16",
    )
    parser.add_argument(
        "--list-workers",
        type=int,
        default=4,
        help="Concurrent directory listings. Default: 4",
    )
    parser.add_argument(
        "--refresh-manifest",
        action="store_true",
        help="Rediscover the directory tree instead of reusing its cached manifest",
    )
    parser.add_argument(
        "--report-every",
        type=int,
        default=25,
        help="Print ACL progress every N completed paths",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=60.0,
        help="Per-request network timeout in seconds. Default: 60",
    )
    parser.add_argument(
        "--hard-timeout",
        type=float,
        default=90.0,
        help="Absolute per-attempt deadline enforced by an isolated process",
    )
    parser.add_argument(
        "--no-request-isolation",
        action="store_true",
        help="Disable the hard-kill subprocess failsafe (debugging only)",
    )
    parser.add_argument(
        "--retries",
        type=int,
        default=2,
        help="Retry attempts per request after the first failure. Default: 2",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay before each request in seconds",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.page_size < 1:
        raise SystemExit("--page-size must be at least 1")
    if args.max_depth is not None and args.max_depth < 0:
        raise SystemExit("--max-depth cannot be negative")
    if args.retries < 0:
        raise SystemExit("--retries cannot be negative")
    if args.delay < 0:
        raise SystemExit("--delay cannot be negative")
    if args.timeout <= 0:
        raise SystemExit("--timeout must be positive")
    if args.hard_timeout <= 0:
        raise SystemExit("--hard-timeout must be positive")
    if args.acl_workers < 1:
        raise SystemExit("--acl-workers must be at least 1")
    if args.list_workers < 1:
        raise SystemExit("--list-workers must be at least 1")
    if args.report_every < 1:
        raise SystemExit("--report-every must be at least 1")

    output = args.output
    if output is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = Path(f"asustor-acl-inventory-{stamp}")

    if args.insecure:
        login_ssl_context = ssl._create_unverified_context()
    else:
        login_ssl_context = ssl.create_default_context(cafile=args.ca_cert)

    account = args.account or os.environ.get("ASUSTOR_ADM_ACCOUNT")
    password_file = args.password_file
    if password_file is None and os.environ.get("ASUSTOR_ADM_PASSWORD_FILE"):
        password_file = Path(os.environ["ASUSTOR_ADM_PASSWORD_FILE"])

    if account:
        password = os.environ.get("ASUSTOR_ADM_PASSWORD")
        if password_file is not None:
            if password is not None:
                raise SystemExit(
                    "Use either ASUSTOR_ADM_PASSWORD or --password-file, not both"
                )
            password = read_password_file(password_file)
        if password is None:
            password = getpass.getpass("ADM password: ")
        if not password:
            raise SystemExit("No ADM password supplied")
        session = SessionManager(
            nas=args.nas,
            ssl_context=login_ssl_context,
            timeout=args.timeout,
            hard_timeout=args.hard_timeout,
            retries=args.retries,
            login_path=args.login_path,
            account=account,
            password=password,
            insecure=args.insecure,
            ca_cert=args.ca_cert,
            isolate_requests=not args.no_request_isolation,
        )
        try:
            session.ensure_login()
        except AuthenticationError as exc:
            raise SystemExit(str(exc))
        sid = ""
        auth_mode = "managed-login"
        print("ADM login succeeded; automatic SID renewal is enabled.", file=sys.stderr)
    else:
        if password_file is not None or os.environ.get("ASUSTOR_ADM_PASSWORD") is not None:
            raise SystemExit("--password-file/ASUSTOR_ADM_PASSWORD requires --account")
        sid = os.environ.get("ASUSTOR_ADM_SID") or getpass.getpass("ADM session ID: ")
        if not sid:
            raise SystemExit("No ADM session ID supplied")
        session = SessionManager(
            nas=args.nas,
            ssl_context=login_ssl_context,
            timeout=args.timeout,
            hard_timeout=args.hard_timeout,
            retries=args.retries,
            sid=sid,
            insecure=args.insecure,
            ca_cert=args.ca_cert,
            isolate_requests=not args.no_request_isolation,
        )
        auth_mode = "fixed-sid"

    client = AdmClient(
        nas=args.nas,
        sid=sid,
        api_prefix=args.api_prefix,
        insecure=args.insecure,
        ca_cert=args.ca_cert,
        timeout=args.timeout,
        retries=args.retries,
        delay=args.delay,
        session_manager=session,
        hard_timeout=args.hard_timeout,
        isolate_requests=not args.no_request_isolation,
    )
    completed = load_completed_paths(output / "inventory.jsonl")
    writer = InventoryWriter(output)
    roots = args.root or ["share"]
    config = manifest_config(args.nas, roots, args.include_files, args.max_depth)
    manifest_reused = False
    try:
        nodes = None if args.refresh_manifest else load_manifest(output, config)
        if nodes is None:
            nodes, discovery_stats = discover_paths(
                client=client,
                writer=writer,
                roots=roots,
                include_files=args.include_files,
                page_size=args.page_size,
                max_depth=args.max_depth,
                list_workers=args.list_workers,
            )
            if discovery_stats["list_error"] == 0:
                save_manifest(output, config, nodes)
            else:
                mark_manifest_incomplete(output, config)
                print(
                    "Discovery had errors; manifest was not cached so the next run can retry it.",
                    file=sys.stderr,
                )
        else:
            manifest_reused = True
            discovery_stats = {
                "list_error": 0,
                "directories": sum(
                    1 for node in nodes if not node[3] and node[2].get("is_dir") == 1
                ),
                "files": sum(
                    1 for node in nodes if not node[3] and node[2].get("is_dir") != 1
                ),
            }
            print(
                f"Reusing cached manifest with {len(nodes)} paths. "
                "Use --refresh-manifest after filesystem changes.",
                file=sys.stderr,
            )

        acl_stats = scan_acls(
            client=client,
            writer=writer,
            nodes=nodes,
            completed=completed,
            acl_workers=args.acl_workers,
            report_every=args.report_every,
        )
    except KeyboardInterrupt:
        print("\nInterrupted; completed records are safely resumable.", file=sys.stderr)
        return 130
    except AuthenticationError as exc:
        print(
            f"\nAuthentication stopped the scan safely: {exc}\n"
            "Rerun with valid credentials and the same --output directory to resume.",
            file=sys.stderr,
        )
        return 3
    finally:
        writer.close()

    summary = {
        "finished_at": utc_now(),
        "nas": args.nas,
        "roots": roots,
        "include_files": args.include_files,
        "authentication": auth_mode,
        "session_renewals": session.renewals,
        "manifest_reused": manifest_reused,
        "acl_workers": args.acl_workers,
        "list_workers": args.list_workers,
        "network_timeout": args.timeout,
        "hard_timeout": args.hard_timeout,
        "discovery": discovery_stats,
        "acl": acl_stats,
        "output": str(output.resolve()),
    }
    summary_path = output / "summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if acl_stats["acl_error"] == 0 and discovery_stats["list_error"] == 0 else 2


if __name__ == "__main__":
    if sys.argv[1:] == ["--_http-worker"]:
        raise SystemExit(_http_worker_main())
    raise SystemExit(main())
