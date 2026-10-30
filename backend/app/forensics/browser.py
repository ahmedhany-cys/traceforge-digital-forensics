"""Chromium-family browser history (``History`` SQLite) analysis.

Safety measures:

* The evidence file is first copied into a private temporary directory and the
  copy's SHA-256 is compared with the original's, so SQLite never touches the
  vault copy (even read-only opens can create ``-wal``/``-shm`` side files).
* The copy is opened through a ``file:...?mode=ro&immutable=1`` URI.
* Only fixed, parameter-free queries are executed; table and column names are
  checked against ``sqlite_master`` / ``PRAGMA table_info`` before use. No
  user-controlled value is ever interpolated into SQL.
* ``PRAGMA quick_check`` runs first and its result is reported.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .hashing import sha256_file
from .timeutil import webkit_to_datetime

ENGINE_VERSION = "chromium-history-1.0"
MAX_ROWS = 200_000

# Chromium download state / danger type enumerations (components/download, history DB values)
DOWNLOAD_STATES = {0: "in_progress", 1: "complete", 2: "cancelled", 3: "interrupted", 4: "interrupted"}
DANGER_TYPES = {
    0: "not_dangerous", 1: "dangerous_file", 2: "dangerous_url", 3: "dangerous_content",
    4: "maybe_dangerous_content", 5: "uncommon_content", 6: "user_validated", 7: "dangerous_host",
    8: "potentially_unwanted",
}
TRANSITION_CORE = {0: "link", 1: "typed", 2: "auto_bookmark", 3: "auto_subframe", 4: "manual_subframe",
                   5: "generated", 6: "auto_toplevel", 7: "form_submit", 8: "reload", 9: "keyword",
                   10: "keyword_generated"}


@dataclass
class BrowserParseResult:
    visits: list[dict[str, Any]] = field(default_factory=list)
    downloads: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def _columns(con: sqlite3.Connection, table: str) -> set[str]:
    # `table` comes from a fixed allow-list below, never from input
    return {row[1] for row in con.execute(f"PRAGMA table_info({table})")}  # noqa: S608


def parse_chromium_history(path: Path, work_dir: Path) -> BrowserParseResult:
    result = BrowserParseResult()
    original_hash = sha256_file(path)
    work_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=work_dir) as tmp:
        copy = Path(tmp) / "history.sqlite"
        shutil.copyfile(path, copy)
        copy.chmod(0o400)
        if sha256_file(copy) != original_hash:
            result.errors.append({"scope": "file", "error": "working copy hash mismatch; analysis aborted"})
            return result
        uri = f"file:{quote(str(copy))}?mode=ro&immutable=1"
        try:
            con = sqlite3.connect(uri, uri=True)
        except sqlite3.Error as exc:
            result.errors.append({"scope": "file", "error": f"cannot open database: {exc}"})
            return result
        try:
            con.execute("PRAGMA query_only = ON")
            try:
                check = [r[0] for r in con.execute("PRAGMA quick_check").fetchall()]
            except sqlite3.DatabaseError as exc:
                result.errors.append({"scope": "file", "error": f"database is malformed: {exc}"})
                return result
            result.meta["quick_check"] = check[:10]
            if check != ["ok"]:
                result.errors.append({"scope": "file", "error": "SQLite quick_check reported problems", "detail": check[:10]})
            tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            result.meta["tables"] = sorted(tables)
            if "meta" in tables:
                try:
                    result.meta["schema_version"] = dict(con.execute("SELECT key, value FROM meta").fetchall()).get("version")
                except sqlite3.Error:
                    pass
            if not {"urls", "visits"} <= tables and "downloads" not in tables:
                result.errors.append({"scope": "file", "error": "no Chromium history tables (urls/visits/downloads) found; not a Chromium History database"})
                return result
            if {"urls", "visits"} <= tables:
                _parse_visits(con, result)
            if "downloads" in tables:
                _parse_downloads(con, result, "downloads_url_chains" in tables)
        finally:
            con.close()
    # confirm the original was not touched
    if sha256_file(path) != original_hash:
        result.errors.append({"scope": "file", "error": "ORIGINAL EVIDENCE HASH CHANGED DURING ANALYSIS"})
    return result


def _parse_visits(con: sqlite3.Connection, result: BrowserParseResult) -> None:
    cols = _columns(con, "visits")
    has_ext_ref = "external_referrer_url" in cols
    # Only constant SQL fragments are concatenated; the row limit is a bound parameter.
    ref_col = ", v.external_referrer_url" if has_ext_ref else ", NULL"
    query = ("SELECT v.id, v.visit_time, v.transition, v.from_visit, u.url, u.title, u.visit_count, u.typed_count"  # nosec B608
             + ref_col + " FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.visit_time LIMIT ?")
    try:
        rows = con.execute(query, (MAX_ROWS,)).fetchall()
    except sqlite3.Error as exc:
        result.errors.append({"scope": "table", "table": "visits", "error": str(exc)})
        return
    by_id: dict[int, str] = {}
    for vid, vtime, transition, from_visit, url, title, visit_count, typed_count, ext_ref in rows:
        ts = webkit_to_datetime(vtime)
        if ts is None:
            result.errors.append({"scope": "row", "table": "visits", "id": vid, "error": f"invalid visit_time {vtime!r}"})
        transition = int(transition or 0)
        by_id[vid] = url or ""
        result.visits.append({
            "visit_id": vid,
            "url": url or "",
            "title": title or "",
            "timestamp_utc": ts,
            "original_timestamp": f"webkit:{vtime}",
            "visit_count": visit_count,
            "typed_count": typed_count,
            "transition": TRANSITION_CORE.get(transition & 0xFF, f"core_{transition & 0xFF}"),
            "transition_raw": transition,
            "referrer": by_id.get(from_visit or 0, "") or (ext_ref or ""),
        })


def _parse_downloads(con: sqlite3.Connection, result: BrowserParseResult, has_chains: bool) -> None:
    cols = _columns(con, "downloads")
    wanted = ["id", "guid", "current_path", "target_path", "start_time", "end_time", "received_bytes",
              "total_bytes", "state", "danger_type", "interrupt_reason", "opened", "referrer", "tab_url",
              "tab_referrer_url", "site_url", "mime_type", "original_mime_type", "hash"]
    present = [c for c in wanted if c in cols]  # columns vary between Chromium versions
    if "id" not in present or "start_time" not in present:
        result.errors.append({"scope": "table", "table": "downloads", "error": "unexpected downloads schema"})
        return
    # Column names come from the fixed `wanted` allow-list (intersected with PRAGMA output), never from input.
    query = f"SELECT {', '.join(present)} FROM downloads ORDER BY start_time LIMIT ?"  # nosec B608
    try:
        rows = con.execute(query, (MAX_ROWS,)).fetchall()
    except sqlite3.Error as exc:
        result.errors.append({"scope": "table", "table": "downloads", "error": str(exc)})
        return
    chains: dict[int, list[str]] = {}
    if has_chains:
        try:
            for did, idx, url in con.execute("SELECT id, chain_index, url FROM downloads_url_chains ORDER BY id, chain_index"):
                chains.setdefault(did, []).append(url)
        except sqlite3.Error as exc:
            result.errors.append({"scope": "table", "table": "downloads_url_chains", "error": str(exc)})
    for row in rows:
        rec = dict(zip(present, row))
        start = webkit_to_datetime(rec.get("start_time"))
        end = webkit_to_datetime(rec.get("end_time"))
        url_chain = chains.get(rec["id"], [])
        sha = rec.get("hash")
        result.downloads.append({
            "download_id": rec["id"],
            "guid": rec.get("guid"),
            "url": url_chain[-1] if url_chain else rec.get("site_url", ""),
            "url_chain": url_chain,
            "target_path": rec.get("target_path") or rec.get("current_path") or "",
            "timestamp_utc": start,
            "end_time_utc": end.isoformat() if end else None,
            "original_timestamp": f"webkit:{rec.get('start_time')}",
            "received_bytes": rec.get("received_bytes"),
            "total_bytes": rec.get("total_bytes"),
            "state": DOWNLOAD_STATES.get(rec.get("state"), str(rec.get("state"))),
            "danger_type": DANGER_TYPES.get(rec.get("danger_type"), str(rec.get("danger_type"))),
            "opened": bool(rec.get("opened")),
            "referrer": rec.get("referrer") or rec.get("tab_referrer_url") or "",
            "tab_url": rec.get("tab_url", ""),
            "mime_type": rec.get("mime_type", ""),
            "sha256": sha.hex() if isinstance(sha, (bytes, bytearray)) and len(sha) == 32 else None,
        })
        if start is None:
            result.errors.append({"scope": "row", "table": "downloads", "id": rec["id"], "error": "invalid start_time"})
