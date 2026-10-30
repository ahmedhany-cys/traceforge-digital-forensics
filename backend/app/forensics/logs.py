"""Parsers for CSV security logs, JSON event exports and line-oriented text logs.

Records are normalised to a common shape:

    {line_number, record_kind, timestamp_utc, original_timestamp,
     timezone_assumed, fields, message}

``record_kind`` is inferred from the fields present: ``network`` (has a
destination address), ``dns`` (has a query name), ``file`` (has a file path)
or ``generic``. Lines/records that cannot be parsed are reported in
``errors`` with their line number rather than dropped silently.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .timeutil import parse_timestamp

ENGINE_VERSION = "logs-1.0"
MAX_RECORDS = 1_000_000
MAX_LINE = 64 * 1024

TIMESTAMP_KEYS = ["timestamp_utc", "timestamp", "@timestamp", "event_time", "eventtime", "time", "datetime",
                  "date_time", "ts", "utc_time", "time_generated", "created_at"]
DST_IP_KEYS = ["dst_ip", "dest_ip", "destination_ip", "destaddress", "dst", "remote_ip", "remote_address"]
SRC_IP_KEYS = ["src_ip", "source_ip", "sourceaddress", "src", "client_ip", "local_ip"]
FILE_KEYS = ["file_path", "filepath", "target_filename", "path", "object_name"]
QUERY_KEYS = ["query", "query_name", "qname", "domain"]


@dataclass
class LogParseResult:
    records: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)


def _find_key(keys: list[str], candidates: list[str]) -> str | None:
    lowered = {k.lower(): k for k in keys}
    for c in candidates:
        if c in lowered:
            return lowered[c]
    return None


def _kind(fields: dict[str, Any]) -> str:
    keys = list(fields.keys())
    if _find_key(keys, DST_IP_KEYS):
        return "network"
    if _find_key(keys, QUERY_KEYS):
        return "dns"
    if _find_key(keys, FILE_KEYS):
        return "file"
    return "generic"


def normalise_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Add canonical aliases (dst_ip, src_ip, file_path, query) alongside original field names."""
    keys = list(fields.keys())
    out = dict(fields)
    for canonical, candidates in (("dst_ip", DST_IP_KEYS), ("src_ip", SRC_IP_KEYS), ("file_path", FILE_KEYS),
                                  ("query", QUERY_KEYS)):
        k = _find_key(keys, candidates)
        if k and canonical not in out:
            out[canonical] = fields[k]
    return out


def _coerce(value: str) -> Any:
    if re.fullmatch(r"-?\d{1,18}", value or ""):
        return int(value)
    return value


def parse_csv(path: Path, assumed_tz: str) -> LogParseResult:
    result = LogParseResult()
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    sample = "\n".join(text.splitlines()[:20])
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        result.errors.append({"line": 1, "error": "CSV has no header row"})
        return result
    ts_key = _find_key(list(reader.fieldnames), TIMESTAMP_KEYS)
    result.meta = {"columns": reader.fieldnames, "timestamp_column": ts_key, "delimiter": dialect.delimiter}
    if ts_key is None:
        result.errors.append({"line": 1, "error": "no recognised timestamp column; records kept without time"})
    for row in reader:
        line = reader.line_num
        if len(result.records) >= MAX_RECORDS:
            result.errors.append({"line": line, "error": f"record limit {MAX_RECORDS} reached"})
            break
        if None in row:  # more values than headers
            result.errors.append({"line": line, "error": "row has more columns than the header; extra values ignored"})
            row.pop(None, None)
        fields = {k: _coerce(v) if isinstance(v, str) else v for k, v in row.items() if k is not None}
        rec = {"line_number": line, "fields": normalise_fields(fields), "record_kind": _kind(fields),
               "timestamp_utc": None, "original_timestamp": "", "timezone_assumed": False,
               "message": ", ".join(f"{k}={v}" for k, v in fields.items())[:1000]}
        if ts_key:
            raw = str(row.get(ts_key) or "")
            try:
                nt = parse_timestamp(raw, assumed_tz)
                rec.update(timestamp_utc=nt.utc, original_timestamp=nt.original, timezone_assumed=nt.timezone_assumed)
            except ValueError as exc:
                result.errors.append({"line": line, "error": str(exc)})
                continue
        result.records.append(rec)
    return result


def _json_records(doc: Any) -> tuple[list[Any], dict[str, Any]]:
    if isinstance(doc, list):
        return doc, {}
    if isinstance(doc, dict):
        for key in ("events", "records", "data", "items", "hits", "results"):
            if isinstance(doc.get(key), list):
                meta = {k: v for k, v in doc.items() if k != key and not isinstance(v, list)}
                return doc[key], meta
        return [doc], {}
    raise ValueError("JSON root must be an object or array")


def parse_json(path: Path, assumed_tz: str) -> LogParseResult:
    result = LogParseResult()
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    items: list[tuple[int, Any]] = []
    try:
        doc = json.loads(text)
        records, meta = _json_records(doc)
        items = [(i + 1, r) for i, r in enumerate(records)]
        result.meta = {"format": "json", "envelope": meta}
    except json.JSONDecodeError:
        # JSON Lines
        result.meta = {"format": "jsonl"}
        for n, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            if len(line) > MAX_LINE:
                result.errors.append({"line": n, "error": "line exceeds maximum length"})
                continue
            try:
                items.append((n, json.loads(line)))
            except json.JSONDecodeError as exc:
                result.errors.append({"line": n, "error": f"invalid JSON: {exc.msg}"})
    except ValueError as exc:
        result.errors.append({"line": 1, "error": str(exc)})
        return result

    for index, item in items[:MAX_RECORDS]:
        if not isinstance(item, dict):
            result.errors.append({"line": index, "error": "record is not a JSON object"})
            continue
        ts_key = _find_key(list(item.keys()), TIMESTAMP_KEYS)
        rec = {"line_number": index, "fields": normalise_fields(item), "record_kind": _kind(item),
               "timestamp_utc": None, "original_timestamp": "", "timezone_assumed": False,
               "message": json.dumps(item, ensure_ascii=False)[:1000]}
        if ts_key is None:
            result.errors.append({"line": index, "error": "record has no recognised timestamp field"})
            continue
        try:
            nt = parse_timestamp(str(item[ts_key]), assumed_tz)
        except ValueError as exc:
            result.errors.append({"line": index, "error": str(exc)})
            continue
        rec.update(timestamp_utc=nt.utc, original_timestamp=nt.original, timezone_assumed=nt.timezone_assumed)
        result.records.append(rec)
    return result


_LEADING_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2}|\s[+-]\d{4})?)\s+(?P<rest>.*)$"
)
_DNS = re.compile(r"CLIENT\s+(?P<client>\S+)\s+QUERY\s+(?P<qtype>\S+)\s+(?P<query>\S+)\s+RESPONSE\s+(?P<rcode>\S+)(?:\s+(?P<answer>\S+))?", re.I)
_KV = re.compile(r"(\w+)=(\"[^\"]*\"|\S+)")


def parse_text(path: Path, assumed_tz: str) -> LogParseResult:
    result = LogParseResult(meta={"format": "text"})
    with open(path, encoding="utf-8", errors="replace") as fh:
        for n, line in enumerate(fh, start=1):
            line = line.rstrip("\r\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            if len(line) > MAX_LINE:
                result.errors.append({"line": n, "error": "line exceeds maximum length"})
                continue
            if len(result.records) >= MAX_RECORDS:
                result.errors.append({"line": n, "error": f"record limit {MAX_RECORDS} reached"})
                break
            m = _LEADING_TS.match(line)
            if not m:
                result.errors.append({"line": n, "error": "no leading timestamp; line not parsed", "content": line[:200]})
                continue
            try:
                nt = parse_timestamp(m.group("ts"), assumed_tz)
            except ValueError as exc:
                result.errors.append({"line": n, "error": str(exc), "content": line[:200]})
                continue
            rest = m.group("rest")
            fields: dict[str, Any] = {}
            dns = _DNS.search(rest)
            if dns:
                fields = {k: v for k, v in dns.groupdict().items() if v is not None}
                fields["src_ip"] = fields.get("client")
                kind = "dns"
            else:
                fields = {k: v.strip('"') for k, v in _KV.findall(rest)}
                kind = _kind(fields) if fields else "generic"
            result.records.append({
                "line_number": n, "fields": normalise_fields(fields), "record_kind": kind,
                "timestamp_utc": nt.utc, "original_timestamp": nt.original,
                "timezone_assumed": nt.timezone_assumed, "message": rest[:1000],
            })
    return result


PARSERS = {"csv_log": parse_csv, "json_events": parse_json, "text_log": parse_text}
