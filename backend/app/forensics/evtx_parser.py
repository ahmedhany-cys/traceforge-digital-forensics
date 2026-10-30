"""Windows EVTX parsing built on python-evtx.

Parsing is defensive: per-record failures and chunk checksum mismatches are
collected and returned with the results rather than silently skipped, so the
analyst can see exactly what could not be read.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import Evtx.Evtx as evtx
from defusedxml import ElementTree as SafeET

from .timeutil import filetime_to_datetime, parse_timestamp

ENGINE_VERSION = "evtx-1.0"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
MAX_RECORDS = 500_000


@dataclass
class ParsedEvent:
    record_number: int
    event_id: int
    provider: str
    channel: str
    computer: str
    level: int | None
    timestamp_utc: datetime
    original_timestamp: str
    user_sid: str | None
    data: dict[str, Any]


@dataclass
class EvtxParseResult:
    events: list[ParsedEvent] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)
    header: dict[str, Any] = field(default_factory=dict)
    chunks_total: int = 0
    chunks_failed_checksum: int = 0
    records_seen: int = 0


def _local(tag: str) -> str:
    return tag.split("}", 1)[-1]


def _text(el) -> str:
    return (el.text or "").strip() if el is not None else ""


def _flatten_user_data(node, prefix: str = "") -> dict[str, str]:
    out: dict[str, str] = {}
    for child in list(node):
        name = prefix + _local(child.tag)
        if len(child):
            out.update(_flatten_user_data(child, name + "."))
        else:
            out[name] = _text(child)
    return out


def parse_record_xml(xml: str, header_filetime: int | None) -> ParsedEvent:
    root = SafeET.fromstring(xml)
    system = root.find(f"{NS}System")
    if system is None:
        raise ValueError("record has no <System> element")
    event_id_el = system.find(f"{NS}EventID")
    if event_id_el is None or not _text(event_id_el).isdigit():
        raise ValueError("record has no numeric EventID")
    provider_el = system.find(f"{NS}Provider")
    time_el = system.find(f"{NS}TimeCreated")
    level_text = _text(system.find(f"{NS}Level"))
    sec = system.find(f"{NS}Security")
    rec_text = _text(system.find(f"{NS}EventRecordID"))
    execution = system.find(f"{NS}Execution")

    original = time_el.get("SystemTime", "") if time_el is not None else ""
    header_dt = filetime_to_datetime(header_filetime) if header_filetime else None
    ts: datetime | None = None
    if original:
        ts = parse_timestamp(original).utc
        # python-evtx renders FILETIME through a float, which can lose ~1µs;
        # prefer the exact record-header value when the two agree.
        if header_dt is not None and abs((header_dt - ts).total_seconds()) < 0.001:
            ts = header_dt
    elif header_dt is not None:
        ts = header_dt
        original = f"record-header FILETIME {header_filetime}"
    if ts is None:
        raise ValueError("record has no usable timestamp")

    data: dict[str, Any] = {}
    event_data = root.find(f"{NS}EventData")
    if event_data is not None:
        unnamed = 0
        for d in event_data:
            name = d.get("Name")
            if not name:
                unnamed += 1
                name = f"param{unnamed}"
            data[name] = _text(d)
    if execution is not None and execution.get("ProcessID", "").isdigit():
        data["_ExecutionProcessID"] = execution.get("ProcessID")
    user_data = root.find(f"{NS}UserData")
    if user_data is not None:
        for child in user_data:
            data["_UserDataType"] = _local(child.tag)
            data.update(_flatten_user_data(child))

    return ParsedEvent(
        record_number=int(rec_text) if rec_text.isdigit() else -1,
        event_id=int(_text(event_id_el)),
        provider=provider_el.get("Name", "") if provider_el is not None else "",
        channel=_text(system.find(f"{NS}Channel")),
        computer=_text(system.find(f"{NS}Computer")),
        level=int(level_text) if level_text.isdigit() else None,
        timestamp_utc=ts,
        original_timestamp=original,
        user_sid=sec.get("UserID") if sec is not None else None,
        data=data,
    )


def parse_evtx(path: Path, max_records: int = MAX_RECORDS) -> EvtxParseResult:
    result = EvtxParseResult()
    try:
        with evtx.Evtx(str(path)) as log:
            fh = log.get_file_header()
            result.header = {
                "magic_ok": fh.check_magic(),
                "header_checksum_ok": fh.checksum() == fh.calculate_checksum(),
                "major_version": fh.major_version(),
                "minor_version": fh.minor_version(),
                "chunk_count": fh.chunk_count(),
                "next_record_number": fh.next_record_number(),
                "dirty": fh.is_dirty(),
                "full": fh.is_full(),
            }
            if not fh.check_magic():
                result.errors.append({"scope": "file", "error": "invalid EVTX file header magic"})
                return result
            if not result.header["header_checksum_ok"]:
                result.errors.append({"scope": "file", "error": "file header CRC32 mismatch (header modified or corrupted)"})
            for chunk_index, chunk in enumerate(log.chunks()):
                result.chunks_total += 1
                try:
                    if not chunk.check_magic():
                        result.errors.append({"scope": "chunk", "chunk": chunk_index, "error": "invalid chunk magic; chunk skipped"})
                        continue
                    if chunk.calculate_header_checksum() != chunk.header_checksum() or \
                            chunk.calculate_data_checksum() != chunk.data_checksum():
                        result.chunks_failed_checksum += 1
                        result.errors.append({"scope": "chunk", "chunk": chunk_index,
                                              "error": "chunk CRC32 mismatch; records parsed but integrity of this chunk is not assured"})
                    records = chunk.records()
                    while True:
                        try:
                            record = next(records)
                        except StopIteration:
                            break
                        except Exception as exc:  # malformed record header ends the chunk
                            result.errors.append({"scope": "chunk", "chunk": chunk_index,
                                                  "error": f"record iteration stopped: {type(exc).__name__}: {exc}"})
                            break
                        result.records_seen += 1
                        if result.records_seen > max_records:
                            result.errors.append({"scope": "file", "error": f"record limit {max_records} reached; remaining records not parsed"})
                            return result
                        try:
                            raw_ft = record.unpack_qword(0x10)
                            xml = record.xml()
                            result.events.append(parse_record_xml(xml, raw_ft))
                        except Exception as exc:
                            try:
                                num = record.record_num()
                            except Exception:
                                num = None
                            result.errors.append({"scope": "record", "chunk": chunk_index, "record_number": num,
                                                  "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
                except Exception as exc:
                    result.errors.append({"scope": "chunk", "chunk": chunk_index, "error": f"{type(exc).__name__}: {str(exc)[:300]}"})
    except Exception as exc:
        result.errors.append({"scope": "file", "error": f"unable to open EVTX: {type(exc).__name__}: {str(exc)[:300]}"})
    return result
