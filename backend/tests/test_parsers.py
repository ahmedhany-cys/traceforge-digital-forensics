"""EVTX, Chromium history and log parsers, including malformed input."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import pytest

from app.forensics.browser import parse_chromium_history
from app.forensics.event_rules import decode_powershell_command, evaluate_rules, load_event_rules
from app.forensics.evtx_parser import parse_evtx
from app.forensics.hashing import sha256_file
from app.forensics.logs import parse_csv, parse_json, parse_text
from conftest import BACKEND, EVIDENCE
from evtx_writer import S, windows_event, write_evtx

RULES = load_event_rules(BACKEND / "rules" / "detections" / "windows_events.json")


# ---------------------------------------------------------------- EVTX

def test_parse_security_evtx_fields_and_exact_timestamps():
    res = parse_evtx(EVIDENCE / "WS-FIN-042_Security.evtx")
    assert res.errors == []
    assert res.header["header_checksum_ok"] and res.chunks_failed_checksum == 0
    assert len(res.events) == 27
    ids = [e.event_id for e in res.events]
    assert ids.count(4688) == 9 and ids.count(4625) == 3 and ids.count(4663) == 8
    proc = next(e for e in res.events if e.event_id == 4688 and e.data["NewProcessName"].endswith("Q3_Vendor_Invoice.pdf.exe"))
    assert proc.timestamp_utc == datetime(2026, 10, 14, 13, 43, 10, 482000, tzinfo=timezone.utc)
    assert proc.computer == "WS-FIN-042.corp.meridianfs.example"
    assert proc.provider == "Microsoft-Windows-Security-Auditing" and proc.channel == "Security"
    assert proc.data["SubjectUserSid"].startswith("S-1-5-21-")
    records = [e.record_number for e in res.events]
    assert records == sorted(records)


def test_parse_userdata_event():
    res = parse_evtx(EVIDENCE / "WS-FIN-042_System.evtx")
    cleared = next(e for e in res.events if e.event_id == 104)
    assert cleared.data["_UserDataType"] == "LogFileCleared"
    assert cleared.data["Channel"] == "Windows PowerShell"
    assert cleared.user_sid.endswith("-1104")


def test_corrupted_chunk_reported_not_ignored(tmp_path):
    data = bytearray((EVIDENCE / "WS-FIN-042_Security.evtx").read_bytes())
    data[0x1000 + 0x400] ^= 0xFF  # flip a byte inside the first chunk's record data
    p = tmp_path / "corrupt.evtx"
    p.write_bytes(bytes(data))
    res = parse_evtx(p)
    assert res.chunks_failed_checksum >= 1
    assert any("CRC32 mismatch" in e["error"] for e in res.errors)


def test_truncated_and_non_evtx_files_do_not_crash(tmp_path):
    data = (EVIDENCE / "WS-FIN-042_System.evtx").read_bytes()
    trunc = tmp_path / "trunc.evtx"
    trunc.write_bytes(data[:5000])
    res = parse_evtx(trunc)
    assert res.events == [] or res.errors  # nothing silently "succeeds" from a partial chunk
    junk = tmp_path / "junk.evtx"
    junk.write_bytes(b"not an event log at all" * 300)
    res = parse_evtx(junk)
    assert res.events == [] and res.errors


def test_record_level_error_is_reported(tmp_path):
    good = windows_event(provider="P", provider_guid=None, event_id=4624, timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
                         record_id=1, channel="Security", computer="H", event_data=[("A", "1")])
    from evtx_writer import Element
    no_system = type(good)(timestamp=good.timestamp, root=Element("Event", [], [Element("Other", [], [S("x")])]))
    p = tmp_path / "mixed.evtx"
    p.write_bytes(write_evtx([good, no_system]))
    res = parse_evtx(p)
    assert len(res.events) == 1
    assert any(e["scope"] == "record" and "System" in e["error"] for e in res.errors)


def test_event_rules_on_dataset():
    events = parse_evtx(EVIDENCE / "WS-FIN-042_Security.evtx").events
    matches = evaluate_rules(RULES, events)
    by_rule = {}
    for m in matches:
        by_rule.setdefault(m.rule["id"], []).append(m)
    assert len(by_rule["WIN-PROC-002"]) == 1  # double extension executed once
    enc = by_rule["WIN-PROC-003"]
    assert len(enc) == 3 and all("decoded_command" in m.detail for m in enc)
    assert any("Compress-Archive" in m.detail["decoded_command"] for m in enc)
    assert by_rule["WIN-AUTH-001"][0].detail["count"] == 3
    assert len(by_rule["WIN-ACCT-002"]) == 1 and len(by_rule["WIN-FILE-001"]) == 8
    assert "WIN-DEF-001" not in by_rule  # Security log was never cleared in this scenario


def test_aggregation_threshold_not_reached():
    events = [e for e in parse_evtx(EVIDENCE / "WS-FIN-042_Security.evtx").events if e.event_id == 4625][:2]
    assert not [m for m in evaluate_rules(RULES, events) if m.rule["id"] == "WIN-AUTH-001"]


def test_decode_powershell_command():
    import base64
    enc = base64.b64encode("Get-Date".encode("utf-16-le")).decode()
    assert decode_powershell_command(f"powershell.exe -nop -enc {enc}") == "Get-Date"
    assert decode_powershell_command("powershell.exe -enc !!!notbase64!!!") is None
    assert decode_powershell_command("powershell.exe -File x.ps1") is None


# ---------------------------------------------------------------- Chromium history

def test_parse_chromium_history(tmp_path):
    path = EVIDENCE / "Chrome_History_jmorales.sqlite"
    before = sha256_file(path)
    res = parse_chromium_history(path, tmp_path)
    assert res.errors == [] and res.meta["quick_check"] == ["ok"]
    assert len(res.visits) == 8 and len(res.downloads) == 2
    dl = next(d for d in res.downloads if d["target_path"].endswith(".pdf.exe"))
    assert dl["timestamp_utc"] == datetime(2026, 10, 14, 13, 41, 45, 102000, tzinfo=timezone.utc)
    assert dl["danger_type"] == "user_validated" and dl["state"] == "complete"
    assert dl["referrer"] == "https://mail.meridianfs.example/owa/"
    assert dl["sha256"] == sha256_file(EVIDENCE / "Q3_Vendor_Invoice.pdf.exe")
    typed = next(v for v in res.visits if v["url"] == "https://intranet.meridianfs.example/")
    assert typed["transition"] == "typed"
    assert sha256_file(path) == before
    assert not list(tmp_path.rglob("*.sqlite*"))  # working copy removed


def test_history_with_hostile_strings_is_inert(tmp_path):
    db = tmp_path / "History"
    con = sqlite3.connect(db)
    con.executescript("""
        CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER);
        CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER, visit_duration INTEGER);
    """)
    con.execute("INSERT INTO urls VALUES (1, ?, ?, 1, 0, 13400000000000000, 0)",
                ("https://x.example/'; DROP TABLE urls; --", "<script>alert(1)</script>"))
    con.execute("INSERT INTO visits VALUES (1, 1, 13400000000000000, 0, 0, 0)")
    con.commit()
    con.close()
    res = parse_chromium_history(db, tmp_path / "work")
    assert res.visits[0]["url"].endswith("DROP TABLE urls; --")
    assert res.visits[0]["title"] == "<script>alert(1)</script>"  # stored verbatim; rendered as text by the UI
    assert sqlite3.connect(db).execute("SELECT count(*) FROM urls").fetchone()[0] == 1


def test_malformed_and_non_chromium_sqlite(tmp_path):
    bad = tmp_path / "bad.sqlite"
    bad.write_bytes(b"SQLite format 3\x00" + b"\xff" * 4000)
    res = parse_chromium_history(bad, tmp_path / "w1")
    assert res.errors and not res.visits
    other = tmp_path / "other.sqlite"
    con = sqlite3.connect(other)
    con.execute("CREATE TABLE notes(id INTEGER, body TEXT)")
    con.commit()
    con.close()
    res = parse_chromium_history(other, tmp_path / "w2")
    assert any("not a Chromium History" in e["error"] for e in res.errors)


# ---------------------------------------------------------------- logs

def test_parse_firewall_csv():
    res = parse_csv(EVIDENCE / "fw-edge-01_connections.csv", "UTC")
    assert res.errors == [] and len(res.records) == 11
    exfil = max(res.records, key=lambda r: r["fields"]["bytes_sent"])
    assert exfil["record_kind"] == "network" and exfil["fields"]["dst_ip"] == "203.0.113.77"
    assert exfil["timestamp_utc"] == datetime(2026, 10, 14, 13, 58, 6, tzinfo=timezone.utc)


def test_parse_edr_json_envelope_with_offsets():
    res = parse_json(EVIDENCE / "edr_file_events.json", "UTC")
    assert res.errors == [] and len(res.records) == 9
    assert res.meta["envelope"]["export"]["notice"].startswith("SIMULATED")
    first = res.records[1]
    assert first["original_timestamp"].endswith("-04:00")
    assert first["timestamp_utc"].hour == 13 and not first["timezone_assumed"]


def test_parse_dns_text_reports_bad_lines():
    res = parse_text(EVIDENCE / "resolver_queries.log", "UTC")
    assert len(res.records) == 11
    assert len(res.errors) == 1 and res.errors[0]["line"] == 8
    q = next(r for r in res.records if r["fields"]["query"] == "upload.meridian-sync.example")
    assert q["record_kind"] == "dns" and q["fields"]["answer"] == "203.0.113.77"


def test_jsonl_with_invalid_lines(tmp_path):
    p = tmp_path / "events.jsonl"
    p.write_text("\n".join([
        json.dumps({"timestamp": "2026-10-14T10:00:00", "dst_ip": "8.8.8.8"}),
        "{not json",
        json.dumps({"no_time": True}),
        json.dumps(["not", "an", "object"]),
    ]))
    res = parse_json(p, "Europe/London")
    assert len(res.records) == 1 and res.records[0]["timezone_assumed"]
    assert res.records[0]["timestamp_utc"].hour == 9  # BST = UTC+1
    assert {e["line"] for e in res.errors} == {2, 3, 4}


def test_csv_without_timestamp_column_and_ragged_rows(tmp_path):
    p = tmp_path / "x.csv"
    p.write_text("a,b\n1,2\n3,4,5\n")
    res = parse_csv(p, "UTC")
    assert any("no recognised timestamp column" in e["error"] for e in res.errors)
    assert any("more columns" in e["error"] for e in res.errors)
