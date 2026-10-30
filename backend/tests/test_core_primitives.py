"""Hashing, entropy, timestamp normalisation and file-type identification."""

from __future__ import annotations

import hashlib
import io
import json
import math
import os
from datetime import datetime, timezone

import pytest

from app.forensics.entropy import entropy_profile, shannon_entropy
from app.forensics.filetype import check_extension, detect_bytes, extension_of
from app.forensics.hashing import hash_file, hash_stream, sha256_bytes
from app.forensics.timeutil import filetime_to_datetime, iso, parse_timestamp, webkit_to_datetime
from conftest import EVIDENCE


# ---------------------------------------------------------------- hashing

def test_sha256_known_vectors():
    assert sha256_bytes(b"") == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert sha256_bytes(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


def test_hash_stream_multi_chunk_matches_hashlib():
    data = os.urandom(3 * 1024 * 1024 + 17)  # spans several 1 MiB read blocks
    h = hash_stream(io.BytesIO(data))
    assert h.sha256 == hashlib.sha256(data).hexdigest()
    assert h.sha1 == hashlib.sha1(data).hexdigest()
    assert h.md5 == hashlib.md5(data).hexdigest()
    assert h.size == len(data)


def test_hash_file_matches_manifest():
    manifest = json.loads((EVIDENCE.parent / "manifest.json").read_text())
    for item in manifest["files"]:
        h = hash_file(EVIDENCE / item["filename"])
        assert h.sha256 == item["sha256"]
        assert h.size == item["size_bytes"]


# ---------------------------------------------------------------- entropy

def test_entropy_bounds_and_known_values():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 4096) == 0.0
    assert shannon_entropy(b"\x00\xff" * 2048) == pytest.approx(1.0)
    assert shannon_entropy(bytes(range(256)) * 16) == pytest.approx(8.0)
    four = bytes([0, 1, 2, 3]) * 100
    assert shannon_entropy(four) == pytest.approx(math.log2(4))


def test_entropy_profile_blocks():
    data = b"\x00" * 4096 + bytes(range(256)) * 16
    assert entropy_profile(data, 4096) == [0.0, 8.0]


# ---------------------------------------------------------------- timestamps

def test_parse_iso_z_and_offsets():
    a = parse_timestamp("2026-10-14T13:41:49.702Z")
    b = parse_timestamp("2026-10-14T09:41:49.702-04:00")
    c = parse_timestamp("2026-10-14 09:41:49.702 -0400")
    assert a.utc == b.utc == c.utc == datetime(2026, 10, 14, 13, 41, 49, 702000, tzinfo=timezone.utc)
    assert not (a.timezone_assumed or b.timezone_assumed or c.timezone_assumed)
    assert c.original == "2026-10-14 09:41:49.702 -0400"


def test_naive_timestamp_uses_assumed_zone_and_is_flagged():
    nt = parse_timestamp("2026-10-14 09:41:49", "America/New_York")
    assert nt.timezone_assumed is True
    assert nt.utc == datetime(2026, 10, 14, 13, 41, 49, tzinfo=timezone.utc)  # EDT = UTC-4
    winter = parse_timestamp("2026-12-01 09:00:00", "America/New_York")
    assert winter.utc.hour == 14  # EST = UTC-5, DST handled by zoneinfo


def test_epoch_seconds_and_millis():
    assert parse_timestamp("1792000000").utc == datetime.fromtimestamp(1792000000, timezone.utc)
    assert parse_timestamp("1792000000123").utc.year == 2026


@pytest.mark.parametrize("bad", ["", "yesterday", "2026-13-40 99:99:99", "1850-01-01T00:00:00Z", "12345"])
def test_invalid_or_implausible_timestamps_rejected(bad):
    with pytest.raises(ValueError):
        parse_timestamp(bad)


def test_unknown_timezone_rejected():
    with pytest.raises(ValueError):
        parse_timestamp("2026-10-14 09:00:00", "Mars/Olympus_Mons")


def test_filetime_and_webkit_conversion_exact():
    # 2026-10-14 13:41:45.102 UTC
    expected = datetime(2026, 10, 14, 13, 41, 45, 102000, tzinfo=timezone.utc)
    micros = int((expected - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 1_000_000 + 102000
    assert webkit_to_datetime(micros) == expected
    assert filetime_to_datetime(micros * 10) == expected
    assert webkit_to_datetime(0) is None and filetime_to_datetime(0) is None
    assert iso(expected) == "2026-10-14T13:41:45.102Z"


# ---------------------------------------------------------------- file types

def test_detects_dataset_formats():
    expectations = {
        "WS-FIN-042_Security.evtx": "windows_evtx",
        "Chrome_History_jmorales.sqlite": "browser_history",
        "fw-edge-01_connections.csv": "csv_log",
        "edr_file_events.json": "json_events",
        "resolver_queries.log": "text_log",
        "Q3_Vendor_Invoice.pdf.exe": "pe_executable",
    }
    for name, artifact in expectations.items():
        data = (EVIDENCE / name).read_bytes()
        detected = detect_bytes(data[:65536], len(data))
        assert detected.artifact_type == artifact, name
        assert check_extension(name, detected)[0], name


def test_extension_content_mismatch_rejected():
    text = b"just some text pretending to be a program\n"
    detected = detect_bytes(text, len(text))
    ok, reason = check_extension("invoice.exe", detected)
    assert not ok and "does not match" in reason
    evtx = (EVIDENCE / "WS-FIN-042_System.evtx").read_bytes()
    ok, _ = check_extension("system.csv", detect_bytes(evtx[:65536], len(evtx)))
    assert not ok


@pytest.mark.parametrize("payload,kind", [
    (b"\x7fELF\x02\x01\x01" + b"\x00" * 64, "elf"),
    (b"PK\x03\x04" + b"\x00" * 64, "zip"),
    (b"%PDF-1.7\n" + b"\x00" * 64, "pdf"),
    (b"MZ" + b"\x00" * 200, "mz"),
    (bytes(range(256)) * 4, "binary"),
])
def test_unsupported_formats_have_no_artifact_type(payload, kind):
    detected = detect_bytes(payload, len(payload))
    assert detected.kind == kind
    assert detected.artifact_type is None
    assert not check_extension("x.log", detected)[0]


def test_unknown_extension_rejected_and_extension_parsing():
    detected = detect_bytes(b"a,b\n1,2\n", 8)
    assert not check_extension("data.xyz", detected)[0]
    assert extension_of("../../x/evil.EXE") == ".exe"
    assert extension_of("History") == ""
    assert extension_of(".bashrc") == ""
