"""The synthetic dataset is reproducible and internally consistent."""

from __future__ import annotations

import csv
import hashlib
import json

import generate
from app.forensics.browser import parse_chromium_history
from app.forensics.evtx_parser import parse_evtx
from app.forensics.pe_analysis import analyze_pe
from conftest import DATASET, EVIDENCE


def test_generator_is_deterministic_and_matches_committed_manifest(tmp_path):
    m1 = generate.generate(tmp_path / "a")
    m2 = generate.generate(tmp_path / "b")
    assert [f["sha256"] for f in m1["files"]] == [f["sha256"] for f in m2["files"]]
    committed = json.loads((DATASET / "manifest.json").read_text())
    assert committed["synthetic"] is True
    assert {f["filename"]: f["sha256"] for f in committed["files"]} == {f["filename"]: f["sha256"] for f in m1["files"]}


def test_cross_source_consistency(tmp_path):
    sample_sha = hashlib.sha256((EVIDENCE / "Q3_Vendor_Invoice.pdf.exe").read_bytes()).hexdigest()
    edr = json.loads((EVIDENCE / "edr_file_events.json").read_text())["events"]
    assert [e["sha256"] for e in edr if e["file_path"].endswith(("Q3_Vendor_Invoice.pdf.exe", "msync.exe"))] == [sample_sha, sample_sha]
    downloads = parse_chromium_history(EVIDENCE / "Chrome_History_jmorales.sqlite", tmp_path).downloads
    assert any(d["sha256"] == sample_sha for d in downloads)
    fw = list(csv.DictReader(open(EVIDENCE / "fw-edge-01_connections.csv")))
    c2_rows = [r for r in fw if r["dst_ip"] == generate.C2_IP]
    assert any(int(r["bytes_sent"]) == generate.EXFIL_BYTES for r in c2_rows)
    pe = analyze_pe(EVIDENCE / "Q3_Vendor_Invoice.pdf.exe")
    strings = " ".join(s["value"] for s in pe["strings"]["interesting"])
    assert generate.C2_IP in strings and generate.UPLOAD_DOMAIN in strings
    dns = (EVIDENCE / "resolver_queries.log").read_text()
    assert f"{generate.UPLOAD_DOMAIN} RESPONSE NOERROR {generate.C2_IP}" in dns
    sec = parse_evtx(EVIDENCE / "WS-FIN-042_Security.evtx").events
    exec_evt = next(e for e in sec if e.event_id == 4688 and e.data["NewProcessName"] == generate.DOWNLOAD_PATH)
    download = next(d for d in downloads if d["target_path"] == generate.DOWNLOAD_PATH)
    assert download["timestamp_utc"] < exec_evt.timestamp_utc  # executed after it was downloaded


def test_all_public_looking_addresses_are_reserved_for_documentation():
    from app.forensics.ioc import extract_from_text
    from app.forensics.netclass import classify_domain, classify_ip
    for path in EVIDENCE.iterdir():
        if path.suffix in (".csv", ".log", ".json"):
            for ind in extract_from_text(path.read_text()):
                if ind.ioc_type == "ipv4":
                    assert classify_ip(ind.normalized) in ("private", "documentation", "loopback"), ind
                if ind.ioc_type == "domain":
                    assert classify_domain(ind.normalized) != "public_namespace", ind
