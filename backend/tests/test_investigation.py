"""End-to-end reconstruction of the Meridian scenario: timeline, correlation, IOCs, reports."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from app.forensics.correlation import Correlator, load_correlation_rules
from conftest import BACKEND, EVIDENCE

CORR_RULES = load_correlation_rules(BACKEND / "rules" / "detections" / "correlation.json")


def test_all_evidence_analysed(demo):
    evidence = demo.client.get(f"/api/cases/{demo.case_id}/evidence").json()
    assert len(evidence) == 9
    assert {e["analysis_status"] for e in evidence} == {"complete"}
    assert {e["integrity_status"] for e in evidence} == {"verified"}


def test_timeline_is_chronological_utc_and_traceable(demo):
    items = demo.client.get(f"/api/cases/{demo.case_id}/timeline").json()["items"]
    assert len(items) == 79
    stamps = [i["timestamp_utc"] for i in items]
    assert stamps == sorted(stamps) and all(s.endswith("Z") for s in stamps)
    sources = {i["source_type"] for i in items}
    assert sources == {"windows_evtx", "browser_history", "csv_log", "text_log", "json_events"}
    for i in items:
        assert i["original_timestamp"] and i["source_ref"]["table"] in ("windows_events", "browser_artifacts", "log_records")
    edr = next(i for i in items if i["source_type"] == "json_events" and "Q3_Vendor_Invoice" in i["summary"])
    assert edr["original_timestamp"] == "2026-10-14T09:41:49.702-04:00"
    assert edr["timestamp_utc"] == "2026-10-14T13:41:49.702Z"


def test_timeline_filters(demo):
    high = demo.client.get(f"/api/cases/{demo.case_id}/timeline?min_severity=high").json()["items"]
    assert high and all(i["severity"] in ("high", "critical") for i in high)
    dns = demo.client.get(f"/api/cases/{demo.case_id}/timeline?source_type=text_log&q=meridian-sync").json()["items"]
    assert len(dns) == 5 and all("meridian-sync" in i["summary"] for i in dns)


def test_full_intrusion_chain_correlated_with_entity_links(demo):
    corrs = {c["rule_id"]: c for c in demo.client.get(f"/api/cases/{demo.case_id}/correlations").json()}
    chain = corrs["CORR-002"]
    assert chain["classification"] == "hypothesis" and chain["confidence"] == "high"
    steps = {s["name"]: s for s in chain["steps"]}
    assert list(steps) == ["download", "file_written", "execution", "sensitive_access", "exfiltration"]
    assert any("same sha256" in link for link in steps["file_written"]["links"])
    assert any("lineage" in link for link in steps["sensitive_access"]["links"])
    assert any("hard-coded" in link and "203.0.113.77" in link for link in steps["exfiltration"]["links"])
    assert any("does not by itself prove causation" in c for c in chain["caveats"])
    # every step references a real timeline event
    timeline_ids = {i["id"] for i in demo.client.get(f"/api/cases/{demo.case_id}/timeline").json()["items"]}
    assert all(s["timeline_event_id"] in timeline_ids for s in chain["steps"])


def test_temporal_only_links_lower_confidence(demo):
    corrs = {c["rule_id"]: c for c in demo.client.get(f"/api/cases/{demo.case_id}/correlations").json()}
    assert corrs["CORR-004"]["confidence"] == "low"
    assert corrs["CORR-004"]["steps"][1]["link_strength"] == "temporal"
    assert corrs["CORR-003"]["confidence"] == "high"


def test_unrelated_failed_logons_not_pulled_into_sequences(demo):
    for c in demo.client.get(f"/api/cases/{demo.case_id}/correlations").json():
        assert not any("Failed logon" in s["summary"] for s in c["steps"])


@dataclass
class FakeEvent:
    id: int
    timestamp_utc: datetime
    event_type: str
    host: str = "H1"
    entities: dict = field(default_factory=dict)
    tags: list = field(default_factory=list)
    severity: str = "info"
    summary: str = ""
    source_type: str = "test"
    evidence_id: str = "EV"
    timezone_assumed: bool = False


def test_correlator_does_not_invent_missing_steps():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    events = [
        FakeEvent(1, t0, "file_download", entities={"file_name": "a.exe"}),
        FakeEvent(2, t0 + timedelta(minutes=5), "process_creation", entities={"file_name": "other.exe", "pid": 10}),
    ]
    results = Correlator(events, {}, 180).run([r for r in CORR_RULES if r["id"] == "CORR-001"])
    assert results == []  # execution of a *different* file never satisfies the required entity link
    events.append(FakeEvent(3, t0 + timedelta(minutes=6), "process_creation", entities={"file_name": "a.exe", "pid": 11}))
    results = Correlator(events, {}, 180).run([r for r in CORR_RULES if r["id"] == "CORR-001"])
    assert len(results) == 1 and [m.event.id for m in results[0].steps] == [1, 3]


def test_correlator_respects_window_and_host():
    t0 = datetime(2026, 1, 1, tzinfo=timezone.utc)
    rule = [r for r in CORR_RULES if r["id"] == "CORR-004"]
    archive = FakeEvent(1, t0, "file_create", entities={"file_name": "x.zip"})
    late = FakeEvent(2, t0 + timedelta(minutes=30), "network_connection", entities={"dst_external": True, "bytes_sent": 50_000_000})
    other_host = FakeEvent(3, t0 + timedelta(minutes=2), "network_connection", host="H2",
                           entities={"dst_external": True, "bytes_sent": 50_000_000})
    assert Correlator([archive, late, other_host], {}, 180).run(rule) == []


def test_iocs_assessed_conservatively(demo):
    iocs = {(i["ioc_type"], i["normalized"]): i for i in demo.client.get(f"/api/cases/{demo.case_id}/iocs").json()}
    assert iocs[("ipv4", "203.0.113.77")]["assessment"] == "watchlist_match"
    assert iocs[("ipv4", "203.0.113.77")]["classification"] == "documentation"
    assert iocs[("ipv4", "10.20.1.15")]["assessment"] == "benign_context"
    assert iocs[("domain", "news.example.com")]["assessment"] == "observed"
    assert iocs[("process", "explorer.exe")]["assessment"] == "observed"
    assert iocs[("process", "q3_vendor_invoice.pdf.exe")]["assessment"] == "suspicious"
    assert iocs[("filename", "q3_vendor_invoice.pdf.exe")]["classification"] == "double_extension_executable"
    sample = iocs[("sha256", "b52143d4a49a8f3f362012f22805ec0da015a4efe8968a6167f72b5b79263290")]
    sources = {o["evidence_name"] for o in sample["occurrences"] if "evidence_name" in o}
    assert {"Chrome_History_jmorales.sqlite", "edr_file_events.json", "Q3_Vendor_Invoice.pdf.exe"} <= sources
    for i in iocs.values():
        assert i["assessment_reason"]


def test_dashboard_metrics_come_from_database(demo):
    d = demo.client.get(f"/api/cases/{demo.case_id}/dashboard").json()
    findings = demo.client.get(f"/api/cases/{demo.case_id}/findings?classification=suspicious,confirmed_rule_match").json()
    assert sum(d["findings_by_severity"].values()) == len(findings)
    assert d["evidence_total"] == 9 and d["timeline_total"] == 79
    assert d["evidence_bytes"] == sum(p.stat().st_size for p in EVIDENCE.iterdir())
    assert sum(sum(v for k, v in b.items() if k != "bucket") for b in d["activity"]) == 79


def test_windows_events_api_filters(demo):
    r = demo.client.get(f"/api/cases/{demo.case_id}/windows-events?event_id=4688&page_size=5").json()
    assert r["total"] == 9 and len(r["items"]) == 5
    flagged = demo.client.get(f"/api/cases/{demo.case_id}/windows-events?flagged_only=true").json()
    assert all(any(d["classification"] != "informational" for d in i["detections"]) for i in flagged["items"])
    s = demo.client.get(f"/api/cases/{demo.case_id}/windows-events?q=%25' OR 1=1 --").json()
    assert s["total"] == 0  # search term is a bound parameter, not SQL


def test_reports_are_reproducible_and_complete(demo):
    r1 = demo.client.post(f"/api/cases/{demo.case_id}/reports", json={"format": "json"}).json()
    r2 = demo.client.post(f"/api/cases/{demo.case_id}/reports", json={"format": "json"}).json()
    pdf = demo.client.post(f"/api/cases/{demo.case_id}/reports", json={"format": "pdf"}).json()
    assert r1["content_sha256"] == r2["content_sha256"] == pdf["content_sha256"]
    assert r1["sha256"] != r2["sha256"]  # metadata (report id, time, integrity snapshot) differs
    body = demo.client.get(f"/api/reports/{r1['id']}/download")
    assert body.status_code == 200 and body.headers["x-report-sha256"] == r1["sha256"]
    report = json.loads(body.content)
    c = report["content"]
    for section in ("case", "evidence_inventory", "acquisition_records", "malware_analysis", "windows_events",
                    "browser_artifacts", "iocs", "timeline", "correlations", "classified_findings",
                    "analyst_conclusions", "limitations"):
        assert section in c, section
    assert c["case"]["synthetic_data"] is False  # TEST-001 is not marked synthetic
    assert report["integrity_snapshot"]["ledger"]["valid"] is True
    assert all(e["result"] == "match" for e in report["integrity_snapshot"]["evidence"])
    assert len(c["classified_findings"]["hypotheses"]) == len(c["correlations"])
    pdf_bytes = demo.client.get(f"/api/reports/{pdf['id']}/download").content
    assert pdf_bytes.startswith(b"%PDF-") and len(pdf_bytes) > 20_000


def test_rebuild_is_deterministic(demo):
    before = demo.client.get(f"/api/cases/{demo.case_id}/correlations").json()
    stats = demo.client.post(f"/api/cases/{demo.case_id}/rebuild").json()
    after = demo.client.get(f"/api/cases/{demo.case_id}/correlations").json()
    strip = lambda cs: [(c["rule_id"], c["confidence"], [(s["name"], s["summary"]) for s in c["steps"]]) for c in cs]
    assert strip(before) == strip(after)
    assert stats["timeline_events"] == 79
