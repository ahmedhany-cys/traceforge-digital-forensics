"""Assemble report data from stored investigation records.

The report has three parts:

* ``content`` – deterministic: built only from stored evidence metadata, analysis
  results, findings, timeline, correlations, IOCs and analyst conclusions, with
  stable ordering and without database row IDs. Its SHA-256 (``content_sha256``)
  is identical for every report generated from the same investigation state,
  which makes reports reproducible and comparable.
* ``integrity_snapshot`` – the evidence re-verification and ledger verification
  performed at generation time (time-dependent by nature).
* ``metadata`` – report ID, generation time and generator.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..forensics.event_rules import EVENT_CATALOG
from ..forensics.ledger import canonical_json, verify_ledger
from ..models import (
    IOC, AnalysisRun, AuditRecord, BrowserArtifact, Case, Correlation, Evidence, Finding, IntegrityCheck,
    TimelineEvent, User, WindowsEvent,
)

TOOL_VERSION = "TraceForge 1.0.0"
SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

STANDARD_LIMITATIONS = [
    "All findings are derived from the acquired artifacts only. Activity that was not logged (audit policy not enabled, logs rotated or cleared) is invisible to this analysis; absence of evidence is not evidence of absence.",
    "Static malware analysis does not execute samples. Packed, encrypted or staged payloads and run-time behaviour cannot be fully characterised statically.",
    "YARA matches confirm that bytes satisfy a rule's condition; the significance of a match depends on the rule and is explained per match.",
    "Correlations are hypotheses built from timestamps and shared entities (file names, hashes, process IDs, embedded indicators). They indicate plausible sequences and do not prove causation.",
    "Timestamps from different sources are normalised to UTC. Clock skew between systems and timezone assumptions for sources without timezone information can affect ordering.",
    "Process IDs are reused by Windows; PID-based lineage is bounded by host and correlation window but could mis-link processes in long investigations.",
    "Indicator assessments ('watchlist match', 'suspicious') reflect local reference data and findings, not external threat intelligence. No commercial or online reputation service was queried.",
    "The audit ledger is tamper-evident, not tamper-proof: an actor with write access to the database could rewrite the entire chain. Compare the ledger head hash with an independently stored copy to detect that.",
    "TraceForge does not certify legal admissibility or compliance with any specific chain-of-custody standard.",
]


def _iso(dt: datetime | None) -> str | None:
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def _sorted_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-SEV_RANK.get(f.severity, 0), f.source, f.rule_id, _iso(f.event_time) or "", f.evidence_id or "", f.description))


def _finding_dict(f: Finding, names: dict[str, str]) -> dict[str, Any]:
    ref = dict(f.source_ref or {})
    for volatile in ("analysis_run_id", "windows_event_ids", "browser_artifact_id", "log_record_id", "watchlist_id"):
        ref.pop(volatile, None)
    return {
        "rule_id": f.rule_id, "title": f.title, "source": f.source, "classification": f.classification,
        "severity": f.severity, "confidence": f.confidence, "evidence_id": f.evidence_id,
        "evidence_name": names.get(f.evidence_id or "", ""), "event_time_utc": _iso(f.event_time),
        "description": f.description, "rationale": f.rationale, "reference": ref,
    }


def build_content(db: Session, case: Case) -> dict[str, Any]:
    evidence = list(db.execute(select(Evidence).where(Evidence.case_id == case.id).order_by(Evidence.acquired_at, Evidence.id)).scalars())
    names = {e.id: e.original_filename for e in evidence}
    users = {u.id: u for u in db.execute(select(User)).scalars()}
    findings = list(db.execute(select(Finding).where(Finding.case_id == case.id)).scalars())
    lead = users.get(case.lead_investigator_id) if case.lead_investigator_id else None

    inventory = []
    for e in evidence:
        inventory.append({
            "evidence_id": e.id, "original_filename": e.original_filename, "artifact_type": e.artifact_type,
            "detected_type": e.detected_type, "size_bytes": e.size_bytes, "sha256": e.sha256, "sha1": e.sha1, "md5": e.md5,
            "acquired_at_utc": _iso(e.acquired_at), "acquired_by": users[e.acquired_by_id].username if e.acquired_by_id in users else "?",
            "source_host": e.source_host, "source_description": e.source_description, "duplicate_of": e.duplicate_of,
            "analysis_status": e.analysis_status,
        })

    acquisitions = []
    for r in db.execute(select(AuditRecord).where(AuditRecord.case_id == case.id, AuditRecord.action == "evidence_acquired").order_by(AuditRecord.seq)).scalars():
        acquisitions.append({"ledger_seq": r.seq, "timestamp_utc": r.timestamp, "actor": r.actor, "evidence_id": r.evidence_id,
                             "details": json.loads(r.details), "record_hash": r.record_hash})

    malware = []
    for e in evidence:
        if e.artifact_type != "pe_executable":
            continue
        run = db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id == e.id, AnalysisRun.analyzer == "pe",
                                                   AnalysisRun.is_current.is_(True))).scalar_one_or_none()
        yrun = db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id == e.id, AnalysisRun.analyzer == "yara",
                                                    AnalysisRun.is_current.is_(True))).scalar_one_or_none()
        s = run.summary if run else {}
        malware.append({
            "evidence_id": e.id, "filename": e.original_filename, "sha256": e.sha256,
            "assessment": s.get("assessment"), "file": s.get("file"), "pe": s.get("pe"),
            "sections": s.get("sections", []), "suspicious_apis": s.get("suspicious_apis", []),
            "indicators": s.get("indicators", []),
            "yara_matches": [{k: m[k] for k in ("rule", "id", "severity", "description", "explanation")} for m in (yrun.summary.get("matches", []) if yrun else [])],
            "errors": (run.errors if run else []),
        })

    yara_all = []
    for e in evidence:
        yrun = db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id == e.id, AnalysisRun.analyzer == "yara",
                                                    AnalysisRun.is_current.is_(True))).scalar_one_or_none()
        for m in (yrun.summary.get("matches", []) if yrun else []):
            yara_all.append({"evidence_id": e.id, "filename": e.original_filename, "rule": m["rule"], "id": m["id"],
                             "severity": m["severity"], "explanation": m["explanation"]})

    win_counts = Counter()
    for e in evidence:
        if e.artifact_type == "windows_evtx":
            for (eid,) in db.execute(select(WindowsEvent.event_id).where(WindowsEvent.evidence_id == e.id)):
                win_counts[eid] += 1
    windows = {
        "event_id_counts": [{"event_id": k, "description": EVENT_CATALOG.get(k, ""), "count": v} for k, v in sorted(win_counts.items())],
        "findings": [_finding_dict(f, names) for f in _sorted_findings([f for f in findings if f.source == "evtx"])],
    }

    downloads, visits = [], []
    for e in evidence:
        if e.artifact_type != "browser_history":
            continue
        for ba in db.execute(select(BrowserArtifact).where(BrowserArtifact.evidence_id == e.id).order_by(BrowserArtifact.timestamp_utc, BrowserArtifact.url)).scalars():
            row = {"evidence_id": e.id, "timestamp_utc": _iso(ba.timestamp_utc), "url": ba.url}
            if ba.kind == "download":
                x = ba.extra or {}
                downloads.append({**row, "target_path": ba.target_path, "referrer": ba.referrer, "total_bytes": ba.total_bytes,
                                  "state": x.get("state"), "danger_type": x.get("danger_type"), "sha256": x.get("sha256")})
            else:
                visits.append({**row, "title": ba.title, "visit_count": ba.visit_count, "transition": (ba.extra or {}).get("transition")})

    iocs = []
    for i in db.execute(select(IOC).where(IOC.case_id == case.id)).scalars():
        occ = [o for o in i.occurrences if "evidence_id" in o]
        iocs.append({"type": i.ioc_type, "value": i.normalized, "classification": i.classification,
                     "assessment": i.assessment, "reason": i.assessment_reason, "first_seen_utc": _iso(i.first_seen),
                     "last_seen_utc": _iso(i.last_seen), "occurrences": len(occ),
                     "sources": sorted({o["evidence_name"] for o in occ})})
    order = {"watchlist_match": 0, "suspicious": 1, "observed": 2, "benign_context": 3}
    iocs.sort(key=lambda x: (order.get(x["assessment"], 9), x["type"], x["value"]))

    timeline = []
    for t in db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case.id)).scalars():
        timeline.append({"timestamp_utc": _iso(t.timestamp_utc), "original_timestamp": t.original_timestamp,
                         "timezone_assumed": t.timezone_assumed, "source_type": t.source_type, "event_type": t.event_type,
                         "host": t.host, "severity": t.severity, "summary": t.summary, "evidence_id": t.evidence_id,
                         "evidence_name": names.get(t.evidence_id, ""), "tags": sorted(t.tags or [])})
    timeline.sort(key=lambda x: (x["timestamp_utc"], x["source_type"], x["summary"]))

    correlations = []
    for c in db.execute(select(Correlation).where(Correlation.case_id == case.id)).scalars():
        correlations.append({
            "rule_id": c.rule_id, "title": c.title, "severity": c.severity, "confidence": c.confidence,
            "classification": c.classification, "start_utc": _iso(c.start_time), "end_utc": _iso(c.end_time),
            "steps": [{k: s.get(k) for k in ("name", "description", "timestamp_utc", "summary", "source_type", "evidence_id",
                                             "link_strength", "links")} for s in c.steps],
            "explanation": c.explanation, "caveats": c.caveats,
        })
    correlations.sort(key=lambda c: (-SEV_RANK.get(c["severity"], 0), c["rule_id"], c["start_utc"] or ""))

    sorted_f = _sorted_findings(findings)
    classified = {
        "confirmed": [_finding_dict(f, names) for f in sorted_f if f.classification == "confirmed_rule_match"],
        "suspicious": [_finding_dict(f, names) for f in sorted_f if f.classification == "suspicious"],
        "informational": [_finding_dict(f, names) for f in sorted_f if f.classification == "informational"],
        "inconclusive": [_finding_dict(f, names) for f in sorted_f if f.classification == "inconclusive"],
        "hypotheses": [{"rule_id": c["rule_id"], "title": c["title"], "confidence": c["confidence"]} for c in correlations],
    }

    case_limits = []
    for e in evidence:
        for run in db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id == e.id, AnalysisRun.is_current.is_(True)).order_by(AnalysisRun.analyzer)).scalars():
            if run.errors:
                case_limits.append(f"{e.original_filename} ({run.analyzer}): {len(run.errors)} parsing issue(s) recorded, e.g. {json.dumps(run.errors[0], default=str)[:200]}")
            if run.summary.get("timezone_assumed_records"):
                case_limits.append(f"{e.original_filename}: {run.summary['timezone_assumed_records']} record(s) had no timezone; '{run.summary.get('assumed_timezone')}' was assumed.")
        if e.analysis_status != "complete":
            case_limits.append(f"{e.original_filename}: analysis status is '{e.analysis_status}'.")
    if case.is_synthetic:
        case_limits.insert(0, "This case uses SIMULATED evidence generated for training/demonstration. No real organisation, person or incident is described.")

    return {
        "case": {
            "case_number": case.case_number, "title": case.title, "organization": case.organization,
            "description": case.description, "status": case.status, "priority": case.priority,
            "lead_investigator": lead.display_name if lead else None, "synthetic_data": case.is_synthetic,
            "created_at_utc": _iso(case.created_at),
        },
        "summary": {
            "evidence_items": len(evidence),
            "findings_by_classification": dict(sorted(Counter(f.classification for f in findings).items())),
            "findings_by_severity": dict(sorted(Counter(f.severity for f in findings if f.classification in ("suspicious", "confirmed_rule_match")).items())),
            "timeline_events": len(timeline), "correlations": len(correlations), "iocs": len(iocs),
            "iocs_by_assessment": dict(sorted(Counter(i["assessment"] for i in iocs).items())),
        },
        "evidence_inventory": inventory,
        "acquisition_records": acquisitions,
        "malware_analysis": malware,
        "yara_matches": sorted(yara_all, key=lambda m: (-SEV_RANK.get(m["severity"], 0), m["filename"], m["rule"])),
        "windows_events": windows,
        "browser_artifacts": {"downloads": downloads, "visits": visits,
                              "findings": [_finding_dict(f, names) for f in sorted_f if f.source == "browser"]},
        "network_and_file_findings": [_finding_dict(f, names) for f in sorted_f if f.source in ("network", "file", "log")],
        "iocs": iocs,
        "timeline": timeline,
        "correlations": correlations,
        "classified_findings": classified,
        "analyst_conclusions": case.conclusions,
        "limitations": {"standard": STANDARD_LIMITATIONS, "case_specific": case_limits},
    }


def integrity_snapshot(db: Session, case: Case) -> dict[str, Any]:
    checks = []
    for e in db.execute(select(Evidence).where(Evidence.case_id == case.id).order_by(Evidence.id)).scalars():
        last = db.execute(select(IntegrityCheck).where(IntegrityCheck.evidence_id == e.id).order_by(IntegrityCheck.id.desc()).limit(1)).scalar_one_or_none()
        total = db.query(IntegrityCheck).filter(IntegrityCheck.evidence_id == e.id).count()
        checks.append({"evidence_id": e.id, "filename": e.original_filename, "expected_sha256": e.sha256,
                       "observed_sha256": last.observed_sha256 if last else None, "result": last.result if last else "never_checked",
                       "checked_at_utc": _iso(last.checked_at) if last else None, "checks_performed": total})
    ledger = verify_ledger(db)
    return {"evidence": checks, "ledger": ledger.as_dict()}


def content_hash(content: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(content).encode("utf-8")).hexdigest()


def build_report(db: Session, case: Case, report_id: str, generated_by: str) -> dict[str, Any]:
    content = build_content(db, case)
    return {
        "metadata": {"report_id": report_id, "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                     "generated_by": generated_by, "tool": TOOL_VERSION, "format_version": 1},
        "content_sha256": content_hash(content),
        "integrity_snapshot": integrity_snapshot(db, case),
        "content": content,
    }
