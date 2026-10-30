"""Per-evidence analysis pipeline.

Every run:

1. verifies the vault copy's SHA-256 *before* analysis (refuses to analyse
   evidence whose hash no longer matches),
2. runs YARA over the bytes and the type-specific parser/analyzer,
3. persists parsed records and findings, replacing results of earlier runs,
4. verifies the SHA-256 again *after* analysis to demonstrate the analysis
   did not modify the evidence,
5. appends ledger records for start and completion.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, update
from sqlalchemy.orm import Session

from ..config import Settings
from ..forensics import browser as browser_mod
from ..forensics import evtx_parser, logs, pe_analysis, yara_engine
from ..forensics.artifact_rules import browser_rules, log_rules
from ..forensics.event_rules import describe_event, evaluate_rules, load_event_rules
from ..forensics.ledger import append_record
from ..models import AnalysisRun, BrowserArtifact, Evidence, Finding, LogRecord, TimelineEvent, WindowsEvent
from . import runtime_settings
from .acquisition import evidence_path
from .integrity import verify_evidence

YARA_CLASS = "confirmed_rule_match"


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    if isinstance(value, bytes):
        return value.hex()
    return value


def _clear_previous(db: Session, evidence: Evidence) -> None:
    db.execute(update(AnalysisRun).where(AnalysisRun.evidence_id == evidence.id).values(is_current=False))
    for model in (WindowsEvent, BrowserArtifact, LogRecord, TimelineEvent):
        db.execute(delete(model).where(model.evidence_id == evidence.id))
    db.execute(delete(Finding).where(Finding.evidence_id == evidence.id, Finding.source != "ioc"))


def _start_run(db: Session, evidence: Evidence, analyzer: str, version: str) -> AnalysisRun:
    run = AnalysisRun(evidence_id=evidence.id, analyzer=analyzer, engine_version=version,
                      started_at=datetime.now(timezone.utc), status="running", input_sha256=evidence.sha256)
    db.add(run)
    db.flush()
    return run


def _finish(run: AnalysisRun, status: str, summary: dict, errors: list) -> None:
    run.status = status
    run.summary = _json_safe(summary)
    run.errors = _json_safe(errors)[:500]
    run.finished_at = datetime.now(timezone.utc)


def analyze_evidence(db: Session, settings: Settings, evidence: Evidence, actor: str) -> dict[str, Any]:
    pre = verify_evidence(db, settings, evidence, actor, trigger="pre_analysis", commit=False)
    if pre.result != "match":
        evidence.analysis_status = "error"
        append_record(db, actor=actor, action="analysis_refused", case_id=evidence.case_id, evidence_id=evidence.id,
                      details={"reason": f"integrity check {pre.result}"}, commit=False)
        db.commit()
        return {"status": "refused", "reason": f"integrity check {pre.result}"}

    append_record(db, actor=actor, action="analysis_started", case_id=evidence.case_id, evidence_id=evidence.id,
                  details={"artifact_type": evidence.artifact_type}, commit=False)
    evidence.analysis_status = "running"
    _clear_previous(db, evidence)
    path = evidence_path(settings, evidence)
    rt = runtime_settings.get_all(db)
    findings: list[Finding] = []
    summary: dict[str, Any] = {}

    # ---- YARA: every evidence type -------------------------------------
    ruleset = yara_engine.load_rules(settings.rules_dir / "yara")
    yrun = _start_run(db, evidence, "yara", yara_engine.ENGINE_VERSION)
    yres = yara_engine.scan_file(ruleset, path)
    _finish(yrun, yres["status"], yres, yres["errors"])
    for m in yres["matches"]:
        findings.append(Finding(
            case_id=evidence.case_id, evidence_id=evidence.id, analysis_run_id=yrun.id, source="yara",
            rule_id=m["id"], title=f"YARA {m['rule']}: {m['description']}", classification=YARA_CLASS,
            severity=m["severity"], confidence="high",
            description=f"Rule {m['rule']} ({m['id']}) matched {len(m['strings'])} string instance(s) in {evidence.original_filename}.",
            rationale=m["explanation"], source_ref={"analysis_run_id": yrun.id, "rule": m["rule"], "strings": m["strings"][:10]},
        ))
    summary["yara"] = {"matches": len(yres["matches"]), "rules_loaded": yres["rules_loaded"]}

    # ---- type specific ---------------------------------------------------
    kind = evidence.artifact_type
    try:
        if kind == "pe_executable":
            summary.update(_analyze_pe(db, evidence, path, findings))
        elif kind == "windows_evtx":
            summary.update(_analyze_evtx(db, settings, evidence, path, findings))
        elif kind == "browser_history":
            summary.update(_analyze_browser(db, settings, evidence, path, findings))
        elif kind in logs.PARSERS:
            summary.update(_analyze_log(db, evidence, path, findings, rt))
        status = "complete"
    except Exception as exc:  # analyzer bug or hostile input: record, never crash the API
        db.rollback()
        evidence = db.get(Evidence, evidence.id)
        evidence.analysis_status = "error"
        append_record(db, actor=actor, action="analysis_failed", case_id=evidence.case_id, evidence_id=evidence.id,
                      details={"error": f"{type(exc).__name__}: {str(exc)[:500]}"}, commit=False)
        db.commit()
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}

    db.add_all(findings)
    post = verify_evidence(db, settings, evidence, actor, trigger="post_analysis", commit=False)
    evidence.analysis_status = status if post.result == "match" else "error"
    counts = Counter(f.classification for f in findings)
    summary["findings"] = dict(counts)
    summary["post_analysis_integrity"] = post.result
    append_record(db, actor=actor, action="analysis_completed", case_id=evidence.case_id, evidence_id=evidence.id,
                  details={"status": evidence.analysis_status, "findings": dict(counts),
                           "post_analysis_sha256": post.observed_sha256}, commit=False)
    db.commit()
    return {"status": evidence.analysis_status, "summary": _json_safe(summary)}


def _analyze_pe(db, evidence, path, findings) -> dict:
    run = _start_run(db, evidence, "pe", pe_analysis.ENGINE_VERSION)
    res = pe_analysis.analyze_pe(path, evidence.original_filename)
    _finish(run, "complete" if not res["errors"] else "partial", res, res["errors"])
    for ind in res["indicators"]:
        findings.append(Finding(
            case_id=evidence.case_id, evidence_id=evidence.id, analysis_run_id=run.id, source="pe",
            rule_id=ind["id"], title=ind["title"], classification=ind["classification"], severity=ind["severity"],
            confidence=ind["confidence"], description=f"{ind['title']} in {evidence.original_filename}.",
            rationale=ind["rationale"], source_ref={"analysis_run_id": run.id, "evidence": _json_safe(ind["evidence"])},
        ))
    return {"pe": res["assessment"]}


def _analyze_evtx(db, settings, evidence, path, findings) -> dict:
    run = _start_run(db, evidence, "evtx", evtx_parser.ENGINE_VERSION)
    parsed = evtx_parser.parse_evtx(path)
    rows = []
    for ev in parsed.events:
        rows.append(WindowsEvent(
            evidence_id=evidence.id, analysis_run_id=run.id, record_number=ev.record_number, event_id=ev.event_id,
            provider=ev.provider[:255], channel=ev.channel[:255], computer=ev.computer[:255], level=ev.level,
            timestamp_utc=ev.timestamp_utc, original_timestamp=ev.original_timestamp[:64], user_sid=ev.user_sid,
            data=ev.data, description=describe_event(ev)[:255],
        ))
    db.add_all(rows)
    db.flush()
    row_of = {id(ev): row for ev, row in zip(parsed.events, rows)}
    rules = load_event_rules(settings.rules_dir / "detections" / "windows_events.json")
    matches = evaluate_rules(rules, parsed.events)
    for m in matches:
        ev_rows = [row_of[id(e)] for e in m.events]
        first = ev_rows[0]
        rule = m.rule
        desc = rule["description"]
        if m.detail.get("count"):
            desc += f" Observed {m.detail['count']} events for {m.detail['group']}."
        else:
            desc += f" Event: {first.description}"
        if m.detail.get("decoded_command"):
            desc += f" Decoded command: {m.detail['decoded_command']}"
        findings.append(Finding(
            case_id=evidence.case_id, evidence_id=evidence.id, analysis_run_id=run.id, source="evtx",
            rule_id=rule["id"], title=rule["title"], classification=rule["classification"], severity=rule["severity"],
            confidence=rule["confidence"], description=desc[:4000],
            rationale=rule["rationale"] + (f" Prerequisites: {rule['prerequisites']}" if rule.get("prerequisites") else ""),
            event_time=first.timestamp_utc,
            source_ref={"analysis_run_id": run.id, "windows_event_ids": [r.id for r in ev_rows],
                        "record_numbers": [r.record_number for r in ev_rows], "event_id": first.event_id,
                        "mitre": rule.get("mitre", []), **({"decoded_command": m.detail["decoded_command"]} if m.detail.get("decoded_command") else {})},
        ))
    times = [e.timestamp_utc for e in parsed.events]
    summary = {
        "records_parsed": len(parsed.events), "records_seen": parsed.records_seen, "errors": len(parsed.errors),
        "chunks": parsed.chunks_total, "chunks_failed_checksum": parsed.chunks_failed_checksum,
        "header": parsed.header, "event_id_counts": dict(Counter(e.event_id for e in parsed.events).most_common()),
        "channels": sorted({e.channel for e in parsed.events}), "computers": sorted({e.computer for e in parsed.events}),
        "first_event": min(times).isoformat() if times else None, "last_event": max(times).isoformat() if times else None,
        "rule_matches": len(matches),
    }
    _finish(run, "complete" if not parsed.errors else "partial", summary, parsed.errors)
    return {"evtx": {k: summary[k] for k in ("records_parsed", "errors", "rule_matches")}}


def _analyze_browser(db, settings, evidence, path, findings) -> dict:
    run = _start_run(db, evidence, "browser", browser_mod.ENGINE_VERSION)
    parsed = browser_mod.parse_chromium_history(path, settings.work_dir)
    rows = []
    for v in parsed.visits:
        rows.append(BrowserArtifact(
            evidence_id=evidence.id, analysis_run_id=run.id, kind="visit", url=v["url"], title=v["title"],
            timestamp_utc=v["timestamp_utc"], original_timestamp=v["original_timestamp"], visit_count=v["visit_count"],
            referrer=v["referrer"], extra={"transition": v["transition"], "typed_count": v["typed_count"], "visit_id": v["visit_id"]},
        ))
    for d in parsed.downloads:
        rows.append(BrowserArtifact(
            evidence_id=evidence.id, analysis_run_id=run.id, kind="download", url=d["url"], title="",
            timestamp_utc=d["timestamp_utc"], original_timestamp=d["original_timestamp"], target_path=d["target_path"],
            referrer=d["referrer"], total_bytes=d["total_bytes"],
            extra=_json_safe({k: d[k] for k in ("download_id", "guid", "url_chain", "end_time_utc", "received_bytes",
                                                 "state", "danger_type", "opened", "tab_url", "mime_type", "sha256")}),
        ))
    db.add_all(rows)
    db.flush()
    for row in rows:
        artifact = {"kind": row.kind, "url": row.url, "target_path": row.target_path, "referrer": row.referrer, "extra": row.extra}
        for hit in browser_rules(artifact):
            findings.append(Finding(
                case_id=evidence.case_id, evidence_id=evidence.id, analysis_run_id=run.id, source="browser",
                rule_id=hit["rule_id"], title=hit["title"], classification=hit["classification"],
                severity=hit["severity"], confidence=hit["confidence"], description=hit["description"],
                rationale=hit["rationale"], event_time=row.timestamp_utc,
                source_ref={"analysis_run_id": run.id, "browser_artifact_id": row.id},
            ))
    summary = {"visits": len(parsed.visits), "downloads": len(parsed.downloads), "errors": len(parsed.errors), **parsed.meta}
    _finish(run, "complete" if not parsed.errors else "partial", summary, parsed.errors)
    return {"browser": {"visits": len(parsed.visits), "downloads": len(parsed.downloads), "errors": len(parsed.errors)}}


def _analyze_log(db, evidence, path, findings, rt) -> dict:
    run = _start_run(db, evidence, evidence.artifact_type, logs.ENGINE_VERSION)
    parsed = logs.PARSERS[evidence.artifact_type](path, rt["assumed_timezone"])
    rows = []
    for r in parsed.records:
        rows.append(LogRecord(
            evidence_id=evidence.id, analysis_run_id=run.id, line_number=r["line_number"], record_kind=r["record_kind"],
            timestamp_utc=r["timestamp_utc"], original_timestamp=str(r["original_timestamp"])[:64],
            timezone_assumed=r["timezone_assumed"], fields=_json_safe(r["fields"]), message=r["message"],
        ))
    db.add_all(rows)
    db.flush()
    for row, r in zip(rows, parsed.records):
        for hit in log_rules(r, rt):
            findings.append(Finding(
                case_id=evidence.case_id, evidence_id=evidence.id, analysis_run_id=run.id,
                source="network" if r["record_kind"] in ("network", "dns") else "file" if r["record_kind"] == "file" else "log",
                rule_id=hit["rule_id"], title=hit["title"], classification=hit["classification"],
                severity=hit["severity"], confidence=hit["confidence"], description=hit["description"],
                rationale=hit["rationale"], event_time=row.timestamp_utc,
                source_ref={"analysis_run_id": run.id, "log_record_id": row.id, "line_number": row.line_number},
            ))
    kinds = Counter(r["record_kind"] for r in parsed.records)
    assumed = sum(1 for r in parsed.records if r["timezone_assumed"])
    summary = {"records": len(parsed.records), "errors": len(parsed.errors), "record_kinds": dict(kinds),
               "timezone_assumed_records": assumed, "assumed_timezone": rt["assumed_timezone"], **parsed.meta}
    _finish(run, "complete" if not parsed.errors else "partial", summary, parsed.errors)
    return {"log": {"records": len(parsed.records), "errors": len(parsed.errors)}}
