"""Model -> JSON-safe dict conversion for API responses."""

from __future__ import annotations

import json
from typing import Any

from ..forensics.timeutil import iso
from ..models import (
    IOC, AnalysisRun, AuditRecord, BrowserArtifact, Case, Correlation, Evidence, Finding, IntegrityCheck, Report,
    TimelineEvent, User, WindowsEvent,
)


def user(u: User) -> dict[str, Any]:
    return {"id": u.id, "username": u.username, "display_name": u.display_name, "role": u.role,
            "is_active": u.is_active, "created_at": iso(u.created_at), "last_login_at": iso(u.last_login_at)}


def case(c: Case, counts: dict[str, Any] | None = None) -> dict[str, Any]:
    d = {"id": c.id, "case_number": c.case_number, "title": c.title, "organization": c.organization,
         "description": c.description, "status": c.status, "priority": c.priority, "is_synthetic": c.is_synthetic,
         "lead_investigator": c.lead_investigator.display_name if c.lead_investigator else None,
         "conclusions": c.conclusions, "created_at": iso(c.created_at), "updated_at": iso(c.updated_at)}
    if counts is not None:
        d["counts"] = counts
    return d


def evidence(e: Evidence) -> dict[str, Any]:
    return {"id": e.id, "case_id": e.case_id, "original_filename": e.original_filename, "size_bytes": e.size_bytes,
            "sha256": e.sha256, "sha1": e.sha1, "md5": e.md5, "declared_mime": e.declared_mime,
            "detected_type": e.detected_type, "artifact_type": e.artifact_type, "source_description": e.source_description,
            "source_host": e.source_host, "acquired_at": iso(e.acquired_at),
            "acquired_by": e.acquired_by.username if e.acquired_by else None, "duplicate_of": e.duplicate_of,
            "analysis_status": e.analysis_status, "integrity_status": e.integrity_status,
            "last_verified_at": iso(e.last_verified_at)}


def run(r: AnalysisRun, include_summary: bool = True) -> dict[str, Any]:
    d = {"id": r.id, "evidence_id": r.evidence_id, "analyzer": r.analyzer, "engine_version": r.engine_version,
         "started_at": iso(r.started_at), "finished_at": iso(r.finished_at), "status": r.status,
         "is_current": r.is_current, "input_sha256": r.input_sha256, "error_count": len(r.errors or []),
         "errors": (r.errors or [])[:200]}
    if include_summary:
        d["summary"] = r.summary
    return d


def finding(f: Finding) -> dict[str, Any]:
    return {"id": f.id, "case_id": f.case_id, "evidence_id": f.evidence_id, "source": f.source, "rule_id": f.rule_id,
            "title": f.title, "classification": f.classification, "severity": f.severity, "confidence": f.confidence,
            "description": f.description, "rationale": f.rationale, "event_time": iso(f.event_time),
            "source_ref": f.source_ref}


def windows_event(w: WindowsEvent) -> dict[str, Any]:
    return {"id": w.id, "evidence_id": w.evidence_id, "record_number": w.record_number, "event_id": w.event_id,
            "provider": w.provider, "channel": w.channel, "computer": w.computer, "level": w.level,
            "timestamp_utc": iso(w.timestamp_utc), "original_timestamp": w.original_timestamp, "user_sid": w.user_sid,
            "description": w.description, "data": w.data}


def browser_artifact(b: BrowserArtifact) -> dict[str, Any]:
    return {"id": b.id, "evidence_id": b.evidence_id, "kind": b.kind, "url": b.url, "title": b.title,
            "timestamp_utc": iso(b.timestamp_utc), "original_timestamp": b.original_timestamp,
            "visit_count": b.visit_count, "target_path": b.target_path, "referrer": b.referrer,
            "total_bytes": b.total_bytes, "extra": b.extra}


def timeline_event(t: TimelineEvent) -> dict[str, Any]:
    return {"id": t.id, "evidence_id": t.evidence_id, "timestamp_utc": iso(t.timestamp_utc),
            "original_timestamp": t.original_timestamp, "timezone_assumed": t.timezone_assumed,
            "source_type": t.source_type, "event_type": t.event_type, "summary": t.summary, "severity": t.severity,
            "confidence": t.confidence, "host": t.host, "entities": t.entities, "source_ref": t.source_ref, "tags": t.tags}


def correlation(c: Correlation) -> dict[str, Any]:
    return {"id": c.id, "rule_id": c.rule_id, "title": c.title, "description": c.description, "severity": c.severity,
            "confidence": c.confidence, "classification": c.classification, "start_time": iso(c.start_time),
            "end_time": iso(c.end_time), "steps": c.steps, "explanation": c.explanation, "caveats": c.caveats}


def ioc(i: IOC) -> dict[str, Any]:
    return {"id": i.id, "ioc_type": i.ioc_type, "value": i.value, "normalized": i.normalized,
            "classification": i.classification, "assessment": i.assessment, "assessment_reason": i.assessment_reason,
            "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "occurrences": i.occurrences,
            "occurrence_count": sum(1 for o in i.occurrences if "evidence_id" in o) + sum(o.get("truncated", 0) for o in i.occurrences)}


def audit(r: AuditRecord) -> dict[str, Any]:
    return {"seq": r.seq, "record_id": r.record_id, "timestamp": r.timestamp, "actor": r.actor, "action": r.action,
            "case_id": r.case_id, "evidence_id": r.evidence_id, "details": json.loads(r.details or "{}"),
            "prev_hash": r.prev_hash, "record_hash": r.record_hash}


def integrity_check(c: IntegrityCheck) -> dict[str, Any]:
    return {"id": c.id, "evidence_id": c.evidence_id, "checked_at": iso(c.checked_at), "checked_by": c.checked_by,
            "expected_sha256": c.expected_sha256, "observed_sha256": c.observed_sha256, "result": c.result,
            "trigger": c.trigger}


def report(r: Report) -> dict[str, Any]:
    return {"id": r.id, "case_id": r.case_id, "format": r.report_format, "generated_at": iso(r.generated_at),
            "generated_by": r.generated_by, "size_bytes": r.size_bytes, "sha256": r.sha256,
            "content_sha256": r.content_sha256}
