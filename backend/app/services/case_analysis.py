"""Case-level reconstruction: timeline, correlation and IOC inventory.

All three are *derived* data. They are rebuilt deterministically from the
parsed records and findings stored for the case, so re-running the rebuild
on unchanged evidence yields the same output.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..config import Settings
from ..forensics.correlation import Correlator, load_correlation_rules
from ..forensics.event_rules import decode_powershell_command
from ..forensics.ioc import (
    Indicator, extract_from_text, make_domain, make_filename, make_hash, make_ip, make_process, make_url,
)
from ..forensics.ledger import append_record
from ..forensics.netclass import classify_ip, is_external_ip
from ..models import (
    IOC, AnalysisRun, BrowserArtifact, Case, Correlation, Evidence, Finding, LogRecord, TimelineEvent,
    WatchlistEntry, WindowsEvent,
)
from . import runtime_settings

SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
EVENT_TYPES = {
    4624: "auth_logon", 4625: "auth_failure", 4634: "auth_logoff", 4647: "auth_logoff", 4688: "process_creation",
    4104: "powershell_script", 4698: "persistence_task", 7045: "persistence_service", 4697: "persistence_service",
    4720: "account_created", 4732: "group_membership_change", 4728: "group_membership_change", 104: "log_cleared",
    1102: "log_cleared", 4663: "file_access", 5156: "network_connection", 7036: "service_state", 6005: "system",
    6006: "system",
}
FILE_EVENT_TYPES = {"file_create": "file_create", "file_read": "file_access", "file_access": "file_access",
                    "file_delete": "file_delete", "file_write": "file_modify", "file_modify": "file_modify",
                    "file_rename": "file_modify"}
_DEVICE = re.compile(r"^\\device\\harddiskvolume\d+", re.I)


def short_host(name: str | None) -> str:
    if not name:
        return ""
    return str(name).split(".")[0].strip().upper()


def _norm_path(path: str | None) -> str:
    if not path:
        return ""
    p = str(path).strip().strip('"').lower()
    return _DEVICE.sub("c:", p)


def _basename(path: str) -> str:
    return re.split(r"[\\/]", path)[-1] if path else ""


def _int(value: Any, base: int = 10) -> int | None:
    try:
        text = str(value).strip()
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, base)
    except (TypeError, ValueError):
        return None


def _image_from_command(command: str) -> str:
    command = (command or "").strip()
    if command.startswith('"'):
        return _norm_path(command[1:].split('"', 1)[0])
    m = re.match(r"(?i)^(.+?\.(?:exe|com|scr|bat|cmd))\b", command)
    return _norm_path(m.group(1) if m else command.split(" ")[0])


def _sensitive(path: str, keywords: list[str]) -> bool:
    lower = (path or "").lower()
    return any(k.lower() in lower for k in keywords)


# --------------------------------------------------------------------- timeline

def _findings_index(db: Session, case_id: int) -> dict[tuple[str, int], list[Finding]]:
    index: dict[tuple[str, int], list[Finding]] = defaultdict(list)
    for f in db.execute(select(Finding).where(Finding.case_id == case_id)).scalars():
        ref = f.source_ref or {}
        for wid in ref.get("windows_event_ids", []):
            index[("windows_events", wid)].append(f)
        if "browser_artifact_id" in ref:
            index[("browser_artifacts", ref["browser_artifact_id"])].append(f)
        if "log_record_id" in ref:
            index[("log_records", ref["log_record_id"])].append(f)
    return index


def _severity(findings: list[Finding]) -> str:
    relevant = [f for f in findings if f.classification in ("suspicious", "confirmed_rule_match")]
    if not relevant:
        return "info"
    return max((f.severity for f in relevant), key=lambda s: SEV_RANK.get(s, 0))


def _windows_entities(ev: WindowsEvent, keywords: list[str]) -> tuple[str, dict[str, Any], list[str]]:
    d = ev.data or {}
    eid = ev.event_id
    ent: dict[str, Any] = {"event_id": eid, "record_number": ev.record_number, "channel": ev.channel}
    tags: list[str] = []
    if eid == 4688:
        image = _norm_path(d.get("NewProcessName"))
        ent.update(pid=_int(d.get("NewProcessId")), parent_pid=_int(d.get("ProcessId")), process_image=image,
                   parent_image=_norm_path(d.get("ParentProcessName")), file_name=_basename(image),
                   user=d.get("SubjectUserName"), command_line=d.get("CommandLine", ""))
        decoded = decode_powershell_command(d.get("CommandLine", ""))
        if decoded:
            ent["decoded_command"] = decoded
    elif eid == 4663:
        path = _norm_path(d.get("ObjectName"))
        ent.update(pid=_int(d.get("ProcessId")), process_image=_norm_path(d.get("ProcessName")), file_path=path,
                   file_name=_basename(path), user=d.get("SubjectUserName"))
        if _sensitive(path, keywords):
            tags.append("sensitive_path")
    elif eid == 5156:
        dst = str(d.get("DestAddress", ""))
        ent.update(pid=_int(d.get("ProcessID")), process_image=_norm_path(d.get("Application")), dst_ip=dst,
                   dst_port=_int(d.get("DestPort")), dst_external=is_external_ip(dst), src_ip=d.get("SourceAddress"))
    elif eid == 4698:
        m = re.search(r"<Command>(.*?)</Command>", d.get("TaskContent", ""), re.S)
        ent.update(task_name=d.get("TaskName"), target_image=_norm_path(m.group(1)) if m else "", user=d.get("SubjectUserName"))
    elif eid in (7045, 4697):
        ent.update(service_name=d.get("ServiceName"), target_image=_image_from_command(d.get("ImagePath", "")),
                   account=d.get("AccountName"))
    elif eid == 4104:
        ent.update(pid=_int(d.get("_ExecutionProcessID")), script=d.get("ScriptBlockText", "")[:2000])
    elif eid in (4624, 4625):
        ent.update(user=d.get("TargetUserName"), src_ip=d.get("IpAddress"), logon_type=d.get("LogonType"),
                   workstation=d.get("WorkstationName"))
    elif eid in (4720, 4732):
        ent.update(user=d.get("SubjectUserName"), target_account=d.get("TargetUserName"), member_sid=d.get("MemberSid"))
    elif eid in (104, 1102):
        ent.update(user=d.get("SubjectUserName"), cleared_channel=d.get("Channel", ev.channel))
    return EVENT_TYPES.get(eid, "windows_event"), {k: v for k, v in ent.items() if v not in (None, "")}, tags


def build_timeline(db: Session, case: Case) -> int:
    rt = runtime_settings.get_all(db)
    keywords = rt["sensitive_path_keywords"]
    db.execute(delete(TimelineEvent).where(TimelineEvent.case_id == case.id))
    evidence = {e.id: e for e in db.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars()}
    if not evidence:
        db.flush()
        return 0
    idx = _findings_index(db, case.id)
    events: list[TimelineEvent] = []
    ev_ids = list(evidence)

    for ev in db.execute(select(WindowsEvent).where(WindowsEvent.evidence_id.in_(ev_ids))).scalars():
        etype, ent, tags = _windows_entities(ev, keywords)
        fnd = idx.get(("windows_events", ev.id), [])
        events.append(TimelineEvent(
            case_id=case.id, evidence_id=ev.evidence_id, timestamp_utc=ev.timestamp_utc,
            original_timestamp=ev.original_timestamp, timezone_assumed=False, source_type="windows_evtx",
            event_type=etype, summary=f"[{ev.event_id}] {ev.description}", severity=_severity(fnd),
            confidence="high", host=short_host(ev.computer), entities=ent,
            source_ref={"table": "windows_events", "id": ev.id, "record_number": ev.record_number, "channel": ev.channel},
            tags=sorted(set(tags) | {f.rule_id for f in fnd}),
        ))

    for ba in db.execute(select(BrowserArtifact).where(BrowserArtifact.evidence_id.in_(ev_ids))).scalars():
        if ba.timestamp_utc is None:
            continue
        host = short_host(evidence[ba.evidence_id].source_host)
        fnd = idx.get(("browser_artifacts", ba.id), [])
        url_res = make_url(ba.url)
        domain = url_res[1].normalized if url_res and url_res[1] else ""
        if ba.kind == "download":
            path = _norm_path(ba.target_path)
            ent = {"url": ba.url, "domain": domain, "file_path": path, "file_name": _basename(path),
                   "sha256": (ba.extra or {}).get("sha256"), "referrer": ba.referrer, "bytes": ba.total_bytes}
            summary = f"Download: {ba.target_path} from {ba.url} ({ba.total_bytes or 0:,} bytes, {(ba.extra or {}).get('danger_type', 'n/a')})"
            etype = "file_download"
        else:
            ent = {"url": ba.url, "domain": domain, "title": ba.title}
            summary = f"Visited {ba.url}" + (f" – “{ba.title}”" if ba.title else "")
            etype = "web_visit"
        events.append(TimelineEvent(
            case_id=case.id, evidence_id=ba.evidence_id, timestamp_utc=ba.timestamp_utc,
            original_timestamp=ba.original_timestamp, source_type="browser_history", event_type=etype,
            summary=summary[:1000], severity=_severity(fnd), confidence="high", host=host,
            entities={k: v for k, v in ent.items() if v not in (None, "")},
            source_ref={"table": "browser_artifacts", "id": ba.id}, tags=sorted({f.rule_id for f in fnd}),
        ))

    for lr in db.execute(select(LogRecord).where(LogRecord.evidence_id.in_(ev_ids))).scalars():
        if lr.timestamp_utc is None:
            continue
        f = lr.fields or {}
        src = evidence[lr.evidence_id]
        host = short_host(f.get("src_host") or f.get("host") or f.get("hostname") or src.source_host)
        fnd = idx.get(("log_records", lr.id), [])
        tags = {x.rule_id for x in fnd}
        if lr.record_kind == "network":
            dst = str(f.get("dst_ip", ""))
            sent = _int(f.get("bytes_sent") or f.get("bytes_out") or 0) or 0
            ent = {"dst_ip": dst, "dst_port": _int(f.get("dst_port")), "dst_external": is_external_ip(dst),
                   "bytes_sent": sent, "bytes_received": _int(f.get("bytes_received")), "src_ip": f.get("src_ip"),
                   "action": f.get("action")}
            summary = f"{str(f.get('action', 'connection')).upper()} {f.get('src_ip', '?')} -> {dst}:{f.get('dst_port', '?')} sent {sent:,} B / received {_int(f.get('bytes_received')) or 0:,} B"
            etype = "network_connection"
        elif lr.record_kind == "dns":
            dom = make_domain(str(f.get("query", "")))
            ent = {"domain": dom.normalized if dom else f.get("query"), "answer": f.get("answer"), "src_ip": f.get("src_ip"),
                   "dst_ip": f.get("answer") if f.get("answer") and classify_ip(str(f.get("answer"))) else None}
            summary = f"DNS {f.get('qtype', '')} query {f.get('query')} -> {f.get('answer', '-')} ({f.get('rcode', '')})"
            etype = "dns_query"
        elif lr.record_kind == "file":
            path = _norm_path(f.get("file_path"))
            raw_type = str(f.get("event_type", "")).lower()
            etype = FILE_EVENT_TYPES.get(raw_type, "file_activity")
            ent = {"file_path": path, "file_name": _basename(path), "sha256": (str(f.get("sha256")).lower() if f.get("sha256") else None),
                   "process_image": _norm_path(f.get("process_path")), "user": f.get("user"), "size": f.get("size")}
            if _sensitive(path, keywords):
                tags.add("sensitive_path")
            summary = f"{raw_type or 'file event'}: {f.get('file_path')} by {f.get('process_name', '?')}"
        else:
            ent, etype, summary = {}, "log_entry", lr.message[:300]
        events.append(TimelineEvent(
            case_id=case.id, evidence_id=lr.evidence_id, timestamp_utc=lr.timestamp_utc,
            original_timestamp=lr.original_timestamp, timezone_assumed=lr.timezone_assumed,
            source_type=src.artifact_type, event_type=etype, summary=summary[:1000], severity=_severity(fnd),
            confidence="medium" if lr.timezone_assumed else "high", host=host,
            entities={k: v for k, v in ent.items() if v not in (None, "")},
            source_ref={"table": "log_records", "id": lr.id, "line_number": lr.line_number}, tags=sorted(tags),
        ))

    events.sort(key=lambda e: (e.timestamp_utc, e.source_type, e.summary))
    db.add_all(events)
    db.flush()
    return len(events)


# --------------------------------------------------------------------- correlation

def _pe_indicator_map(db: Session, case: Case) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    rows = db.execute(
        select(AnalysisRun, Evidence).join(Evidence, Evidence.id == AnalysisRun.evidence_id)
        .where(Evidence.case_id == case.id, AnalysisRun.analyzer == "pe", AnalysisRun.is_current.is_(True))
    ).all()
    for run, ev in rows:
        values: set[str] = set()
        for s in (run.summary or {}).get("strings", {}).get("interesting", []):
            for ind in extract_from_text(s.get("value", "")):
                if ind.ioc_type in ("ipv4", "domain"):
                    values.add(ind.normalized)
        out[ev.original_filename.lower()] = values
        out[ev.sha256] = values
    return out


def run_correlation(db: Session, settings: Settings, case: Case) -> int:
    rt = runtime_settings.get_all(db)
    db.execute(delete(Correlation).where(Correlation.case_id == case.id))
    events = list(db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case.id)).scalars())
    rules = load_correlation_rules(settings.rules_dir / "detections" / "correlation.json")
    correlator = Correlator(events, _pe_indicator_map(db, case), rt["correlation_window_minutes"])
    results = correlator.run(rules)
    for r in results:
        db.add(Correlation(
            case_id=case.id, rule_id=r.rule["id"], title=r.rule["title"], description=r.rule["description"],
            severity=r.rule["severity"], confidence=r.confidence, classification="hypothesis",
            start_time=r.steps[0].event.timestamp_utc, end_time=r.steps[-1].event.timestamp_utc,
            steps=[{
                "name": m.step["name"], "description": m.step.get("description", ""),
                "timeline_event_id": m.event.id, "timestamp_utc": m.event.timestamp_utc.isoformat(),
                "summary": m.event.summary, "source_type": m.event.source_type, "evidence_id": m.event.evidence_id,
                "link_strength": m.strength, "links": m.links, "gap_seconds": m.gap_seconds,
            } for m in r.steps],
            explanation=r.explanation, caveats=r.caveats,
        ))
    db.flush()
    return len(results)


# --------------------------------------------------------------------- IOCs

class _IocCollector:
    def __init__(self):
        self.items: dict[tuple[str, str], dict[str, Any]] = {}

    def add(self, ind: Indicator | None, *, evidence: Evidence, source: str, field: str, context: str,
            when: datetime | None, ref: dict[str, Any]) -> None:
        if ind is None:
            return
        key = (ind.ioc_type, ind.normalized)
        item = self.items.setdefault(key, {"ind": ind, "occurrences": [], "first": None, "last": None, "count": 0})
        item["count"] += 1
        if when:
            item["first"] = min(filter(None, [item["first"], when]))
            item["last"] = max(filter(None, [item["last"], when]))
        if len(item["occurrences"]) < 50:
            item["occurrences"].append({
                "evidence_id": evidence.id, "evidence_name": evidence.original_filename, "source": source,
                "field": field, "context": context[:300], "timestamp_utc": when.isoformat() if when else None, "ref": ref,
            })


def _interesting_filename(path: str) -> Indicator | None:
    ind = make_filename(path)
    if ind is None:
        return None
    if ind.classification in ("double_extension_executable", "archive"):
        return ind
    if re.search(r"(?i)\\(users\\[^\\]+\\(downloads|appdata|desktop)|programdata|temp)\\", path or ""):
        return ind
    return None


def build_iocs(db: Session, case: Case) -> int:
    rt = runtime_settings.get_all(db)
    db.execute(delete(IOC).where(IOC.case_id == case.id))
    db.execute(delete(Finding).where(Finding.case_id == case.id, Finding.source == "ioc"))
    evidence = {e.id: e for e in db.execute(select(Evidence).where(Evidence.case_id == case.id)).scalars()}
    col = _IocCollector()
    ev_ids = list(evidence)

    for run in db.execute(select(AnalysisRun).where(AnalysisRun.evidence_id.in_(ev_ids), AnalysisRun.is_current.is_(True),
                                                    AnalysisRun.analyzer == "pe")).scalars():
        ev = evidence[run.evidence_id]
        ref = {"table": "analysis_runs", "id": run.id}
        col.add(make_hash(ev.sha256), evidence=ev, source="pe_analysis", field="sha256", context=f"SHA-256 of acquired sample {ev.original_filename}", when=None, ref=ref)
        col.add(make_hash(ev.md5), evidence=ev, source="pe_analysis", field="md5", context=f"MD5 of acquired sample {ev.original_filename}", when=None, ref=ref)
        col.add(_interesting_filename(ev.original_filename) or make_filename(ev.original_filename), evidence=ev,
                source="pe_analysis", field="original_filename", context="Acquired sample filename", when=None, ref=ref)
        for s in (run.summary or {}).get("strings", {}).get("interesting", []):
            for ind in extract_from_text(s.get("value", "")):
                if ind.ioc_type in ("url", "domain", "ipv4"):
                    col.add(ind, evidence=ev, source="pe_strings", field=f"string@{s.get('offset')}", context=s.get("value", ""), when=None, ref=ref)

    for we in db.execute(select(WindowsEvent).where(WindowsEvent.evidence_id.in_(ev_ids))).scalars():
        ev = evidence[we.evidence_id]
        d = we.data or {}
        ref = {"table": "windows_events", "id": we.id, "record_number": we.record_number}
        ctx = f"[{we.event_id}] {we.description}"
        for fld in ("IpAddress", "DestAddress", "SourceAddress"):
            val = str(d.get(fld, ""))
            if val and val not in ("-", "::1"):
                col.add(make_ip(val), evidence=ev, source="windows_evtx", field=fld, context=ctx, when=we.timestamp_utc, ref=ref)
        for fld in ("NewProcessName", "ParentProcessName", "ProcessName", "Application"):
            if d.get(fld):
                path = _norm_path(d[fld])
                col.add(make_process(path), evidence=ev, source="windows_evtx", field=fld, context=ctx, when=we.timestamp_utc, ref=ref)
                col.add(_interesting_filename(path), evidence=ev, source="windows_evtx", field=fld, context=ctx, when=we.timestamp_utc, ref=ref)
        for fld in ("ObjectName", "ImagePath"):
            if d.get(fld):
                col.add(_interesting_filename(_image_from_command(d[fld]) if fld == "ImagePath" else _norm_path(d[fld])),
                        evidence=ev, source="windows_evtx", field=fld, context=ctx, when=we.timestamp_utc, ref=ref)
        texts = [d.get("ScriptBlockText", ""), d.get("TaskContent", "")]
        decoded = decode_powershell_command(d.get("CommandLine", ""))
        if decoded:
            texts.append(decoded)
        for text in texts:
            for ind in extract_from_text(text or ""):
                col.add(ind, evidence=ev, source="windows_evtx", field="script/command", context=(text or "")[:300], when=we.timestamp_utc, ref=ref)
            for m in re.finditer(r"(?i)[a-z]:\\[^\s\"';|]+\.(?:zip|7z|rar|exe)", text or ""):
                col.add(_interesting_filename(_norm_path(m.group())), evidence=ev, source="windows_evtx", field="script/command",
                        context=(text or "")[:300], when=we.timestamp_utc, ref=ref)

    for ba in db.execute(select(BrowserArtifact).where(BrowserArtifact.evidence_id.in_(ev_ids))).scalars():
        ev = evidence[ba.evidence_id]
        ref = {"table": "browser_artifacts", "id": ba.id}
        res = make_url(ba.url)
        if res:
            col.add(res[0], evidence=ev, source="browser_history", field=f"{ba.kind}.url", context=ba.title or ba.url, when=ba.timestamp_utc, ref=ref)
            col.add(res[1], evidence=ev, source="browser_history", field=f"{ba.kind}.host", context=ba.url, when=ba.timestamp_utc, ref=ref)
        if ba.kind == "download":
            col.add(_interesting_filename(ba.target_path) or make_filename(ba.target_path), evidence=ev, source="browser_history",
                    field="download.target_path", context=ba.target_path, when=ba.timestamp_utc, ref=ref)
            col.add(make_hash((ba.extra or {}).get("sha256") or ""), evidence=ev, source="browser_history",
                    field="download.hash", context=f"hash recorded by browser for {ba.target_path}", when=ba.timestamp_utc, ref=ref)

    for lr in db.execute(select(LogRecord).where(LogRecord.evidence_id.in_(ev_ids))).scalars():
        ev = evidence[lr.evidence_id]
        f = lr.fields or {}
        ref = {"table": "log_records", "id": lr.id, "line_number": lr.line_number}
        ctx = lr.message[:300]
        for fld in ("dst_ip", "src_ip", "answer"):
            if f.get(fld):
                col.add(make_ip(str(f[fld])), evidence=ev, source=ev.artifact_type, field=fld, context=ctx, when=lr.timestamp_utc, ref=ref)
        if f.get("query"):
            col.add(make_domain(str(f["query"])), evidence=ev, source=ev.artifact_type, field="query", context=ctx, when=lr.timestamp_utc, ref=ref)
        if f.get("sha256"):
            col.add(make_hash(str(f["sha256"])), evidence=ev, source=ev.artifact_type, field="sha256", context=ctx, when=lr.timestamp_utc, ref=ref)
        if f.get("file_path"):
            col.add(_interesting_filename(_norm_path(str(f["file_path"]))), evidence=ev, source=ev.artifact_type, field="file_path", context=ctx, when=lr.timestamp_utc, ref=ref)
        if f.get("process_path"):
            col.add(make_process(_norm_path(str(f["process_path"]))), evidence=ev, source=ev.artifact_type, field="process_path", context=ctx, when=lr.timestamp_utc, ref=ref)
        zone = f.get("zone_identifier")
        if isinstance(zone, dict):
            for k in ("HostUrl", "ReferrerUrl"):
                if zone.get(k):
                    res = make_url(zone[k])
                    if res:
                        col.add(res[0], evidence=ev, source=ev.artifact_type, field=f"zone_identifier.{k}", context=ctx, when=lr.timestamp_utc, ref=ref)

    # ---- assessment -------------------------------------------------------
    watch = list(db.execute(select(WatchlistEntry)).scalars())
    referencing = []  # (object, lowercase text) for findings of medium+ severity and correlations
    for f in db.execute(select(Finding).where(Finding.case_id == case.id,
                                              Finding.classification.in_(["suspicious", "confirmed_rule_match"]))).scalars():
        if SEV_RANK.get(f.severity, 0) >= SEV_RANK["medium"]:
            referencing.append((f, (f.title + " " + f.description + " " + json.dumps(f.source_ref, default=str)).lower()))
    for c in db.execute(select(Correlation).where(Correlation.case_id == case.id)).scalars():
        referencing.append((c, (c.title + " " + c.explanation).lower()))
    # A process is suspicious only when a process-creation event *for that image* was itself flagged.
    flagged_images: dict[str, TimelineEvent] = {}
    for te in db.execute(select(TimelineEvent).where(TimelineEvent.case_id == case.id,
                                                     TimelineEvent.event_type == "process_creation")).scalars():
        if SEV_RANK.get(te.severity, 0) >= SEV_RANK["medium"]:
            name = str((te.entities or {}).get("file_name", "")).lower()
            flagged_images.setdefault(name, te)
    internal = [d.lower() for d in rt["internal_domains"]]

    count = 0
    for (ioc_type, norm), item in sorted(col.items.items()):
        ind: Indicator = item["ind"]
        assessment, reason = "observed", "Observed in evidence; no watchlist entry or medium+ severity finding references it."
        wl = _watch_match(ind, watch)
        host = _host_of(ind)
        is_internal_name = bool(host) and any(host == d or host.endswith("." + d) for d in internal)
        if wl:
            assessment = "watchlist_match"
            reason = f"Matches local watchlist entry '{wl.indicator}' ({wl.source}, confidence {wl.confidence}): {wl.description}"
        elif is_internal_name:
            assessment = "benign_context"
            reason = "Organisation-owned domain (configured internal domain); recorded for context."
        elif ioc_type == "process":
            te = flagged_images.get(norm)
            if te is not None:
                assessment = "suspicious"
                reason = f"Process creation of this image was flagged ({', '.join(te.tags) or te.severity}) at {te.timestamp_utc.isoformat()}."
        else:
            needle = re.compile(r"(?<![\w.])" + re.escape(norm) + r"(?![\w])")
            ref = next((obj for obj, text in referencing if needle.search(text)), None)
            if ref is not None:
                assessment = "suspicious"
                kind = "correlation" if isinstance(ref, Correlation) else "finding"
                reason = f"Referenced by {kind} '{ref.title}' ({ref.rule_id})."
            elif ind.classification in ("private", "loopback", "link_local"):
                assessment = "benign_context"
                reason = "Internal address; recorded for context."
        db.add(IOC(case_id=case.id, ioc_type=ioc_type, value=ind.value[:2000], normalized=norm[:512],
                   classification=ind.classification, assessment=assessment, assessment_reason=reason,
                   first_seen=item["first"], last_seen=item["last"],
                   occurrences=item["occurrences"] + ([{"truncated": item["count"] - 50}] if item["count"] > 50 else [])))
        if wl:
            first_occ = item["occurrences"][0]
            db.add(Finding(
                case_id=case.id, evidence_id=first_occ["evidence_id"], source="ioc", rule_id="IOC-WATCHLIST",
                title=f"Indicator matches local watchlist: {norm}", classification="confirmed_rule_match",
                severity={"high": "high", "medium": "medium"}.get(wl.confidence, "low"), confidence=wl.confidence,
                description=f"{ioc_type} {norm} observed {item['count']} time(s); first occurrence in {first_occ['evidence_name']} ({first_occ['field']}).",
                rationale="The watchlist is analyst-curated reference data (synthetic in the demonstration dataset). A match confirms the "
                          "indicator was previously associated with suspicious activity by that source; it does not by itself prove "
                          "malicious activity in this case.",
                event_time=item["first"], source_ref={"ioc": norm, "watchlist_id": wl.id},
            ))
        count += 1
    db.flush()
    return count


def _host_of(ind: Indicator) -> str:
    if ind.ioc_type == "domain":
        return ind.normalized
    if ind.ioc_type == "url":
        res = make_url(ind.normalized)
        return res[1].normalized if res and res[1] else ""
    return ""


def _watch_match(ind: Indicator, watch: list[WatchlistEntry]) -> WatchlistEntry | None:
    host = _host_of(ind)
    for w in watch:
        wv = w.indicator.lower()
        if ind.normalized == wv:
            return w
        if w.ioc_type == "domain" and host and (host == wv or host.endswith("." + wv)):
            return w
        if w.ioc_type == "ipv4" and ind.ioc_type == "url" and host == wv:
            return w
    return None


def rebuild_case(db: Session, settings: Settings, case: Case, actor: str) -> dict[str, int]:
    timeline = build_timeline(db, case)
    correlations = run_correlation(db, settings, case)
    iocs = build_iocs(db, case)
    append_record(db, actor=actor, action="case_reconstructed", case_id=case.id,
                  details={"timeline_events": timeline, "correlations": correlations, "iocs": iocs}, commit=False)
    db.commit()
    return {"timeline_events": timeline, "correlations": correlations, "iocs": iocs}
