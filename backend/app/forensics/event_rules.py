"""Configurable detection rules for parsed Windows events.

Rules are plain JSON (``rules/detections/windows_events.json``) so they can be
reviewed, versioned and extended without code changes. Each match carries the
rule's rationale and the audit-policy prerequisites, making explicit that the
*absence* of a match does not demonstrate the absence of activity.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any

from .evtx_parser import ParsedEvent
from .netclass import is_external_ip

# Short descriptions of event semantics, used for display and timeline summaries.
EVENT_CATALOG: dict[int, str] = {
    104: "Event log cleared",
    1102: "Security audit log cleared",
    4104: "PowerShell script block logged",
    4624: "Account logged on",
    4625: "Account failed to log on",
    4634: "Account logged off",
    4647: "User initiated logoff",
    4648: "Logon attempted with explicit credentials",
    4663: "Attempt to access an object",
    4672: "Special privileges assigned to new logon",
    4688: "New process created",
    4697: "Service installed (Security log)",
    4698: "Scheduled task created",
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempted",
    4728: "Member added to global security group",
    4732: "Member added to local security group",
    4740: "User account locked out",
    5156: "Windows Filtering Platform permitted a connection",
    6005: "Event Log service started",
    6006: "Event Log service stopped",
    7036: "Service changed state",
    7045: "New service installed",
}

LOGON_TYPES = {"2": "Interactive", "3": "Network", "4": "Batch", "5": "Service", "7": "Unlock",
               "8": "NetworkCleartext", "9": "NewCredentials", "10": "RemoteInteractive", "11": "CachedInteractive"}


@dataclass
class RuleMatch:
    rule: dict[str, Any]
    events: list[ParsedEvent]
    detail: dict[str, Any]


class RuleConfigError(ValueError):
    pass


VALID_OPS = {"equals", "contains", "regex", "in", "startswith", "external_ip"}


def load_event_rules(path: Path) -> list[dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    rules = doc.get("rules", [])
    ids = set()
    for rule in rules:
        for key in ("id", "title", "event_ids", "severity", "classification", "confidence", "description", "rationale"):
            if key not in rule:
                raise RuleConfigError(f"rule {rule.get('id', '?')} missing '{key}'")
        if rule["id"] in ids:
            raise RuleConfigError(f"duplicate rule id {rule['id']}")
        ids.add(rule["id"])
        for cond in rule.get("conditions", []):
            if cond.get("op") not in VALID_OPS:
                raise RuleConfigError(f"rule {rule['id']}: unsupported op {cond.get('op')}")
            if cond["op"] == "regex":
                cond["_compiled"] = re.compile(cond["value"])
    return rules


def _condition_holds(cond: dict[str, Any], event: ParsedEvent) -> bool:
    value = str(event.data.get(cond["field"], ""))
    op = cond["op"]
    if op == "equals":
        return value.lower() == str(cond["value"]).lower()
    if op == "contains":
        return str(cond["value"]).lower() in value.lower()
    if op == "startswith":
        return value.lower().startswith(str(cond["value"]).lower())
    if op == "in":
        return value.lower() in {str(v).lower() for v in cond["value"]}
    if op == "regex":
        return bool(cond["_compiled"].search(value))
    if op == "external_ip":
        return is_external_ip(value)
    return False


def event_matches(rule: dict[str, Any], event: ParsedEvent) -> bool:
    if event.event_id not in rule["event_ids"]:
        return False
    if "channel" in rule and event.channel.lower() != rule["channel"].lower():
        return False
    if "providers" in rule and event.provider not in rule["providers"]:
        return False
    return all(_condition_holds(c, event) for c in rule.get("conditions", []))


_ENC_ARG = re.compile(r"(?i)\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc\w*|encodedcommand)\s+([A-Za-z0-9+/=]{8,})")


def decode_powershell_command(command_line: str) -> str | None:
    """Decode a PowerShell -EncodedCommand argument (Base64 of UTF-16LE). Returns None if absent/invalid."""
    m = _ENC_ARG.search(command_line or "")
    if not m:
        return None
    try:
        raw = base64.b64decode(m.group(1), validate=True)
        return raw.decode("utf-16-le")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None


def evaluate_rules(rules: list[dict[str, Any]], events: list[ParsedEvent]) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    ordered = sorted(events, key=lambda e: e.timestamp_utc)
    for rule in rules:
        hits = [e for e in ordered if event_matches(rule, e)]
        if not hits:
            continue
        agg = rule.get("aggregation")
        if agg:
            groups: dict[tuple, list[ParsedEvent]] = {}
            for e in hits:
                key = tuple(str(e.data.get(f, "")) for f in agg["group_by"])
                groups.setdefault(key, []).append(e)
            window = timedelta(seconds=agg["window_seconds"])
            for key, group in groups.items():
                # sliding window: report the first window that reaches the threshold
                for i in range(len(group)):
                    j = i
                    while j + 1 < len(group) and group[j + 1].timestamp_utc - group[i].timestamp_utc <= window:
                        j += 1
                    if j - i + 1 >= agg["threshold"]:
                        matches.append(RuleMatch(rule, group[i : j + 1], {
                            "group": dict(zip(agg["group_by"], key)), "count": j - i + 1,
                            "window_seconds": agg["window_seconds"],
                        }))
                        break
        else:
            for e in hits:
                detail: dict[str, Any] = {}
                if rule.get("decode_powershell"):
                    decoded = decode_powershell_command(str(e.data.get("CommandLine", "")))
                    if decoded is not None:
                        detail["decoded_command"] = decoded
                matches.append(RuleMatch(rule, [e], detail))
    return matches


def describe_event(event: ParsedEvent) -> str:
    """One-line human readable summary used in tables and the timeline."""
    d = event.data
    eid = event.event_id
    base = EVENT_CATALOG.get(eid, f"Event {eid}")
    if eid == 4688:
        return f"Process created: {d.get('NewProcessName', '?')} (parent {d.get('ParentProcessName', '?')}, user {d.get('SubjectUserName', '?')})"
    if eid == 4624:
        lt = d.get("LogonType", "")
        return f"Logon: {d.get('TargetDomainName', '')}\\{d.get('TargetUserName', '?')} type {lt} ({LOGON_TYPES.get(lt, 'unknown')}) from {d.get('IpAddress', '-')}"
    if eid == 4625:
        return f"Failed logon for {d.get('TargetUserName', '?')} from {d.get('IpAddress', '-')} ({d.get('WorkstationName', '-')}), status {d.get('Status', '?')}"
    if eid == 4663:
        return f"Object access: {d.get('ObjectName', '?')} by {d.get('ProcessName', '?')}"
    if eid == 4698:
        return f"Scheduled task created: {d.get('TaskName', '?')} by {d.get('SubjectUserName', '?')}"
    if eid == 4720:
        return f"User account created: {d.get('TargetUserName', '?')} by {d.get('SubjectUserName', '?')}"
    if eid == 4732:
        return f"Member {d.get('MemberSid', '?')} added to group {d.get('TargetUserName', '?')} by {d.get('SubjectUserName', '?')}"
    if eid == 5156:
        return f"Connection permitted: {d.get('Application', '?')} -> {d.get('DestAddress', '?')}:{d.get('DestPort', '?')}"
    if eid == 7045:
        return f"Service installed: {d.get('ServiceName', '?')} -> {d.get('ImagePath', '?')} ({d.get('StartType', '')}, {d.get('AccountName', '')})"
    if eid == 7036:
        return f"Service '{d.get('param1', '?')}' entered the {d.get('param2', '?')} state"
    if eid == 104:
        return f"Event log '{d.get('Channel', '?')}' cleared by {d.get('SubjectDomainName', '')}\\{d.get('SubjectUserName', '?')}"
    if eid == 1102:
        return f"Security log cleared by {d.get('SubjectUserName', '?')}"
    if eid == 4104:
        text = str(d.get("ScriptBlockText", "")).replace("\n", " ")
        return f"PowerShell script block: {text[:160]}{'…' if len(text) > 160 else ''}"
    if eid == 4647:
        return f"User {d.get('TargetUserName', '?')} initiated logoff"
    return base
