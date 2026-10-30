"""Detection rules for browser artifacts and normalised log records.

Kept in code (rather than JSON) because they need small amounts of logic, but
each rule is a pure function with a stable ID, a documented rationale, and
unit tests. Thresholds are configurable through the settings API.
"""

from __future__ import annotations

import re
from typing import Any, Callable

from .ioc import ARCHIVE_EXT, EXECUTABLE_EXT
from .netclass import is_external_ip

DOUBLE_EXT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|txt|jpe?g|png|zip|rtf|csv)\.(exe|scr|com|pif|bat|cmd|js|vbs|hta)$", re.I)
USER_WRITABLE = re.compile(r"(?i)\\(users\\[^\\]+\\(downloads|appdata|desktop)|programdata|temp)\\")
DEFAULT_SENSITIVE = ["\\confidential\\", "\\restricted\\", "\\hr\\payroll\\", "\\finance\\board\\"]

RuleDef = dict[str, Any]


def _ext(path: str) -> str:
    name = re.split(r"[\\/]", path or "")[-1]
    return name.rsplit(".", 1)[-1].lower() if "." in name else ""


def _hit(rule_id, title, classification, severity, confidence, description, rationale) -> dict[str, Any]:
    return {"rule_id": rule_id, "title": title, "classification": classification, "severity": severity,
            "confidence": confidence, "description": description, "rationale": rationale}


# ---------------------------------------------------------------- browser

def browser_rules(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    if artifact["kind"] != "download":
        return out
    target = artifact.get("target_path") or ""
    ext = _ext(target)
    danger = (artifact.get("extra") or {}).get("danger_type", "")
    if DOUBLE_EXT.search(target):
        out.append(_hit("BRW-002", "Download of an executable disguised with a double extension", "suspicious", "high", "high",
                        f"Downloaded file '{target}' from {artifact.get('url', '?')}.",
                        "A document-style extension followed by an executable extension is a common lure; legitimate downloads rarely use it."))
    elif ext in EXECUTABLE_EXT:
        out.append(_hit("BRW-001", "Executable file downloaded", "informational", "low", "high",
                        f"Executable '{target}' downloaded from {artifact.get('url', '?')}.",
                        "Executable downloads are routine (installers, updates) but are the usual first stage of user-executed malware."))
    if danger and danger not in ("not_dangerous", "0"):
        out.append(_hit("BRW-003", f"Browser download safety verdict: {danger}", "suspicious", "medium", "medium",
                        f"Chromium recorded danger_type '{danger}' for '{target}'.",
                        "'user_validated' means the browser warned about the file and the user chose to keep it. Other values indicate the browser's own reputation checks flagged it."))
    referrer = artifact.get("referrer") or ""
    if ext in EXECUTABLE_EXT and re.search(r"(?i)(mail|owa|outlook|webmail)", referrer):
        out.append(_hit("BRW-004", "Executable downloaded via a webmail page", "suspicious", "medium", "medium",
                        f"Referrer of the download was {referrer}.",
                        "Executables reached from e-mail are a primary phishing delivery path; shared software links are a benign explanation."))
    return out


# ---------------------------------------------------------------- logs

def log_rules(record: dict[str, Any], settings: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    f = record.get("fields") or {}
    kind = record.get("record_kind")
    threshold = int(settings.get("large_transfer_bytes", 10 * 1024 * 1024))
    sensitive = [s.lower() for s in settings.get("sensitive_path_keywords", DEFAULT_SENSITIVE)]

    if kind == "network":
        dst = str(f.get("dst_ip", ""))
        sent = f.get("bytes_sent") or f.get("bytes_out") or f.get("sent_bytes") or 0
        try:
            sent = int(sent)
        except (TypeError, ValueError):
            sent = 0
        action = str(f.get("action", "")).lower()
        if is_external_ip(dst) and sent >= threshold and action not in ("deny", "drop", "block", "reset"):
            out.append(_hit("NET-001", "Large outbound transfer to an external address", "suspicious", "high", "medium",
                            f"{f.get('src_ip', '?')} sent {sent:,} bytes to {dst}:{f.get('dst_port', '?')} ({action or 'action unknown'}).",
                            f"Outbound volume at or above {threshold:,} bytes in one session can indicate data exfiltration. Backups, uploads to sanctioned cloud services and software updates are benign explanations; the destination must be assessed."))
        if action in ("deny", "drop", "block"):
            out.append(_hit("NET-002", "Connection blocked by firewall policy", "informational", "info", "high",
                            f"Connection to {dst}:{f.get('dst_port', '?')} was {action} by rule '{f.get('rule', '?')}'.",
                            "Shows when containment or blocking took effect."))

    if kind == "file":
        path = str(f.get("file_path", ""))
        etype = str(f.get("event_type", "")).lower()
        ext = _ext(path)
        lower = path.lower()
        if "create" in etype and ext in EXECUTABLE_EXT and USER_WRITABLE.search(path):
            out.append(_hit("FILE-001", "Executable written to a user-writable location", "suspicious", "medium", "medium",
                            f"{f.get('process_name', '?')} created {path}.",
                            "Droppers and downloaded payloads land in Downloads, AppData, ProgramData or Temp; so do many installers."))
        if "create" in etype and ext in ARCHIVE_EXT:
            out.append(_hit("FILE-002", "Archive file created", "suspicious", "low", "medium",
                            f"{f.get('process_name', '?')} created archive {path} ({f.get('size', '?')} bytes).",
                            "Archiving is a common data-staging step before exfiltration; it is also routine user behaviour."))
        if ("read" in etype or "access" in etype) and any(s in lower for s in sensitive):
            out.append(_hit("FILE-003", "Read of a file in a sensitive location", "suspicious", "medium", "medium",
                            f"{f.get('process_path') or f.get('process_name', '?')} read {path}.",
                            "Access to sensitive folders is relevant when the reading process is unexpected for that data."))
        if "delete" in etype and ext in ARCHIVE_EXT:
            out.append(_hit("FILE-004", "Archive deleted", "suspicious", "low", "low",
                            f"{f.get('process_name', '?')} deleted {path}.",
                            "Deleting a staging archive after transfer is a clean-up behaviour; temporary archives are also deleted routinely."))
    return out


RULE_DOCS: list[dict[str, str]] = [
    {"id": "BRW-001", "source": "browser", "title": "Executable file downloaded", "severity": "low"},
    {"id": "BRW-002", "source": "browser", "title": "Download of an executable disguised with a double extension", "severity": "high"},
    {"id": "BRW-003", "source": "browser", "title": "Browser download safety verdict recorded", "severity": "medium"},
    {"id": "BRW-004", "source": "browser", "title": "Executable downloaded via a webmail page", "severity": "medium"},
    {"id": "NET-001", "source": "network", "title": "Large outbound transfer to an external address", "severity": "high"},
    {"id": "NET-002", "source": "network", "title": "Connection blocked by firewall policy", "severity": "info"},
    {"id": "FILE-001", "source": "file", "title": "Executable written to a user-writable location", "severity": "medium"},
    {"id": "FILE-002", "source": "file", "title": "Archive file created", "severity": "low"},
    {"id": "FILE-003", "source": "file", "title": "Read of a file in a sensitive location", "severity": "medium"},
    {"id": "FILE-004", "source": "file", "title": "Archive deleted", "severity": "low"},
]

RuleFn = Callable[[dict[str, Any]], list[dict[str, Any]]]
