"""YARA rule management and scanning.

Rules live in ``rules/yara/*.yar``. Each rule must define the meta fields
``id``, ``description``, ``severity`` and ``explanation``; rules that omit them
are rejected at load time so every match can be explained to an analyst.

A YARA match is reported as a *confirmed rule match*: the bytes provably
satisfy the rule's condition. What that means for the investigation depends
on the rule, which is why the rule's own explanation is carried with every
match.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yara

ENGINE_VERSION = f"yara-{yara.__version__ if hasattr(yara, '__version__') else 'unknown'}"
REQUIRED_META = ("id", "description", "severity", "explanation")
SEVERITIES = {"info", "low", "medium", "high", "critical"}
MAX_SCAN_BYTES = 64 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 30


@dataclass
class RuleInfo:
    name: str
    namespace: str
    meta: dict[str, Any]
    tags: list[str]
    source_file: str


@dataclass
class RuleSet:
    compiled: yara.Rules
    rules: list[RuleInfo]
    files: list[str]
    errors: list[str] = field(default_factory=list)


class RuleValidationError(ValueError):
    pass


def _extract_rule_infos(compiled: yara.Rules, source_file: str) -> list[RuleInfo]:
    infos = []
    for rule in compiled:
        infos.append(RuleInfo(rule.identifier, getattr(rule, "namespace", "default"), dict(rule.meta), list(rule.tags), source_file))
    return infos


def validate_rule_source(source: str) -> list[RuleInfo]:
    """Compile a rule source string and check required metadata. Raises RuleValidationError."""
    if len(source) > 256 * 1024:
        raise RuleValidationError("rule source exceeds 256 KiB")
    try:
        compiled = yara.compile(source=source)
    except yara.SyntaxError as exc:
        raise RuleValidationError(f"syntax error: {exc}") from exc
    except yara.Error as exc:
        raise RuleValidationError(f"compilation failed: {exc}") from exc
    infos = _extract_rule_infos(compiled, "<inline>")
    if not infos:
        raise RuleValidationError("no rules defined")
    for info in infos:
        missing = [m for m in REQUIRED_META if m not in info.meta]
        if missing:
            raise RuleValidationError(f"rule {info.name} is missing required meta: {', '.join(missing)}")
        if str(info.meta["severity"]).lower() not in SEVERITIES:
            raise RuleValidationError(f"rule {info.name} has invalid severity '{info.meta['severity']}'")
    return infos


_cache_lock = threading.Lock()
_cache: dict[str, tuple[float, RuleSet]] = {}


def load_rules(rules_dir: Path) -> RuleSet:
    """Compile every .yar file in ``rules_dir`` (cached until a file changes)."""
    files = sorted(p for p in rules_dir.glob("*.yar") if p.is_file())
    stamp = max((p.stat().st_mtime for p in files), default=0.0) + len(files)
    key = str(rules_dir.resolve())
    with _cache_lock:
        cached = _cache.get(key)
        if cached and cached[0] == stamp:
            return cached[1]
        errors: list[str] = []
        sources: dict[str, str] = {}
        infos: list[RuleInfo] = []
        for path in files:
            text = path.read_text(encoding="utf-8")
            try:
                file_infos = validate_rule_source(text)
            except RuleValidationError as exc:
                errors.append(f"{path.name}: {exc}")
                continue
            sources[path.stem] = text
            for info in file_infos:
                info.source_file = path.name
                info.namespace = path.stem
            infos.extend(file_infos)
        compiled = yara.compile(sources=sources) if sources else yara.compile(source="rule tf_empty { condition: false }")
        ruleset = RuleSet(compiled=compiled, rules=infos, files=[p.name for p in files], errors=errors)
        _cache[key] = (stamp, ruleset)
        return ruleset


def scan_file(ruleset: RuleSet, path: Path) -> dict[str, Any]:
    """Scan a file. Only reads bytes; never executes anything."""
    size = path.stat().st_size
    result: dict[str, Any] = {"engine_version": ENGINE_VERSION, "rules_loaded": len(ruleset.rules),
                              "rule_files": ruleset.files, "matches": [], "errors": [], "scanned_bytes": size}
    if size > MAX_SCAN_BYTES:
        result["errors"].append(f"file larger than {MAX_SCAN_BYTES} bytes; YARA scan skipped")
        result["status"] = "skipped"
        return result
    try:
        data = path.read_bytes()
        matches = ruleset.compiled.match(data=data, timeout=SCAN_TIMEOUT_SECONDS)
    except yara.TimeoutError:
        result["errors"].append("YARA scan timed out")
        result["status"] = "timeout"
        return result
    except yara.Error as exc:
        result["errors"].append(f"YARA scan error: {exc}")
        result["status"] = "error"
        return result
    for m in matches:
        strings = []
        for s in m.strings:
            for inst in s.instances[:5]:
                raw = bytes(inst.matched_data[:120])
                strings.append({
                    "identifier": s.identifier,
                    "offset": inst.offset,
                    "data": raw.decode("utf-8", errors="replace").replace("\x00", ""),
                })
        meta = dict(m.meta)
        result["matches"].append({
            "rule": m.rule,
            "namespace": m.namespace,
            "id": meta.get("id", m.rule),
            "description": meta.get("description", ""),
            "severity": str(meta.get("severity", "medium")).lower(),
            "explanation": meta.get("explanation", ""),
            "tags": list(m.tags),
            "strings": strings[:20],
        })
    result["status"] = "complete"
    return result
