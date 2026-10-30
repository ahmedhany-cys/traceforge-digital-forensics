"""Explainable sequence correlation over the normalised timeline.

Design principles:

* **No invented events.** Every step of a correlation references an existing
  timeline event (and through it, a source record in a specific piece of
  evidence).
* **Explicit link strength.** Each step records *why* it was attached to the
  sequence: an entity link (same file name, same SHA-256, PID/parent-PID process
  lineage, or a destination embedded in an analysed binary) or merely the same
  host within a time window. Confidence is derived from those links.
* **Hypotheses, not verdicts.** Correlations are classified as hypotheses and
  always carry caveats about causality and clock skew.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
MAX_ROOTS_PER_RULE = 200


class TimelineLike(Protocol):
    id: int
    timestamp_utc: datetime
    event_type: str
    host: str
    entities: dict[str, Any]
    tags: list[str]
    severity: str
    summary: str
    source_type: str
    evidence_id: str
    timezone_assumed: bool


@dataclass
class StepMatch:
    step: dict[str, Any]
    event: TimelineLike
    links: list[str]
    strength: str  # "entity" | "temporal" | "root"
    gap_seconds: float | None


@dataclass
class CorrelationResult:
    rule: dict[str, Any]
    steps: list[StepMatch]
    confidence: str
    explanation: str
    caveats: list[str] = field(default_factory=list)


def load_correlation_rules(path: Path) -> list[dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    rules = doc.get("rules", [])
    for rule in rules:
        names = [s["name"] for s in rule["steps"]]
        if len(names) != len(set(names)):
            raise ValueError(f"{rule['id']}: duplicate step names")
        for step in rule["steps"]:
            for link in step.get("links", []):
                if link.get("step") and link["step"] not in names[: names.index(step["name"])]:
                    raise ValueError(f"{rule['id']}: step '{step['name']}' links to a later or unknown step")
    return rules


def _ext(name: str) -> str:
    return name.rsplit(".", 1)[-1].lower() if name and "." in name else ""


def _matches(event: TimelineLike, match: dict[str, Any]) -> bool:
    if event.event_type not in match.get("event_types", [event.event_type]):
        return False
    ent = event.entities or {}
    if "file_ext_in" in match and _ext(str(ent.get("file_name", ""))) not in match["file_ext_in"]:
        return False
    if "tag_any" in match and not (set(event.tags or []) & set(match["tag_any"])):
        return False
    if match.get("external_dst") and not ent.get("dst_external"):
        return False
    if "min_bytes_sent" in match:
        try:
            if int(ent.get("bytes_sent") or 0) < int(match["min_bytes_sent"]):
                return False
        except (TypeError, ValueError):
            return False
    if "min_severity" in match and SEVERITY_RANK.get(event.severity, 0) < SEVERITY_RANK[match["min_severity"]]:
        return False
    return True


class Lineage:
    """Process lineage rooted at a process-creation event, bounded by host and time."""

    def __init__(self, root: TimelineLike, events: list[TimelineLike], window: timedelta):
        self.host = root.host
        self.pids: set[int] = set()
        self.images: set[str] = set()
        self.evidence: list[str] = []
        root_ent = root.entities or {}
        if root_ent.get("pid") is not None:
            self.pids.add(int(root_ent["pid"]))
        if root_ent.get("process_image"):
            self.images.add(root_ent["process_image"])
        root_sha = root_ent.get("sha256")
        end = root.timestamp_utc + window
        later = [e for e in events if e.host == root.host and root.timestamp_utc <= e.timestamp_utc <= end]
        if root_sha is None:
            # recover the root image hash from a file-creation record for the same path
            for e in later + [e for e in events if e.event_type == "file_create" and e.host == root.host]:
                ent = e.entities or {}
                if e.event_type == "file_create" and ent.get("file_path") == root_ent.get("process_image") and ent.get("sha256"):
                    root_sha = ent["sha256"]
                    break
        changed = True
        while changed:
            changed = False
            for e in later:
                ent = e.entities or {}
                if e.event_type == "process_creation" and ent.get("parent_pid") is not None:
                    if int(ent["parent_pid"]) in self.pids and int(ent.get("pid", -1)) not in self.pids:
                        self.pids.add(int(ent["pid"]))
                        if ent.get("process_image"):
                            self.images.add(ent["process_image"])
                        self.evidence.append(f"event #{e.id}: {ent.get('process_image')} (PID {ent.get('pid')}) spawned by PID {ent.get('parent_pid')}")
                        changed = True
                if e.event_type == "file_create" and root_sha and ent.get("sha256") == root_sha:
                    path = ent.get("file_path")
                    if path and path not in self.images:
                        self.images.add(path)
                        self.evidence.append(f"event #{e.id}: {path} written with the same SHA-256 as the root image")
                        changed = True

    def contains(self, event: TimelineLike) -> str | None:
        if event.host != self.host:
            return None
        ent = event.entities or {}
        if ent.get("pid") is not None and event.event_type != "process_creation" and int(ent["pid"]) in self.pids:
            return f"PID {ent['pid']} belongs to the process lineage of the executed image"
        if event.event_type == "process_creation" and ent.get("pid") is not None and int(ent["pid"]) in self.pids:
            return f"process PID {ent['pid']} is a descendant of the executed image"
        for key in ("process_image", "target_image"):
            img = ent.get(key)
            if img and img in self.images and ent.get("pid") is None:
                return f"{key.replace('_', ' ')} '{img}' is part of the process lineage (image path match; no PID available)"
        return None


def _gap(a: datetime, b: datetime) -> str:
    seconds = int((b - a).total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, s = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m {s:02d}s"
    h, m = divmod(minutes, 60)
    return f"{h}h {m:02d}m"


class Correlator:
    def __init__(self, events: list[TimelineLike], pe_indicators: dict[str, set[str]], window_minutes: int):
        self.events = sorted(events, key=lambda e: (e.timestamp_utc, e.id))
        self.pe_indicators = pe_indicators
        self.window = timedelta(minutes=window_minutes)
        self._lineages: dict[int, Lineage] = {}

    def lineage(self, root: TimelineLike) -> Lineage:
        if root.id not in self._lineages:
            self._lineages[root.id] = Lineage(root, self.events, self.window)
        return self._lineages[root.id]

    def _links(self, step: dict[str, Any], event: TimelineLike, chosen: dict[str, StepMatch]) -> list[str]:
        out = []
        ent = event.entities or {}
        for link in step.get("links", []):
            prior = chosen.get(link.get("step", ""))
            if link["type"] == "same_entity" and prior:
                key = link["entity"]
                mine, theirs = ent.get(key), (prior.event.entities or {}).get(key)
                if mine and theirs and str(mine).lower() == str(theirs).lower():
                    out.append(f"same {key.replace('_', ' ')} as step '{prior.step['name']}' ({mine})")
            elif link["type"] == "lineage" and prior:
                reason = self.lineage(prior.event).contains(event)
                if reason:
                    out.append(reason)
            elif link["type"] == "embedded_indicator" and prior:
                pent = prior.event.entities or {}
                keys = [k for k in (str(pent.get("file_name", "")).lower(), pent.get("sha256")) if k]
                embedded: set[str] = set()
                for k in keys:
                    embedded |= self.pe_indicators.get(k, set())
                for value in (ent.get("dst_ip"), ent.get("domain")):
                    if value and str(value).lower() in embedded:
                        out.append(f"destination {value} is hard-coded in the analysed binary '{pent.get('file_name')}'")
        return out

    def _search(self, rule, index, chosen, order) -> list[StepMatch] | None:
        steps = rule["steps"]
        if index == len(steps):
            return [chosen[s["name"]] for s in steps]
        step = steps[index]
        prev = chosen[steps[index - 1]["name"]].event
        root = chosen[steps[0]["name"]].event
        max_gap = timedelta(minutes=step.get("max_gap_minutes", self.window.total_seconds() / 60))
        candidates = []
        for e in self.events:
            if e.timestamp_utc < prev.timestamp_utc:
                continue
            if e.timestamp_utc - prev.timestamp_utc > max_gap or e.timestamp_utc - root.timestamp_utc > self.window:
                break
            if any(m.event.id == e.id for m in chosen.values()):
                continue
            if e.host and root.host and e.host != root.host:
                continue
            if not _matches(e, step.get("match", {})):
                continue
            links = self._links(step, e, chosen)
            if step.get("require_link") and not links:
                continue
            candidates.append((0 if links else 1, e.timestamp_utc, e, links))
        candidates.sort(key=lambda c: (c[0], c[1]))
        for _, _, e, links in candidates[:25]:
            chosen[step["name"]] = StepMatch(step, e, links, "entity" if links else "temporal",
                                             (e.timestamp_utc - prev.timestamp_utc).total_seconds())
            result = self._search(rule, index + 1, chosen, order)
            if result:
                return result
            del chosen[step["name"]]
        return None

    def run(self, rules: list[dict[str, Any]]) -> list[CorrelationResult]:
        results: list[CorrelationResult] = []
        for rule in rules:
            first = rule["steps"][0]
            seen: set[tuple[int, ...]] = set()
            roots = [e for e in self.events if _matches(e, first.get("match", {}))][:MAX_ROOTS_PER_RULE]
            for root in roots:
                chosen = {first["name"]: StepMatch(first, root, [], "root", None)}
                chain = self._search(rule, 1, chosen, None)
                if not chain:
                    continue
                key = tuple(m.event.id for m in chain)
                # one correlation per distinct set of later steps (avoid N roots → same chain)
                tail = key[1:]
                if key in seen or any(t == tail for t in (k[1:] for k in seen)):
                    continue
                seen.add(key)
                results.append(self._describe(rule, chain))
        return results

    def _describe(self, rule, chain: list[StepMatch]) -> CorrelationResult:
        later = chain[1:]
        entity_steps = sum(1 for m in later if m.strength == "entity")
        if later and entity_steps == len(later):
            confidence = "high"
        elif later and entity_steps * 2 >= len(later):
            confidence = "medium"
        else:
            confidence = "low"
        lines = []
        for i, m in enumerate(chain, start=1):
            prefix = f"{i}. [{m.step['name']}] {m.event.timestamp_utc.strftime('%Y-%m-%d %H:%M:%S')} UTC – {m.event.summary}"
            if m.strength == "root":
                lines.append(prefix + " (sequence anchor)")
            elif m.strength == "entity":
                lines.append(prefix + f" (+{_gap(chain[i - 2].event.timestamp_utc, m.event.timestamp_utc)}; linked: {'; '.join(m.links)})")
            else:
                lines.append(prefix + f" (+{_gap(chain[i - 2].event.timestamp_utc, m.event.timestamp_utc)}; linked by host and time window only)")
        caveats = [
            "Correlation is inferred from timestamps and shared entities. It indicates a plausible sequence and does not by itself prove causation.",
        ]
        temporal = [m.step["name"] for m in later if m.strength == "temporal"]
        if temporal:
            caveats.append(f"Step(s) {', '.join(repr(t) for t in temporal)} are attached only by host and time proximity; an unrelated event could occupy the same window.")
        sources = {m.event.source_type for m in chain}
        if len(sources) > 1:
            caveats.append(f"Events come from {len(sources)} different sources ({', '.join(sorted(sources))}); clock skew between sources could affect ordering by seconds or more.")
        if any(m.event.timezone_assumed for m in chain):
            caveats.append("At least one step's timestamp had no timezone in the source; the configured assumed timezone was applied.")
        lineage_notes = []
        if any("lineage" in link for m in later for link in m.links):
            for m in chain:
                if m.event.id in self._lineages:
                    lineage_notes = self._lineages[m.event.id].evidence[:8]
        explanation = (
            f"{rule['description']}\n\n" + "\n".join(lines)
            + (f"\n\nProcess lineage evidence:\n- " + "\n- ".join(lineage_notes) if lineage_notes else "")
            + f"\n\nConfidence '{confidence}': {entity_steps} of {len(later)} subsequent steps are linked by shared entities."
        )
        return CorrelationResult(rule, chain, confidence, explanation, caveats)
