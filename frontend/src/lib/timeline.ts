import type { TimelineEvent } from "../api/types";
import { severityRank } from "./format";

export interface TimelineFilter {
  sources: string[]; // empty = all
  minSeverity: string; // "" = all
  text: string;
}

export function filterTimeline(events: TimelineEvent[], f: TimelineFilter): TimelineEvent[] {
  const text = f.text.trim().toLowerCase();
  const min = f.minSeverity ? severityRank(f.minSeverity) : -1;
  return events.filter((e) => {
    if (f.sources.length && !f.sources.includes(e.source_type)) return false;
    if (min >= 0 && severityRank(e.severity) < min) return false;
    if (text) {
      const hay = `${e.summary} ${e.host} ${e.evidence_name ?? ""} ${e.tags.join(" ")}`.toLowerCase();
      if (!hay.includes(text)) return false;
    }
    return true;
  });
}

export interface TimelineGroup {
  key: string; // "2026-10-14 13:00"
  day: string; // "2026-10-14"
  hour: string; // "13:00"
  events: TimelineEvent[];
}

/** Group chronologically by UTC day+hour, preserving input order inside each group. */
export function groupByHour(events: TimelineEvent[]): TimelineGroup[] {
  const sorted = [...events].sort((a, b) => a.timestamp_utc.localeCompare(b.timestamp_utc) || a.id - b.id);
  const groups: TimelineGroup[] = [];
  for (const e of sorted) {
    const d = new Date(e.timestamp_utc);
    const day = d.toISOString().slice(0, 10);
    const hour = `${String(d.getUTCHours()).padStart(2, "0")}:00`;
    const key = `${day} ${hour}`;
    let g = groups[groups.length - 1];
    if (!g || g.key !== key) {
      g = { key, day, hour, events: [] };
      groups.push(g);
    }
    g.events.push(e);
  }
  return groups;
}
