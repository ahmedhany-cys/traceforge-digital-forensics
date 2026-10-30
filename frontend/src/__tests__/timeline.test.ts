import { describe, expect, it } from "vitest";
import type { TimelineEvent } from "../api/types";
import { filterTimeline, groupByHour } from "../lib/timeline";

function ev(id: number, ts: string, source: string, severity: TimelineEvent["severity"], summary: string): TimelineEvent {
  return {
    id, evidence_id: "EV-1", evidence_name: "x", timestamp_utc: ts, original_timestamp: ts, timezone_assumed: false, source_type: source,
    event_type: "e", summary, severity, confidence: "high", host: "WS-FIN-042", entities: {}, source_ref: {}, tags: [],
  };
}

const events = [
  ev(3, "2026-10-14T13:58:06+00:00", "csv_log", "high", "ALLOW 10.20.4.42 -> 203.0.113.77:443"),
  ev(1, "2026-10-14T12:31:04+00:00", "windows_evtx", "info", "Logon jmorales"),
  ev(2, "2026-10-14T13:41:45+00:00", "browser_history", "high", "Download Q3_Vendor_Invoice.pdf.exe"),
  ev(4, "2026-10-14T13:52:10+00:00", "windows_evtx", "medium", "Object access Confidential"),
];

describe("timeline logic", () => {
  it("filters by source, minimum severity and text", () => {
    expect(filterTimeline(events, { sources: [], minSeverity: "", text: "" })).toHaveLength(4);
    expect(filterTimeline(events, { sources: ["windows_evtx"], minSeverity: "", text: "" }).map((e) => e.id)).toEqual([1, 4]);
    expect(filterTimeline(events, { sources: [], minSeverity: "high", text: "" }).map((e) => e.id).sort()).toEqual([2, 3]);
    expect(filterTimeline(events, { sources: [], minSeverity: "", text: "INVOICE" }).map((e) => e.id)).toEqual([2]);
    expect(filterTimeline(events, { sources: ["csv_log"], minSeverity: "medium", text: "203.0.113" }).map((e) => e.id)).toEqual([3]);
  });

  it("groups chronologically by UTC hour", () => {
    const groups = groupByHour(events);
    expect(groups.map((g) => g.key)).toEqual(["2026-10-14 12:00", "2026-10-14 13:00"]);
    expect(groups[1].events.map((e) => e.id)).toEqual([2, 4, 3]);
  });
});
