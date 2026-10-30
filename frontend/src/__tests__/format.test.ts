import { describe, expect, it } from "vitest";
import { formatBytes, formatGap, formatUtc, severityRank, truncateMiddle } from "../lib/format";

describe("format utils", () => {
  it("formats byte sizes", () => {
    expect(formatBytes(0)).toBe("0 B");
    expect(formatBytes(1023)).toBe("1,023 B");
    expect(formatBytes(54792)).toBe("53.5 KB");
    expect(formatBytes(48_213_904)).toBe("46.0 MB");
    expect(formatBytes(null)).toBe("–");
  });

  it("formats timestamps in UTC regardless of offset in input", () => {
    expect(formatUtc("2026-10-14T13:43:10.482000+00:00")).toBe("2026-10-14 13:43:10");
    expect(formatUtc("2026-10-14T09:41:49.702-04:00", { ms: true })).toBe("2026-10-14 13:41:49.702");
    expect(formatUtc("2026-10-14T13:43:10Z", { date: false })).toBe("13:43:10");
    expect(formatUtc(null)).toBe("–");
    expect(formatUtc("not a date")).toBe("not a date");
  });

  it("formats gaps between correlated steps", () => {
    expect(formatGap(4)).toBe("+4s");
    expect(formatGap(85)).toBe("+1m 25s");
    expect(formatGap(3 * 3600 + 120)).toBe("+3h 02m");
    expect(formatGap(null)).toBe("");
  });

  it("truncates long hashes in the middle", () => {
    const h = "b52143d4a49a8f3f362012f22805ec0da015a4efe8968a6167f72b5b79263290";
    expect(truncateMiddle(h, 6)).toBe("b52143…263290");
    expect(truncateMiddle("short", 6)).toBe("short");
  });

  it("ranks severities", () => {
    expect(severityRank("critical")).toBeGreaterThan(severityRank("high"));
    expect(severityRank("high")).toBeGreaterThan(severityRank("medium"));
    expect(severityRank("info")).toBe(0);
  });
});
