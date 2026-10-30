export function formatBytes(n: number | null | undefined): string {
  if (n === null || n === undefined || Number.isNaN(n)) return "–";
  if (n < 1024) return `${n.toLocaleString("en-US")} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

/** "2026-10-14 13:43:10 UTC" (seconds precision by default; ms optional). */
export function formatUtc(iso: string | null | undefined, opts: { ms?: boolean; date?: boolean } = {}): string {
  if (!iso) return "–";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const pad = (x: number, w = 2) => String(x).padStart(w, "0");
  const date = `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
  let time = `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}`;
  if (opts.ms) time += `.${pad(d.getUTCMilliseconds(), 3)}`;
  return opts.date === false ? time : `${date} ${time}`;
}

export function formatGap(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "";
  const s = Math.round(seconds);
  if (s < 60) return `+${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `+${m}m ${String(s % 60).padStart(2, "0")}s`;
  return `+${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m`;
}

export function truncateMiddle(value: string | null | undefined, keep = 10): string {
  if (!value) return "–";
  if (value.length <= keep * 2 + 1) return value;
  return `${value.slice(0, keep)}…${value.slice(-keep)}`;
}

export function titleCase(value: string): string {
  return value.replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

export function plural(n: number, word: string, pluralWord?: string): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? word : pluralWord ?? `${word}s`}`;
}

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export function severityRank(sev: string): number {
  const i = SEVERITY_ORDER.indexOf(sev as (typeof SEVERITY_ORDER)[number]);
  return i === -1 ? 0 : SEVERITY_ORDER.length - i - 1;
}
