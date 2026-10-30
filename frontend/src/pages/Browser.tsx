import { useState } from "react";
import { qs } from "../api/client";
import type { BrowserArtifact, Finding } from "../api/types";
import { useCase } from "../auth/CaseContext";
import { FindingList } from "../components/FindingList";
import {
  Badge, cx, Empty, ErrorBox, Hash, Loading, Mono, PageHeader, Panel, SearchInput, SeverityChip, Stat, tableCls, TableWrap, tdCls, thCls, trCls,
} from "../components/ui";
import { formatBytes, formatUtc } from "../lib/format";
import { useApi, useDebounced } from "../lib/hooks";

interface BrowserResp {
  items: BrowserArtifact[];
  findings: Finding[];
}

function Detections({ items }: { items: BrowserArtifact["detections"] }) {
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((d) => (
        <span key={d.rule_id} className="inline-flex items-center gap-1" title={d.title}>
          <SeverityChip severity={d.severity} />
          <Mono className="text-[11px] text-ink-300">{d.rule_id}</Mono>
        </span>
      ))}
    </div>
  );
}

export default function BrowserPage() {
  const { caseId } = useCase();
  const [text, setText] = useState("");
  const q = useDebounced(text);
  const resp = useApi<BrowserResp>(caseId ? `/api/cases/${caseId}/browser${qs({ q })}` : null);
  const items = resp.data?.items ?? [];
  const downloads = items.filter((i) => i.kind === "download");
  const visits = items.filter((i) => i.kind === "visit");
  const domains = new Set(visits.map((v) => { try { return new URL(v.url).hostname; } catch { return v.url; } }));

  return (
    <div>
      <PageHeader
        title="Browser Forensics"
        description="Chromium History databases are copied, hash-verified and opened read-only (immutable). WebKit timestamps (µs since 1601-01-01) are converted to UTC."
        actions={<SearchInput value={text} onChange={setText} placeholder="Filter URL, title, path" />}
      />
      <ErrorBox error={resp.error} onRetry={resp.reload} />
      {resp.loading && !resp.data ? (
        <Loading />
      ) : (
        <>
          <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4">
            <Stat label="Visits" value={visits.length} />
            <Stat label="Distinct hosts" value={domains.size} />
            <Stat label="Downloads" value={downloads.length} />
            <Stat label="Flagged downloads" value={downloads.filter((d) => d.detections.some((x) => x.classification === "suspicious")).length} tone="warn" />
          </div>
          <Panel title={`Downloads (${downloads.length})`} bodyClass="p-0">
            {downloads.length ? (
              <TableWrap>
                <table className={tableCls}>
                  <thead>
                    <tr>
                      {["Start (UTC)", "Downloaded file & origin", "Size", "State / verdict", "SHA-256", "Detections"].map((h) => (
                        <th key={h} className={thCls}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {downloads.map((d) => (
                      <tr key={d.id} className={trCls}>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>
                          <div>{formatUtc(d.timestamp_utc, { date: false, ms: true })}</div>
                          <div className="text-[11px] text-ink-400">{formatUtc(d.timestamp_utc).slice(0, 10)}</div>
                        </td>
                        <td className={cx(tdCls, "min-w-[320px]")}>
                          <div className="break-all font-mono text-[12.5px] text-ink-100">{d.target_path}</div>
                          <div className="mt-0.5 break-all font-mono text-[11px] text-ink-300">
                            <span className="text-ink-500">from </span>
                            {d.url}
                          </div>
                          {d.referrer && (
                            <div className="break-all font-mono text-[11px] text-ink-400">
                              <span className="text-ink-500">referrer </span>
                              {d.referrer}
                            </div>
                          )}
                        </td>
                        <td className={cx(tdCls, "whitespace-nowrap text-right font-mono text-xs")}>{formatBytes(d.total_bytes)}</td>
                        <td className={tdCls}>
                          <div className="flex flex-col items-start gap-1">
                            <Badge tone={d.extra?.state === "complete" ? "ok" : "warn"}>{d.extra?.state ?? "?"}</Badge>
                            <Badge tone={d.extra?.danger_type && d.extra.danger_type !== "not_dangerous" ? "danger" : "neutral"}>{d.extra?.danger_type ?? "?"}</Badge>
                          </div>
                        </td>
                        <td className={tdCls}>
                          <Hash value={d.extra?.sha256} keep={6} />
                        </td>
                        <td className={cx(tdCls, "min-w-[120px]")}>
                          <Detections items={d.detections} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            ) : (
              <div className="p-4">
                <Empty>No download records.</Empty>
              </div>
            )}
          </Panel>

          <Panel title={`Visits (${visits.length})`} className="mt-4" bodyClass="p-0">
            {visits.length ? (
              <TableWrap maxH="max-h-[520px]">
                <table className={tableCls}>
                  <thead>
                    <tr>
                      {["Visit time (UTC)", "Page", "Visits", "Transition", "Original value"].map((h) => (
                        <th key={h} className={thCls}>
                          {h}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {visits.map((v) => (
                      <tr key={v.id} className={trCls}>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>
                          <div>{formatUtc(v.timestamp_utc, { date: false, ms: true })}</div>
                          <div className="text-[11px] text-ink-400">{formatUtc(v.timestamp_utc).slice(0, 10)}</div>
                        </td>
                        <td className={cx(tdCls, "min-w-[320px]")}>
                          <div className="text-ink-100">{v.title || <span className="text-ink-500">(no title)</span>}</div>
                          <div className="break-all font-mono text-[11.5px] text-ink-300">{v.url}</div>
                        </td>
                        <td className={cx(tdCls, "text-right font-mono text-xs")}>{v.visit_count ?? "–"}</td>
                        <td className={tdCls}>
                          <Badge>{v.extra?.transition ?? "?"}</Badge>
                        </td>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-[11px] text-ink-400")}>{v.original_timestamp}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            ) : (
              <div className="p-4">
                <Empty>No visit records.</Empty>
              </div>
            )}
          </Panel>

          <Panel title="Browser findings" className="mt-4">
            <FindingList findings={resp.data?.findings ?? []} empty="No browser findings." />
          </Panel>
        </>
      )}
    </div>
  );
}
