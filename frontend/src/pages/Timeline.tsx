import { useMemo, useState } from "react";
import type { Correlation, TimelineEvent } from "../api/types";
import { useCase } from "../auth/CaseContext";
import {
  Badge, ClassificationBadge, ConfidenceTag, cx, Drawer, Empty, ErrorBox, JsonBlock, KV, Label, Loading, Mono, PageHeader, Panel, SearchInput, selectCls,
  SEV_HEX, SeverityChip,
} from "../components/ui";
import { formatGap, formatUtc, titleCase } from "../lib/format";
import { useApi } from "../lib/hooks";
import { filterTimeline, groupByHour } from "../lib/timeline";

interface TimelineResp {
  items: TimelineEvent[];
  source_types: string[];
}

const SOURCE_LABEL: Record<string, [string, string]> = {
  windows_evtx: ["EVTX", "bg-sky-500/15 text-sky-300 ring-sky-500/40"],
  browser_history: ["BROWSER", "bg-violet-500/15 text-violet-200 ring-violet-500/40"],
  csv_log: ["NETWORK", "bg-emerald-500/15 text-emerald-300 ring-emerald-500/40"],
  json_events: ["EDR", "bg-orange-500/15 text-orange-300 ring-orange-500/40"],
  text_log: ["DNS/TEXT", "bg-teal-500/15 text-teal-300 ring-teal-500/40"],
};

function SourceTag({ source }: { source: string }) {
  const [label, cls] = SOURCE_LABEL[source] ?? [source.toUpperCase(), "bg-ink-700 text-ink-200 ring-ink-500"];
  return <span className={cx("inline-flex w-[74px] justify-center rounded px-1.5 py-0.5 text-[10px] font-bold tracking-wider ring-1 ring-inset", cls)}>{label}</span>;
}

function CorrelationCard({ c, onJump }: { c: Correlation; onJump: (id: number) => void }) {
  const [open, setOpen] = useState(c.rule_id === "CORR-002");
  return (
    <div className="rounded-lg border border-ink-700 bg-ink-900">
      <button type="button" className="flex w-full flex-wrap items-center gap-2 px-4 py-3 text-left" onClick={() => setOpen(!open)} aria-expanded={open}>
        <SeverityChip severity={c.severity} />
        <Mono className="text-ink-400">{c.rule_id}</Mono>
        <span className="min-w-0 flex-1 basis-[240px] text-[14px] font-medium text-ink-100">{c.title}</span>
        <ConfidenceTag value={c.confidence} />
        <ClassificationBadge classification="hypothesis" />
      </button>
      {open && (
        <div className="border-t border-ink-700 px-4 pb-4 pt-3">
          <ol className="relative ml-2 border-l border-ink-600">
            {c.steps.map((s, i) => {
              const tone = s.link_strength === "entity" ? "border-accent-400 bg-accent-500" : s.link_strength === "root" ? "border-ink-200 bg-ink-200" : "border-amber-400 bg-ink-900";
              return (
                <li key={i} className="mb-3 ml-4 last:mb-0">
                  <span className={cx("absolute -left-[6px] mt-1.5 h-[11px] w-[11px] rounded-full border-2", tone)} />
                  <div className="flex flex-wrap items-center gap-2 text-xs">
                    <span className="font-semibold uppercase tracking-wider text-ink-200">{i + 1}. {titleCase(s.name)}</span>
                    <span className="font-mono text-ink-300">{formatUtc(s.timestamp_utc)} UTC</span>
                    {s.gap_seconds !== null && <span className="font-mono text-ink-400">{formatGap(s.gap_seconds)}</span>}
                    <SourceTag source={s.source_type} />
                    {s.link_strength === "entity" && <Badge tone="accent">entity link</Badge>}
                    {s.link_strength === "temporal" && <Badge tone="warn">host + time window only</Badge>}
                    {s.link_strength === "root" && <Badge>anchor</Badge>}
                  </div>
                  <button type="button" onClick={() => onJump(s.timeline_event_id)} className="mt-0.5 text-left text-[13px] text-ink-100 [overflow-wrap:anywhere] hover:text-accent-400">
                    {s.summary}
                  </button>
                  {s.links.length > 0 && (
                    <ul className="mt-0.5 space-y-0.5 text-xs text-accent-400/90 [overflow-wrap:anywhere]">
                      {s.links.map((l, j) => (
                        <li key={j}>↳ {l}</li>
                      ))}
                    </ul>
                  )}
                </li>
              );
            })}
          </ol>
          <details className="mt-3">
            <summary className="cursor-pointer text-xs text-ink-300">Full explanation</summary>
            <pre className="mt-2 whitespace-pre-wrap rounded-md [overflow-wrap:anywhere] border border-ink-700 bg-ink-950 p-3 font-mono text-[11.5px] leading-relaxed text-ink-200">{c.explanation}</pre>
          </details>
          <div className="mt-3 rounded-md border border-violet-500/30 bg-violet-500/5 p-2.5">
            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-violet-200">Caveats</div>
            <ul className="list-disc space-y-0.5 pl-4 text-xs text-ink-300">
              {c.caveats.map((cv, i) => (
                <li key={i}>{cv}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </div>
  );
}

export default function TimelinePage() {
  const { caseId } = useCase();
  const resp = useApi<TimelineResp>(caseId ? `/api/cases/${caseId}/timeline` : null);
  const corr = useApi<Correlation[]>(caseId ? `/api/cases/${caseId}/correlations` : null);
  const [sources, setSources] = useState<string[]>([]);
  const [minSev, setMinSev] = useState("");
  const [text, setText] = useState("");
  const [onlyCorrelated, setOnlyCorrelated] = useState(false);
  const [selected, setSelected] = useState<TimelineEvent | null>(null);

  const events = useMemo(() => {
    const filtered = filterTimeline(resp.data?.items ?? [], { sources, minSeverity: minSev, text });
    return onlyCorrelated ? filtered.filter((e) => (e.correlations ?? []).length) : filtered;
  }, [resp.data, sources, minSev, text, onlyCorrelated]);
  const groups = useMemo(() => groupByHour(events), [events]);

  function jump(id: number) {
    const ev = resp.data?.items.find((e) => e.id === id);
    if (ev) setSelected(ev);
  }

  return (
    <div>
      <PageHeader
        title="Investigation Timeline"
        description="Events from every evidence source normalised to UTC (original values preserved). Correlations are explainable hypotheses: each step references a real event and states how it is linked."
      />

      <Panel title={`Correlated sequences (${corr.data?.length ?? 0})`} subtitle="Hypotheses — temporal and entity links do not by themselves prove causation" className="mb-4">
        <ErrorBox error={corr.error} onRetry={corr.reload} />
        {corr.loading && !corr.data ? (
          <Loading />
        ) : corr.data?.length ? (
          <div className="space-y-3">
            {corr.data.map((c) => (
              <CorrelationCard key={c.id} c={c} onJump={jump} />
            ))}
          </div>
        ) : (
          <Empty>No correlation rule matched the current timeline.</Empty>
        )}
      </Panel>

      <Panel
        title={`Chronology (${events.length} of ${resp.data?.items.length ?? 0} events)`}
        actions={
          <div className="flex flex-wrap items-end gap-2">
            <div className="w-36">
              <Label htmlFor="minsev">Min severity</Label>
              <select id="minsev" className={selectCls} value={minSev} onChange={(e) => setMinSev(e.target.value)}>
                <option value="">All</option>
                {["low", "medium", "high", "critical"].map((s) => (
                  <option key={s} value={s}>
                    {titleCase(s)}+
                  </option>
                ))}
              </select>
            </div>
            <SearchInput value={text} onChange={setText} placeholder="Search events" />
          </div>
        }
      >
        <div className="mb-3 flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] uppercase tracking-wider text-ink-400">Sources</span>
          {(resp.data?.source_types ?? []).map((s) => {
            const on = sources.includes(s);
            return (
              <button
                key={s}
                type="button"
                onClick={() => setSources(on ? sources.filter((x) => x !== s) : [...sources, s])}
                className={cx("rounded-md border px-2 py-1 text-xs", on ? "border-accent-400 bg-accent-500/10 text-accent-400" : "border-ink-600 text-ink-300 hover:bg-ink-800")}
                aria-pressed={on}
              >
                {SOURCE_LABEL[s]?.[0] ?? s} <span className="text-ink-500">({(resp.data?.items ?? []).filter((e) => e.source_type === s).length})</span>
              </button>
            );
          })}
          <label className="ml-2 flex items-center gap-1.5 text-xs text-ink-200">
            <input type="checkbox" className="accent-[#1fb5ae]" checked={onlyCorrelated} onChange={(e) => setOnlyCorrelated(e.target.checked)} />
            only events in a correlation
          </label>
        </div>
        <ErrorBox error={resp.error} onRetry={resp.reload} />
        {resp.loading && !resp.data ? (
          <Loading />
        ) : !groups.length ? (
          <Empty>No events match the filters.</Empty>
        ) : (
          <div className="space-y-5">
            {groups.map((g) => (
              <div key={g.key}>
                <div className="sticky top-0 z-[2] mb-1 flex items-center gap-2 bg-ink-900/95 py-1 backdrop-blur">
                  <span className="font-mono text-xs font-semibold text-ink-200">{g.day}</span>
                  <span className="font-mono text-xs text-accent-400">{g.hour} UTC</span>
                  <span className="h-px flex-1 bg-ink-700" />
                  <span className="text-[11px] text-ink-400">{g.events.length} events</span>
                </div>
                <ul className="space-y-1">
                  {g.events.map((e) => (
                    <li key={e.id}>
                      <button
                        type="button"
                        onClick={() => setSelected(e)}
                        className="group flex w-full items-stretch gap-3 rounded-md border border-transparent text-left hover:border-ink-700 hover:bg-ink-850"
                      >
                        <span className="w-1 shrink-0 rounded-full" style={{ background: SEV_HEX[e.severity] }} />
                        <span className="flex min-w-0 flex-1 flex-col gap-1 py-1.5 pr-2 md:flex-row md:items-start md:gap-3">
                          <span className="shrink-0 font-mono text-[12px] text-ink-300 md:w-[92px]">
                            {formatUtc(e.timestamp_utc, { date: false, ms: true })}
                            {e.timezone_assumed && <span className="text-amber-300" title="Timezone assumed for this source value">*</span>}
                          </span>
                          <span className="shrink-0">
                            <SourceTag source={e.source_type} />
                          </span>
                          <span className="min-w-0 flex-1">
                            <span className="block text-[13px] text-ink-100 [overflow-wrap:anywhere]">{e.summary}</span>
                            <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-400">
                              <span>{e.host || "unknown host"}</span>
                              <span>·</span>
                              <span>{titleCase(e.event_type)}</span>
                              <span>·</span>
                              <span className="font-mono">{e.evidence_name}</span>
                              {e.tags.slice(0, 6).map((t) => (
                                <Badge key={t} className="!text-[10px]">
                                  {t}
                                </Badge>
                              ))}
                              {(e.correlations ?? []).map((c) => (
                                <Badge key={c} tone="violet" className="!text-[10px]">
                                  {c}
                                </Badge>
                              ))}
                            </span>
                          </span>
                          {e.severity !== "info" && (
                            <span className="shrink-0">
                              <SeverityChip severity={e.severity} />
                            </span>
                          )}
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        )}
        <p className="mt-3 text-xs text-ink-400">* timezone not present in the source value; the configured assumed timezone was applied.</p>
      </Panel>

      <Drawer open={!!selected} onClose={() => setSelected(null)} title="Timeline event" width="max-w-2xl">
        {selected && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityChip severity={selected.severity} />
              <SourceTag source={selected.source_type} />
              <Badge>{titleCase(selected.event_type)}</Badge>
              <ConfidenceTag value={selected.confidence} />
            </div>
            <p className="text-sm text-ink-100 [overflow-wrap:anywhere]">{selected.summary}</p>
            <KV
              rows={[
                ["Time (UTC)", <Mono>{formatUtc(selected.timestamp_utc, { ms: true })}</Mono>],
                ["Original value", <Mono>{selected.original_timestamp}</Mono>],
                ["Timezone", selected.timezone_assumed ? <Badge tone="warn">assumed</Badge> : "present in source"],
                ["Host", selected.host || "–"],
                ["Evidence", <Mono>{selected.evidence_name} ({selected.evidence_id})</Mono>],
                ["Tags", selected.tags.length ? selected.tags.join(", ") : "–"],
                ["Correlations", (selected.correlations ?? []).join(", ") || "–"],
              ]}
            />
            <div>
              <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Entities</div>
              <JsonBlock value={selected.entities} />
            </div>
            <div>
              <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Source reference</div>
              <JsonBlock value={selected.source_ref} />
            </div>
          </div>
        )}
      </Drawer>
    </div>
  );
}
