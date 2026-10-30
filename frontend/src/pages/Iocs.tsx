import { Fragment, useRef, useState } from "react";
import { api, qs } from "../api/client";
import type { Ioc } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useCase } from "../auth/CaseContext";
import { Icon } from "../components/Icon";
import { useToast } from "../components/Toast";
import {
  AssessmentBadge, Badge, Button, CopyButton, cx, Empty, ErrorBox, Label, Loading, Mono, PageHeader, Panel, SearchInput, selectCls, tableCls, TableWrap,
  tdCls, thCls, trCls,
} from "../components/ui";
import { formatUtc, titleCase } from "../lib/format";
import { useAction, useApi, useDebounced } from "../lib/hooks";

interface WatchEntry {
  id: number;
  indicator: string;
  type: string;
  confidence: string;
  source: string;
  description: string;
}

const NS_TONE: Record<string, "neutral" | "ok" | "warn" | "info" | "danger"> = {
  private: "ok",
  loopback: "ok",
  documentation: "info",
  reserved_example: "info",
  public: "warn",
  public_namespace: "warn",
  double_extension_executable: "danger",
};

function Watchlist() {
  const { can } = useAuth();
  const toast = useToast();
  const { busy, run } = useAction();
  const list = useApi<WatchEntry[]>("/api/watchlist");
  const fileRef = useRef<HTMLInputElement>(null);
  const [result, setResult] = useState<{ added: number; rejected: { line: number; indicator: string; reason: string }[]; note: string } | null>(null);

  async function importCsv(file: File) {
    const form = new FormData();
    form.append("file", file, file.name);
    try {
      const r = await run("import", () => api.upload<{ added: number; rejected: { line: number; indicator: string; reason: string }[]; note: string }>("/api/watchlist/import", form));
      setResult(r);
      toast.success(`Watchlist: ${r.added} entries added, ${r.rejected.length} rejected`);
      list.reload();
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <Panel
      title={`Local watchlist (${list.data?.length ?? 0})`}
      subtitle="Analyst-curated reference indicators. No external or paid threat-intelligence service is queried."
      actions={
        can("investigator") && (
          <>
            <Button size="sm" icon="upload" busy={busy === "import"} onClick={() => fileRef.current?.click()}>
              Import CSV
            </Button>
            <input
              ref={fileRef}
              type="file"
              accept=".csv,text/csv"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void importCsv(f);
                e.target.value = "";
              }}
            />
          </>
        )
      }
      bodyClass="p-0"
    >
      {result && (
        <div className="border-b border-ink-700 px-4 py-2 text-xs text-ink-300">
          Added {result.added}; rejected {result.rejected.length}
          {result.rejected.slice(0, 5).map((r) => (
            <div key={r.line} className="text-rose-300">
              line {r.line}: {r.indicator} – {r.reason}
            </div>
          ))}
          <div className="text-ink-400">{result.note}</div>
        </div>
      )}
      <p className="px-4 pt-3 text-xs text-ink-400">
        CSV columns: <Mono>indicator,type,confidence,source,description</Mono> (type: ipv4 | domain | sha256 | sha1 | md5).
      </p>
      {list.data?.length ? (
        <TableWrap>
          <table className={tableCls}>
            <thead>
              <tr>
                {["Indicator", "Type", "Confidence", "Source", "Description"].map((h) => (
                  <th key={h} className={thCls}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {list.data.map((w) => (
                <tr key={w.id} className={trCls}>
                  <td className={cx(tdCls, "max-w-[300px] break-all font-mono text-xs text-ink-100")}>{w.indicator}</td>
                  <td className={tdCls}>{w.type}</td>
                  <td className={tdCls}>
                    <Badge tone={w.confidence === "high" ? "danger" : w.confidence === "medium" ? "warn" : "neutral"}>{w.confidence}</Badge>
                  </td>
                  <td className={cx(tdCls, "text-xs")}>{w.source}</td>
                  <td className={cx(tdCls, "text-xs text-ink-300")}>{w.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      ) : (
        <div className="p-4">{list.loading ? <Loading /> : <Empty>The watchlist is empty.</Empty>}</div>
      )}
    </Panel>
  );
}

export default function IocsPage() {
  const { caseId } = useCase();
  const [type, setType] = useState("");
  const [assessment, setAssessment] = useState("");
  const [text, setText] = useState("");
  const [open, setOpen] = useState<number | null>(null);
  const q = useDebounced(text);
  const resp = useApi<Ioc[]>(caseId ? `/api/cases/${caseId}/iocs${qs({ ioc_type: type, assessment, q })}` : null);
  const all = useApi<Ioc[]>(caseId ? `/api/cases/${caseId}/iocs` : null);
  const types = Array.from(new Set((all.data ?? []).map((i) => i.ioc_type))).sort();
  const counts = (all.data ?? []).reduce<Record<string, number>>((m, i) => ({ ...m, [i.assessment]: (m[i.assessment] ?? 0) + 1 }), {});

  return (
    <div>
      <PageHeader
        title="IOC Explorer"
        description="Indicators extracted from every evidence source, validated and normalised. Extraction never implies maliciousness: assessments are raised only by a watchlist match or a referencing finding, and the reason is shown."
      />
      <div className="mb-4 flex flex-wrap gap-2">
        {["watchlist_match", "suspicious", "observed", "benign_context"].map((a) => (
          <button
            key={a}
            type="button"
            onClick={() => setAssessment(assessment === a ? "" : a)}
            className={cx("flex items-center gap-2 rounded-md border px-3 py-2", assessment === a ? "border-accent-400 bg-accent-500/10" : "border-ink-700 bg-ink-900 hover:bg-ink-850")}
            aria-pressed={assessment === a}
          >
            <AssessmentBadge assessment={a} />
            <span className="font-mono text-lg font-semibold tabular-nums text-ink-100">{counts[a] ?? 0}</span>
          </button>
        ))}
      </div>
      <Panel
        title={`Indicators (${resp.data?.length ?? 0})`}
        actions={
          <div className="flex flex-wrap items-end gap-2">
            <div className="w-36">
              <Label htmlFor="itype">Type</Label>
              <select id="itype" className={selectCls} value={type} onChange={(e) => setType(e.target.value)}>
                <option value="">All types</option>
                {types.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </select>
            </div>
            <div className="w-40">
              <Label htmlFor="iass">Assessment</Label>
              <select id="iass" className={selectCls} value={assessment} onChange={(e) => setAssessment(e.target.value)}>
                <option value="">All</option>
                {["watchlist_match", "suspicious", "observed", "benign_context"].map((a) => (
                  <option key={a} value={a}>
                    {titleCase(a)}
                  </option>
                ))}
              </select>
            </div>
            <SearchInput value={text} onChange={setText} placeholder="Search value" />
          </div>
        }
        bodyClass="p-0"
      >
        <ErrorBox error={resp.error} onRetry={resp.reload} />
        {resp.loading && !resp.data ? (
          <Loading />
        ) : resp.data?.length ? (
          <TableWrap>
            <table className={tableCls}>
              <thead>
                <tr>
                  {["", "Type", "Indicator", "Namespace", "Assessment", "Reason", "Seen (UTC)", "Count"].map((h, i) => (
                    <th key={i} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {resp.data.map((i) => {
                  const isOpen = open === i.id;
                  return (
                    <Fragment key={i.id}>
                      <tr className={cx(trCls, "cursor-pointer", isOpen && "bg-ink-850")} onClick={() => setOpen(isOpen ? null : i.id)}>
                        <td className={cx(tdCls, "w-6")}>
                          <Icon name="chevron" className={cx("h-3.5 w-3.5 text-ink-400 transition-transform", isOpen && "rotate-90")} />
                        </td>
                        <td className={tdCls}>
                          <Badge>{i.ioc_type}</Badge>
                        </td>
                        <td className={cx(tdCls, "min-w-[240px] max-w-[340px]")} onClick={(e) => e.stopPropagation()}>
                          <span className="inline-flex max-w-full items-start gap-1">
                            <span className="break-all font-mono text-[12px] text-ink-100">{i.normalized}</span>
                            <CopyButton value={i.normalized} />
                          </span>
                        </td>
                        <td className={tdCls}>
                          <Badge tone={NS_TONE[i.classification] ?? "neutral"}>{i.classification.replace(/_/g, " ")}</Badge>
                        </td>
                        <td className={tdCls}>
                          <AssessmentBadge assessment={i.assessment} />
                        </td>
                        <td className={cx(tdCls, "min-w-[220px] max-w-[320px] text-xs text-ink-300 [overflow-wrap:anywhere]")}>{i.assessment_reason}</td>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>
                          {i.first_seen ? (
                            <>
                              <div>{formatUtc(i.first_seen, { date: false })}{i.last_seen && i.last_seen !== i.first_seen ? ` → ${formatUtc(i.last_seen, { date: false })}` : ""}</div>
                              <div className="text-[11px] text-ink-400">{formatUtc(i.first_seen).slice(0, 10)}</div>
                            </>
                          ) : (
                            <span className="text-ink-400" title="Static artifact (e.g. string in a binary) – no event time">static</span>
                          )}
                        </td>
                        <td className={cx(tdCls, "text-right font-mono")}>{i.occurrence_count}</td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-ink-850">
                          <td />
                          <td colSpan={7} className="px-3 pb-3 pt-1">
                            <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Occurrences (source evidence)</div>
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="text-left text-ink-400">
                                  <th className="py-1 pr-3 font-medium">Time (UTC)</th>
                                  <th className="py-1 pr-3 font-medium">Evidence</th>
                                  <th className="py-1 pr-3 font-medium">Source</th>
                                  <th className="py-1 pr-3 font-medium">Field</th>
                                  <th className="py-1 font-medium">Context</th>
                                </tr>
                              </thead>
                              <tbody>
                                {i.occurrences.map((o, k) =>
                                  o.truncated ? (
                                    <tr key={k}>
                                      <td colSpan={5} className="py-1 text-ink-400">
                                        … {o.truncated} more occurrence(s) not stored individually
                                      </td>
                                    </tr>
                                  ) : (
                                    <tr key={k} className="border-t border-ink-800 align-top">
                                      <td className="whitespace-nowrap py-1 pr-3 font-mono">{o.timestamp_utc ? formatUtc(o.timestamp_utc) : "–"}</td>
                                      <td className="py-1 pr-3 font-mono text-ink-200">{o.evidence_name}</td>
                                      <td className="py-1 pr-3">{o.source}</td>
                                      <td className="py-1 pr-3 font-mono">{o.field}</td>
                                      <td className="break-all py-1 font-mono text-ink-300">{o.context}</td>
                                    </tr>
                                  ),
                                )}
                              </tbody>
                            </table>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        ) : (
          <div className="p-4">
            <Empty>No indicators match the filters.</Empty>
          </div>
        )}
      </Panel>
      <div className="mt-4">
        <Watchlist />
      </div>
    </div>
  );
}
