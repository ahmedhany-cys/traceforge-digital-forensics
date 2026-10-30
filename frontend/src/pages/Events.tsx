import { Fragment, useEffect, useState } from "react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { qs } from "../api/client";
import type { Evidence, Finding, WindowsEvent } from "../api/types";
import { useCase } from "../auth/CaseContext";
import { FindingList } from "../components/FindingList";
import { Icon } from "../components/Icon";
import {
  Badge, Button, cx, Empty, ErrorBox, Label, Loading, Mono, PageHeader, Panel, SearchInput, selectCls, SeverityChip, tableCls, TableWrap, tdCls, thCls, trCls,
} from "../components/ui";
import { formatUtc, severityRank } from "../lib/format";
import { useApi, useDebounced } from "../lib/hooks";

interface EventsResp {
  total: number;
  page: number;
  page_size: number;
  items: WindowsEvent[];
  event_id_stats: { event_id: number; count: number; description: string }[];
}

const PAGE_SIZE = 50;

export default function EventsPage() {
  const { caseId } = useCase();
  const [eventId, setEventId] = useState("");
  const [evidenceId, setEvidenceId] = useState("");
  const [text, setText] = useState("");
  const [flagged, setFlagged] = useState(false);
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<number | null>(null);
  const q = useDebounced(text);
  useEffect(() => setPage(1), [eventId, evidenceId, q, flagged, caseId]);

  const evidence = useApi<Evidence[]>(caseId ? `/api/cases/${caseId}/evidence` : null);
  const evtx = (evidence.data ?? []).filter((e) => e.artifact_type === "windows_evtx");
  const names = Object.fromEntries((evidence.data ?? []).map((e) => [e.id, e.original_filename]));
  const resp = useApi<EventsResp>(
    caseId
      ? `/api/cases/${caseId}/windows-events${qs({ event_id: eventId, evidence_id: evidenceId, q, flagged_only: flagged, page, page_size: PAGE_SIZE })}`
      : null,
  );
  const findings = useApi<Finding[]>(caseId ? `/api/cases/${caseId}/findings?source=evtx&classification=suspicious,confirmed_rule_match` : null);
  const stats = resp.data?.event_id_stats ?? [];
  const pages = resp.data ? Math.max(1, Math.ceil(resp.data.total / PAGE_SIZE)) : 1;

  return (
    <div>
      <PageHeader
        title="Windows Event Analysis"
        description="EVTX records parsed with python-evtx and evaluated against documented, configurable detection rules. Rules state the audit policy they depend on: absence of a detection is not absence of activity."
      />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Event ID distribution" subtitle="All parsed records in this case (click a bar to filter)" className="xl:col-span-2">
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={stats.map((s) => ({ ...s, label: String(s.event_id) }))} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="#1b2535" vertical={false} />
                <XAxis dataKey="label" tickLine={false} axisLine={{ stroke: "#263246" }} interval={0} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip
                  contentStyle={{ background: "#0f1520", border: "1px solid #263246", borderRadius: 6, fontSize: 12 }}
                  cursor={{ fill: "rgba(63,208,201,0.06)" }}
                  formatter={(v: number, _n, p) => [`${v} records`, (p?.payload as { description?: string })?.description || "Event"]}
                />
                <Bar isAnimationActive={false} dataKey="count" fill="#3fd0c9" radius={[3, 3, 0, 0]} maxBarSize={30} cursor="pointer" onClick={(d: { event_id?: number }) => d?.event_id && setEventId(String(d.event_id))} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Filters">
          <div className="space-y-3">
            <div>
              <Label htmlFor="eid">Event ID</Label>
              <select id="eid" className={selectCls} value={eventId} onChange={(e) => setEventId(e.target.value)}>
                <option value="">All event IDs</option>
                {stats.map((s) => (
                  <option key={s.event_id} value={s.event_id}>
                    {s.event_id} – {s.description || "other"} ({s.count})
                  </option>
                ))}
              </select>
            </div>
            <div>
              <Label htmlFor="evf">Log file</Label>
              <select id="evf" className={selectCls} value={evidenceId} onChange={(e) => setEvidenceId(e.target.value)}>
                <option value="">All EVTX evidence</option>
                {evtx.map((e) => (
                  <option key={e.id} value={e.id}>
                    {e.original_filename}
                  </option>
                ))}
              </select>
            </div>
            <div>
              <Label>Text</Label>
              <SearchInput value={text} onChange={setText} placeholder="Description, computer, provider" />
            </div>
            <label className="flex items-center gap-2 text-sm text-ink-200">
              <input type="checkbox" className="accent-[#1fb5ae]" checked={flagged} onChange={(e) => setFlagged(e.target.checked)} />
              Only records with suspicious detections
            </label>
            {(eventId || evidenceId || text || flagged) && (
              <Button size="sm" variant="ghost" icon="x" onClick={() => { setEventId(""); setEvidenceId(""); setText(""); setFlagged(false); }}>
                Clear filters
              </Button>
            )}
          </div>
        </Panel>
      </div>

      <Panel
        title={`Event records (${resp.data?.total ?? 0})`}
        className="mt-4"
        bodyClass="p-0"
        actions={
          <div className="flex items-center gap-2 text-xs text-ink-300">
            <Button size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
              Prev
            </Button>
            <span className="font-mono">
              {page} / {pages}
            </span>
            <Button size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>
              Next
            </Button>
          </div>
        }
      >
        <ErrorBox error={resp.error} onRetry={resp.reload} />
        {resp.loading && !resp.data ? (
          <Loading />
        ) : resp.data?.items.length ? (
          <TableWrap>
            <table className={tableCls}>
              <thead>
                <tr>
                  {["", "Time (UTC)", "Event", "Source", "Description", "Detections"].map((h, i) => (
                    <th key={i} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {resp.data.items.map((ev) => {
                  const isOpen = open === ev.id;
                  const top = [...ev.detections].sort((a, b) => severityRank(b.severity) - severityRank(a.severity));
                  return (
                    <Fragment key={ev.id}>
                      <tr className={cx(trCls, "cursor-pointer", isOpen && "bg-ink-850")} onClick={() => setOpen(isOpen ? null : ev.id)}>
                        <td className={cx(tdCls, "w-6")}>
                          <Icon name="chevron" className={cx("h-3.5 w-3.5 text-ink-400 transition-transform", isOpen && "rotate-90")} />
                        </td>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>
                          <div>{formatUtc(ev.timestamp_utc, { date: false, ms: true })}</div>
                          <div className="text-[11px] text-ink-400">{formatUtc(ev.timestamp_utc).slice(0, 10)}</div>
                        </td>
                        <td className={tdCls}>
                          <div className="font-mono font-semibold text-accent-400">{ev.event_id}</div>
                          <div className="font-mono text-[11px] text-ink-400">#{ev.record_number}</div>
                        </td>
                        <td className={cx(tdCls, "whitespace-nowrap text-xs")}>
                          <div>{ev.computer.split(".")[0]}</div>
                          <div className="max-w-[150px] truncate text-ink-400" title={ev.channel}>{ev.channel}</div>
                        </td>
                        <td className={cx(tdCls, "min-w-[220px] max-w-[620px] break-words")}>{ev.description}</td>
                        <td className={cx(tdCls, "min-w-[130px]")}>
                          <div className="flex flex-wrap gap-1">
                            {top.map((d) => (
                              <span key={d.rule_id} className="inline-flex items-center gap-1" title={d.title}>
                                <SeverityChip severity={d.severity} />
                                <Mono className="text-[11px] text-ink-300">{d.rule_id}</Mono>
                              </span>
                            ))}
                          </div>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-ink-850">
                          <td />
                          <td colSpan={5} className="px-3 pb-4 pt-1">
                            <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_340px]">
                              <div>
                                <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Event data</div>
                                <table className="w-full text-xs">
                                  <tbody>
                                    {Object.entries(ev.data).map(([k, v]) => (
                                      <tr key={k} className="border-b border-ink-800">
                                        <td className="w-48 py-1 pr-3 align-top font-mono text-ink-400">{k}</td>
                                        <td className="whitespace-pre-wrap break-all py-1 font-mono text-ink-100">{v || <span className="text-ink-500">(empty)</span>}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                              <div className="space-y-2 text-xs">
                                <div className="text-[11px] uppercase tracking-wider text-ink-400">Record</div>
                                <div className="space-y-1 text-ink-300">
                                  <div>Provider: <span className="text-ink-100">{ev.provider}</span></div>
                                  <div>Original TimeCreated: <Mono>{ev.original_timestamp}</Mono></div>
                                  <div>User SID: <Mono>{ev.user_sid ?? "–"}</Mono></div>
                                  <div>Level: {ev.level ?? "–"}</div>
                                  <div>Source file: <Mono>{names[ev.evidence_id] ?? ev.evidence_id}</Mono></div>
                                </div>
                                {ev.detections.length > 0 && (
                                  <>
                                    <div className="pt-2 text-[11px] uppercase tracking-wider text-ink-400">Detections</div>
                                    {ev.detections.map((d) => (
                                      <div key={d.rule_id} className="flex flex-wrap items-center gap-1.5">
                                        <SeverityChip severity={d.severity} />
                                        <Mono>{d.rule_id}</Mono>
                                        <span className="text-ink-200">{d.title}</span>
                                        <Badge>{d.classification}</Badge>
                                      </div>
                                    ))}
                                  </>
                                )}
                              </div>
                            </div>
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
            <Empty>No event records match the filters.</Empty>
          </div>
        )}
      </Panel>

      <Panel title="Windows event detections" subtitle="Suspicious findings with rule rationale and audit-policy prerequisites" className="mt-4">
        {findings.loading && !findings.data ? <Loading /> : <FindingList findings={findings.data ?? []} empty="No suspicious Windows event detections." />}
      </Panel>
    </div>
  );
}
