import { useMemo, useRef, useState, type DragEvent } from "react";
import { api, ApiError, qs } from "../api/client";
import type { AnalysisRun, AuditRecord, Evidence, Finding, IntegrityCheck } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useCase } from "../auth/CaseContext";
import { FindingList } from "../components/FindingList";
import { Icon } from "../components/Icon";
import { useToast } from "../components/Toast";
import {
  Badge, Button, cx, Drawer, Empty, ErrorBox, Hash, inputCls, JsonBlock, KV, Label, Loading, Mono, PageHeader, Panel, SearchInput, StatusBadge,
  tableCls, TableWrap, tdCls, thCls, trCls,
} from "../components/ui";
import { formatBytes, formatUtc, titleCase } from "../lib/format";
import { useAction, useApi } from "../lib/hooks";

interface UploadItem {
  name: string;
  size: number;
  state: "queued" | "uploading" | "acquired" | "rejected";
  message?: string;
  evidenceId?: string;
  analysis?: string;
  httpStatus?: number;
}

interface UploadResponse {
  results: { filename: string; status: string; evidence?: Evidence; analysis?: { status: string }; error?: string; existing_id?: string | null }[];
}

function rejectionText(err: unknown): { message: string; status?: number; existing?: string } {
  if (err instanceof ApiError) {
    const d = err.detail as { results?: { existing_id?: string | null }[] } | string;
    const existing = typeof d === "object" && d?.results?.[0]?.existing_id ? d.results[0].existing_id ?? undefined : undefined;
    return { message: err.message, status: err.status, existing };
  }
  return { message: (err as Error).message };
}

function UploadPanel({ caseId, onDone }: { caseId: number; onDone: () => void }) {
  const [items, setItems] = useState<UploadItem[]>([]);
  const [drag, setDrag] = useState(false);
  const [host, setHost] = useState("");
  const [desc, setDesc] = useState("");
  const [autoAnalyze, setAutoAnalyze] = useState(true);
  const [running, setRunning] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const toast = useToast();

  async function uploadAll(files: File[]) {
    if (!files.length || running) return;
    const queue: UploadItem[] = files.map((f) => ({ name: f.name, size: f.size, state: "queued" }));
    setItems(queue);
    setRunning(true);
    let ok = 0;
    for (let i = 0; i < files.length; i++) {
      setItems((cur) => cur.map((it, j) => (j === i ? { ...it, state: "uploading" } : it)));
      const form = new FormData();
      form.append("files", files[i], files[i].name);
      form.append("source_host", host);
      form.append("source_description", desc);
      form.append("auto_analyze", String(autoAnalyze));
      try {
        const res = await api.upload<UploadResponse>(`/api/cases/${caseId}/evidence`, form);
        const r = res.results[0];
        if (r.status === "acquired") ok++;
        setItems((cur) =>
          cur.map((it, j) =>
            j === i
              ? r.status === "acquired"
                ? { ...it, state: "acquired", evidenceId: r.evidence?.id, analysis: r.analysis?.status ?? "not requested", message: r.evidence?.detected_type }
                : { ...it, state: "rejected", message: r.error, evidenceId: r.existing_id ?? undefined }
              : it,
          ),
        );
      } catch (e) {
        const rej = rejectionText(e);
        setItems((cur) => cur.map((it, j) => (j === i ? { ...it, state: "rejected", message: rej.message, httpStatus: rej.status, evidenceId: rej.existing } : it)));
      }
    }
    setRunning(false);
    if (ok) toast.success(`${ok} of ${files.length} file(s) acquired`);
    onDone();
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDrag(false);
    void uploadAll(Array.from(e.dataTransfer.files));
  }

  return (
    <Panel title="Acquire evidence" subtitle="Files are hashed (SHA-256/SHA-1/MD5) while streaming, type-checked by content, stored read-only and logged to the ledger.">
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1fr_320px]">
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          className={cx(
            "flex min-h-[150px] flex-col items-center justify-center gap-2 rounded-md border-2 border-dashed px-4 py-6 text-center transition-colors",
            drag ? "border-accent-400 bg-accent-500/5" : "border-ink-600 bg-ink-850/60",
          )}
        >
          <Icon name="upload" className="h-7 w-7 text-ink-400" />
          <div className="text-sm text-ink-200">Drop evidence files here</div>
          <div className="text-xs text-ink-400">EVTX · Chromium History (SQLite) · CSV · JSON / JSONL · text logs · PE executables</div>
          <Button size="sm" onClick={() => inputRef.current?.click()} disabled={running} icon="plus">
            Choose files
          </Button>
          <input
            ref={inputRef}
            type="file"
            multiple
            className="hidden"
            data-testid="evidence-input"
            onChange={(e) => {
              void uploadAll(Array.from(e.target.files ?? []));
              e.target.value = "";
            }}
          />
        </div>
        <div className="space-y-3">
          <div>
            <Label htmlFor="src-host">Source host</Label>
            <input id="src-host" className={inputCls} value={host} maxLength={128} onChange={(e) => setHost(e.target.value)} placeholder="e.g. WS-FIN-042" />
          </div>
          <div>
            <Label htmlFor="src-desc">Source / acquisition notes</Label>
            <input id="src-desc" className={inputCls} value={desc} maxLength={2000} onChange={(e) => setDesc(e.target.value)} placeholder="How and where it was collected" />
          </div>
          <label className="flex items-center gap-2 text-sm text-ink-200">
            <input type="checkbox" className="accent-[#1fb5ae]" checked={autoAnalyze} onChange={(e) => setAutoAnalyze(e.target.checked)} />
            Analyse immediately and rebuild case timeline
          </label>
        </div>
      </div>
      {items.length > 0 && (
        <ul className="mt-4 divide-y divide-ink-800 rounded-md border border-ink-700">
          {items.map((it, i) => (
            <li key={`${it.name}-${i}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-sm">
              <span className="w-24 shrink-0">
                {it.state === "uploading" ? (
                  <Badge tone="info">uploading…</Badge>
                ) : it.state === "acquired" ? (
                  <Badge tone="ok">acquired</Badge>
                ) : it.state === "rejected" ? (
                  <Badge tone="danger">{it.httpStatus === 409 ? "duplicate" : it.httpStatus === 413 ? "too large" : it.httpStatus === 415 ? "type rejected" : "rejected"}</Badge>
                ) : (
                  <Badge>queued</Badge>
                )}
              </span>
              <span className="min-w-0 flex-1 truncate font-mono text-[12.5px]">{it.name}</span>
              <span className="font-mono text-xs text-ink-400">{formatBytes(it.size)}</span>
              {it.evidenceId && <Mono className="text-accent-400">{it.evidenceId}</Mono>}
              {it.analysis && <StatusBadge status={it.analysis} />}
              {it.message && <span className={cx("w-full text-xs", it.state === "rejected" ? "text-rose-300" : "text-ink-400")}>{it.message}</span>}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

interface EvidenceDetail {
  evidence: Evidence;
  analysis_runs: AnalysisRun[];
  integrity_checks: IntegrityCheck[];
  custody: AuditRecord[];
  findings: Finding[];
}

function EvidenceDrawer({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
  const { data, error, loading, reload } = useApi<EvidenceDetail>(`/api/evidence/${id}`);
  const { can } = useAuth();
  const { busy, run } = useAction();
  const toast = useToast();

  async function verify() {
    try {
      const r = await run("verify", () => api.post<{ check: IntegrityCheck }>(`/api/evidence/${id}/verify`));
      if (r.check.result === "match") toast.success("Integrity verified: SHA-256 matches the acquisition hash");
      else toast.error(`Integrity ${r.check.result.toUpperCase()}: stored copy does not match acquisition hash`);
      reload();
      onChanged();
    } catch (e) {
      toast.error(e);
    }
  }
  async function analyze() {
    try {
      const r = await run("analyze", () => api.post<{ analysis: { status: string }; reconstruction: Record<string, number> }>(`/api/evidence/${id}/analyze`));
      toast.success(`Analysis ${r.analysis.status}; timeline rebuilt (${r.reconstruction?.timeline_events ?? 0} events)`);
      reload();
      onChanged();
    } catch (e) {
      toast.error(e);
    }
  }

  const ev = data?.evidence;
  return (
    <Drawer open onClose={onClose} title={<span className="font-mono">{id}</span>} width="max-w-4xl">
      {loading && !data && <Loading />}
      <ErrorBox error={error} onRetry={reload} />
      {ev && data && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-base font-semibold text-ink-100">{ev.original_filename}</span>
            <StatusBadge status={ev.integrity_status} />
            <StatusBadge status={ev.analysis_status} />
            <div className="ml-auto flex flex-wrap gap-2">
              {can("investigator") && (
                <>
                  <Button size="sm" icon="shield" busy={busy === "verify"} onClick={verify}>
                    Verify integrity
                  </Button>
                  <Button size="sm" icon="refresh" busy={busy === "analyze"} onClick={analyze}>
                    Re-analyze
                  </Button>
                  <a
                    href={`/api/evidence/${id}/download`}
                    className="inline-flex h-7 items-center gap-1.5 rounded-md border border-ink-600 bg-ink-800 px-2.5 text-xs text-ink-100 hover:bg-ink-700"
                    title="Download a copy (logged as evidence_exported)"
                    onClick={() => setTimeout(reload, 800)}
                  >
                    <Icon name="download" className="h-3.5 w-3.5" /> Export copy
                  </a>
                </>
              )}
            </div>
          </div>
          <Panel title="Acquisition record">
            <KV
              rows={[
                ["SHA-256", <Hash value={ev.sha256} full />],
                ["SHA-1", <Hash value={ev.sha1} full />],
                ["MD5", <Hash value={ev.md5} full />],
                ["Size", `${formatBytes(ev.size_bytes)} (${ev.size_bytes.toLocaleString()} bytes)`],
                ["Detected type", ev.detected_type],
                ["Artifact type", titleCase(ev.artifact_type)],
                ["Declared MIME", ev.declared_mime || "–"],
                ["Source host", ev.source_host || "–"],
                ["Source notes", ev.source_description || "–"],
                ["Acquired", `${formatUtc(ev.acquired_at, { ms: true })} UTC by ${ev.acquired_by}`],
                ["Last verified", ev.last_verified_at ? `${formatUtc(ev.last_verified_at)} UTC` : "–"],
                ["Duplicate of", ev.duplicate_of ? <Mono>{ev.duplicate_of} (same SHA-256 in another case)</Mono> : "–"],
              ]}
            />
          </Panel>
          <Panel title="Analysis runs" bodyClass="p-0">
            <TableWrap>
              <table className={tableCls}>
                <thead>
                  <tr>
                    {["Analyzer", "Engine", "Status", "Started (UTC)", "Issues", "Current"].map((h) => (
                      <th key={h} className={thCls}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.analysis_runs.map((r) => (
                    <tr key={r.id} className={trCls}>
                      <td className={tdCls}>{r.analyzer}</td>
                      <td className={cx(tdCls, "font-mono text-xs")}>{r.engine_version}</td>
                      <td className={tdCls}>
                        <StatusBadge status={r.status} />
                      </td>
                      <td className={cx(tdCls, "font-mono text-xs")}>{formatUtc(r.started_at)}</td>
                      <td className={tdCls}>
                        {r.error_count ? (
                          <details>
                            <summary className="cursor-pointer text-amber-300">{r.error_count} parse issue(s)</summary>
                            <div className="mt-1">
                              <JsonBlock value={r.errors} />
                            </div>
                          </details>
                        ) : (
                          <span className="text-ink-400">none</span>
                        )}
                      </td>
                      <td className={tdCls}>{r.is_current ? <Badge tone="accent">current</Badge> : <span className="text-xs text-ink-400">superseded</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Panel>
          <Panel title={`Findings (${data.findings.length})`}>
            <FindingList findings={data.findings} showEvidence={false} />
          </Panel>
          <Panel title="Integrity verification history" bodyClass="p-0">
            <TableWrap maxH="max-h-64">
              <table className={tableCls}>
                <thead>
                  <tr>
                    {["Checked (UTC)", "By", "Trigger", "Result", "Observed SHA-256"].map((h) => (
                      <th key={h} className={thCls}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.integrity_checks.map((c) => (
                    <tr key={c.id} className={trCls}>
                      <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(c.checked_at)}</td>
                      <td className={tdCls}>{c.checked_by}</td>
                      <td className={tdCls}>{c.trigger.replace(/_/g, " ")}</td>
                      <td className={tdCls}>
                        <StatusBadge status={c.result} />
                      </td>
                      <td className={tdCls}>
                        <Hash value={c.observed_sha256} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Panel>
          <Panel title="Chain-of-custody records for this item" bodyClass="p-0">
            <TableWrap maxH="max-h-72">
              <table className={tableCls}>
                <thead>
                  <tr>
                    {["Seq", "Timestamp (UTC)", "Actor", "Action", "Record hash"].map((h) => (
                      <th key={h} className={thCls}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {data.custody.map((a) => (
                    <tr key={a.seq} className={trCls}>
                      <td className={cx(tdCls, "font-mono text-xs")}>{a.seq}</td>
                      <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(a.timestamp, { ms: true })}</td>
                      <td className={tdCls}>{a.actor}</td>
                      <td className={tdCls}>
                        <Badge>{a.action}</Badge>
                      </td>
                      <td className={tdCls}>
                        <Hash value={a.record_hash} keep={8} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </Panel>
        </div>
      )}
    </Drawer>
  );
}

export default function EvidencePage() {
  const { caseId, refresh } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const { busy, run } = useAction();
  const list = useApi<Evidence[]>(caseId ? `/api/cases/${caseId}/evidence` : null);
  const history = useApi<{ items: AuditRecord[] }>(
    caseId ? `/api/custody/ledger${qs({ case_id: caseId, action: "evidence_acquired,duplicate_evidence_rejected,evidence_rejected", page_size: 100 })}` : null,
  );
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(null);

  const rows = useMemo(() => {
    const t = q.trim().toLowerCase();
    return (list.data ?? []).filter((e) => !t || `${e.id} ${e.original_filename} ${e.sha256} ${e.artifact_type} ${e.source_host}`.toLowerCase().includes(t));
  }, [list.data, q]);

  function reloadAll() {
    list.reload();
    history.reload();
    void refresh();
  }

  async function verifyAll() {
    try {
      const r = await run("verifyAll", () => api.post<{ checked: number; mismatches: number }>(`/api/cases/${caseId}/verify-all`));
      if (r.mismatches) toast.error(`${r.mismatches} of ${r.checked} items FAILED verification`);
      else toast.success(`All ${r.checked} evidence items match their acquisition SHA-256`);
      list.reload();
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div>
      <PageHeader
        title="Evidence Vault"
        description="Original evidence is stored once, read-only, outside any web-served directory. Analysis works on verified bytes and re-checks the hash afterwards."
        actions={
          can("investigator") && (
            <Button icon="shield" busy={busy === "verifyAll"} onClick={verifyAll}>
              Verify all
            </Button>
          )
        }
      />
      {can("investigator") && caseId && (
        <div className="mb-4">
          <UploadPanel caseId={caseId} onDone={reloadAll} />
        </div>
      )}
      <Panel title={`Evidence inventory (${list.data?.length ?? 0})`} actions={<SearchInput value={q} onChange={setQ} placeholder="Filter by name, ID, hash…" />} bodyClass="p-0">
        <ErrorBox error={list.error} onRetry={list.reload} />
        {list.loading && !list.data ? (
          <Loading />
        ) : rows.length ? (
          <TableWrap>
            <table className={tableCls}>
              <thead>
                <tr>
                  {["Evidence ID", "Original filename", "Type", "Size", "SHA-256", "Acquired (UTC)", "By", "Analysis", "Integrity"].map((h) => (
                    <th key={h} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => (
                  <tr key={e.id} className={cx(trCls, "cursor-pointer")} onClick={() => setOpen(e.id)}>
                    <td className={cx(tdCls, "whitespace-nowrap font-mono text-[12px] text-accent-400")}>{e.id}</td>
                    <td className={cx(tdCls, "min-w-[220px] max-w-[320px] break-all font-mono text-[12px]")}>{e.original_filename}</td>
                    <td className={tdCls}>
                      <Badge tone="info">{titleCase(e.artifact_type)}</Badge>
                    </td>
                    <td className={cx(tdCls, "whitespace-nowrap text-right font-mono text-xs")}>{formatBytes(e.size_bytes)}</td>
                    <td className={tdCls} onClick={(ev) => ev.stopPropagation()}>
                      <Hash value={e.sha256} keep={8} />
                    </td>
                    <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(e.acquired_at)}</td>
                    <td className={tdCls}>{e.acquired_by}</td>
                    <td className={tdCls}>
                      <StatusBadge status={e.analysis_status} />
                    </td>
                    <td className={tdCls}>
                      <StatusBadge status={e.integrity_status} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        ) : (
          <div className="p-4">
            <Empty>{q ? "No evidence matches the filter." : "No evidence acquired yet."}</Empty>
          </div>
        )}
      </Panel>

      <Panel title="Acquisition history" subtitle="From the audit ledger: acquisitions, rejected uploads and duplicate detections" className="mt-4" bodyClass="p-0">
        {history.data?.items.length ? (
          <TableWrap maxH="max-h-80">
            <table className={tableCls}>
              <thead>
                <tr>
                  {["Seq", "Timestamp (UTC)", "Actor", "Action", "Evidence", "Details"].map((h) => (
                    <th key={h} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.data.items.map((a) => {
                  const d = a.details as Record<string, string | number | null>;
                  return (
                    <tr key={a.seq} className={trCls}>
                      <td className={cx(tdCls, "font-mono text-xs")}>{a.seq}</td>
                      <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(a.timestamp, { ms: true })}</td>
                      <td className={tdCls}>{a.actor}</td>
                      <td className={tdCls}>
                        <Badge tone={a.action === "evidence_acquired" ? "ok" : "danger"}>{a.action}</Badge>
                      </td>
                      <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{a.evidence_id ?? "–"}</td>
                      <td className={cx(tdCls, "min-w-[320px] text-xs text-ink-300")}>
                        <span className="font-mono">{String(d.original_filename ?? d.filename ?? "")}</span>
                        {d.reason ? <span className="text-rose-300"> — {String(d.reason)}</span> : null}
                        {d.sha256 ? <span className="text-ink-400"> · sha256 {String(d.sha256).slice(0, 16)}…</span> : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        ) : (
          <div className="p-4">{history.loading ? <Loading /> : <Empty>No acquisition records.</Empty>}</div>
        )}
      </Panel>

      {open && <EvidenceDrawer id={open} onClose={() => setOpen(null)} onChanged={reloadAll} />}
    </div>
  );
}
