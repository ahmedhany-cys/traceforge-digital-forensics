import { Fragment, useEffect, useState } from "react";
import { api, qs } from "../api/client";
import type { AuditRecord, IntegrityCheck } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useCase } from "../auth/CaseContext";
import { Icon } from "../components/Icon";
import { useToast } from "../components/Toast";
import {
  Badge, Button, cx, Empty, ErrorBox, Hash, JsonBlock, Label, Loading, Mono, PageHeader, Panel, selectCls, StatusBadge, tableCls, TableWrap, tdCls, thCls,
  trCls,
} from "../components/ui";
import { formatUtc } from "../lib/format";
import { useAction, useApi } from "../lib/hooks";

interface LedgerResp {
  total: number;
  page: number;
  page_size: number;
  items: AuditRecord[];
  actions: string[];
  head: { seq: number; hash: string };
}

interface Verification {
  valid: boolean;
  records_checked: number;
  head_hash: string;
  first_invalid_seq: number | null;
  problems: { seq: number; issue: string; detail: string }[];
}

const PAGE = 50;

function actionTone(a: string): "ok" | "danger" | "info" | "warn" | "neutral" | "accent" {
  if (/fail|rejected|refused|locked/.test(a)) return "danger";
  if (/acquired|verified|login$/.test(a)) return "ok";
  if (/analysis|reconstructed/.test(a)) return "info";
  if (/report|export|download/.test(a)) return "accent";
  if (/settings|user_/.test(a)) return "warn";
  return "neutral";
}

export default function CustodyPage() {
  const { caseId } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const { busy, run } = useAction();
  const [scope, setScope] = useState<"case" | "all">("case");
  const [action, setAction] = useState("");
  const [page, setPage] = useState(1);
  const [open, setOpen] = useState<number | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  useEffect(() => setPage(1), [scope, action, caseId]);

  const ledger = useApi<LedgerResp>(`/api/custody/ledger${qs({ case_id: scope === "case" ? caseId : undefined, action, page, page_size: PAGE })}`);
  const checks = useApi<IntegrityCheck[]>(caseId ? `/api/cases/${caseId}/integrity-checks` : null);
  const pages = ledger.data ? Math.max(1, Math.ceil(ledger.data.total / PAGE)) : 1;

  async function verify() {
    try {
      const r = await run("verify", () => api.post<Verification>("/api/custody/verify"));
      setVerification(r);
      if (r.valid) toast.success(`Ledger intact: ${r.records_checked} records verified`);
      else toast.error(`Ledger verification FAILED at seq ${r.first_invalid_seq}`);
      ledger.reload();
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div>
      <PageHeader
        title="Chain of Custody"
        description="Every acquisition, access, analysis, verification, report and configuration change is appended to a SHA-256 hash-chained audit ledger."
        actions={
          can("investigator") && (
            <Button variant="primary" icon="shield" busy={busy === "verify"} onClick={verify}>
              Verify ledger
            </Button>
          )
        }
      />

      <div className="mb-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Ledger state" className="xl:col-span-2">
          {verification ? (
            <div className={cx("rounded-md border px-4 py-3", verification.valid ? "border-emerald-500/40 bg-emerald-500/10" : "border-rose-500/50 bg-rose-500/10")}>
              <div className="flex flex-wrap items-center gap-2">
                <Icon name={verification.valid ? "check" : "alert"} className={cx("h-5 w-5", verification.valid ? "text-emerald-300" : "text-rose-300")} />
                <span className={cx("text-base font-semibold", verification.valid ? "text-emerald-200" : "text-rose-200")}>
                  {verification.valid ? "Chain intact" : "Chain BROKEN"}
                </span>
                <span className="text-sm text-ink-300">· {verification.records_checked} records recomputed and linked</span>
              </div>
              <div className="mt-2 text-xs text-ink-300">
                Head hash <Hash value={verification.head_hash} full />
              </div>
              {verification.problems.length > 0 && (
                <ul className="mt-2 space-y-1 text-xs text-rose-200">
                  {verification.problems.slice(0, 20).map((p, i) => (
                    <li key={i}>
                      seq {p.seq}: <b>{p.issue}</b> – {p.detail}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ) : (
            <div className="text-sm text-ink-300">
              Current head: seq <Mono>{ledger.data?.head.seq ?? "–"}</Mono> · <Hash value={ledger.data?.head.hash} keep={16} />
              <p className="mt-2 text-xs text-ink-400">Run “Verify ledger” to recompute every record hash and check every link. The verification itself is recorded.</p>
            </div>
          )}
        </Panel>
        <Panel title="Tamper-evident ≠ immutable">
          <p className="text-xs leading-relaxed text-ink-300">
            Each record's hash covers its content and the previous record's hash, so editing, deleting, inserting or re-ordering any record breaks the chain
            from that point and is detected. It does not make the database immutable: someone with write access could rewrite the whole chain
            consistently. Record the head hash somewhere independent (a report, a ticket, WORM storage) to detect that.
          </p>
        </Panel>
      </div>

      <Panel
        title={`Audit ledger (${ledger.data?.total ?? 0} records)`}
        actions={
          <div className="flex flex-wrap items-end gap-2">
            <div className="w-36">
              <Label htmlFor="scope">Scope</Label>
              <select id="scope" className={selectCls} value={scope} onChange={(e) => setScope(e.target.value as "case" | "all")}>
                <option value="case">Selected case</option>
                <option value="all">Entire ledger</option>
              </select>
            </div>
            <div className="w-56">
              <Label htmlFor="act">Action</Label>
              <select id="act" className={selectCls} value={action} onChange={(e) => setAction(e.target.value)}>
                <option value="">All actions</option>
                {(ledger.data?.actions ?? []).map((a) => (
                  <option key={a} value={a}>
                    {a}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2 text-xs text-ink-300">
              <Button size="sm" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                Prev
              </Button>
              <span className="font-mono">
                {page}/{pages}
              </span>
              <Button size="sm" disabled={page >= pages} onClick={() => setPage(page + 1)}>
                Next
              </Button>
            </div>
          </div>
        }
        bodyClass="p-0"
      >
        <ErrorBox error={ledger.error} onRetry={ledger.reload} />
        {ledger.loading && !ledger.data ? (
          <Loading />
        ) : ledger.data?.items.length ? (
          <TableWrap>
            <table className={tableCls}>
              <thead>
                <tr>
                  {["Seq", "Timestamp (UTC)", "Actor", "Action", "Evidence", "Hash chain (prev → record)"].map((h) => (
                    <th key={h} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ledger.data.items.map((r) => {
                  const isOpen = open === r.seq;
                  return (
                    <Fragment key={r.seq}>
                      <tr className={cx(trCls, "cursor-pointer", isOpen && "bg-ink-850")} onClick={() => setOpen(isOpen ? null : r.seq)}>
                        <td className={cx(tdCls, "font-mono text-xs text-accent-400")}>{r.seq}</td>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(r.timestamp, { ms: true })}</td>
                        <td className={tdCls}>{r.actor}</td>
                        <td className={tdCls}>
                          <Badge tone={actionTone(r.action)}>{r.action}</Badge>
                        </td>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{r.evidence_id ?? "–"}</td>
                        <td className={cx(tdCls, "whitespace-nowrap font-mono text-[11.5px]")}>
                          <span className="text-ink-400">{r.prev_hash.slice(0, 10)}…</span>
                          <span className="mx-1.5 text-ink-500">→</span>
                          <span className="text-ink-100">{r.record_hash.slice(0, 10)}…</span>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-ink-850">
                          <td colSpan={6} className="px-3 pb-3">
                            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
                              <div>
                                <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-400">Details</div>
                                <JsonBlock value={r.details} />
                              </div>
                              <div className="space-y-1 text-xs">
                                <div className="text-[11px] uppercase tracking-wider text-ink-400">Record</div>
                                <div>Record ID: <Mono>{r.record_id}</Mono></div>
                                <div>Case: <Mono>{r.case_id ?? "–"}</Mono></div>
                                <div>Previous hash: <Hash value={r.prev_hash} full /></div>
                                <div>Record hash: <Hash value={r.record_hash} full /></div>
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
            <Empty>No ledger records for this filter.</Empty>
          </div>
        )}
      </Panel>

      <Panel title="Evidence integrity verification history" subtitle="Re-hash results for this case (acquisition, pre/post analysis, manual, report generation)" className="mt-4" bodyClass="p-0">
        {checks.loading && !checks.data ? (
          <Loading />
        ) : checks.data?.length ? (
          <TableWrap maxH="max-h-[420px]">
            <table className={tableCls}>
              <thead>
                <tr>
                  {["Checked (UTC)", "Evidence", "By", "Trigger", "Result", "Expected SHA-256", "Observed SHA-256"].map((h) => (
                    <th key={h} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {checks.data.map((c) => (
                  <tr key={c.id} className={trCls}>
                    <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(c.checked_at)}</td>
                    <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{c.evidence_id}</td>
                    <td className={tdCls}>{c.checked_by}</td>
                    <td className={cx(tdCls, "text-xs")}>{c.trigger.replace(/_/g, " ")}</td>
                    <td className={tdCls}>
                      <StatusBadge status={c.result} />
                    </td>
                    <td className={tdCls}>
                      <Hash value={c.expected_sha256} keep={8} />
                    </td>
                    <td className={tdCls}>
                      <Hash value={c.observed_sha256} keep={8} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        ) : (
          <div className="p-4">
            <Empty>No integrity checks recorded.</Empty>
          </div>
        )}
      </Panel>
    </div>
  );
}
