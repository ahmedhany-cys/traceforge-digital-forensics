import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { Case } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useCase } from "../auth/CaseContext";
import { useToast } from "../components/Toast";
import {
  Badge, Button, cx, Empty, inputCls, KV, Label, Loading, PageHeader, Panel, selectCls, SeverityChip, tableCls, TableWrap, tdCls, textareaCls, thCls, trCls,
} from "../components/ui";
import { formatUtc, titleCase } from "../lib/format";
import { useAction } from "../lib/hooks";

function CreateCaseForm({ onCreated, onCancel }: { onCreated: (c: Case) => void; onCancel: () => void }) {
  const toast = useToast();
  const { busy, run } = useAction();
  const [form, setForm] = useState({ case_number: "", title: "", organization: "", description: "", priority: "medium" });
  const set = (k: keyof typeof form) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });

  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      const c = await run("create", () => api.post<Case>("/api/cases", form));
      toast.success(`Case ${c.case_number} created`);
      onCreated(c);
    } catch (err) {
      toast.error(err);
    }
  }

  return (
    <form onSubmit={submit} className="grid grid-cols-1 gap-3 md:grid-cols-2">
      <div>
        <Label htmlFor="cn">Case number</Label>
        <input id="cn" className={cx(inputCls, "font-mono")} value={form.case_number} onChange={set("case_number")} required pattern="[A-Za-z0-9][A-Za-z0-9._\-]*" minLength={3} maxLength={64} placeholder="IR-2026-0001" />
      </div>
      <div>
        <Label htmlFor="pr">Priority</Label>
        <select id="pr" className={selectCls} value={form.priority} onChange={set("priority")}>
          {["low", "medium", "high", "critical"].map((p) => (
            <option key={p} value={p}>
              {titleCase(p)}
            </option>
          ))}
        </select>
      </div>
      <div className="md:col-span-2">
        <Label htmlFor="ti">Title</Label>
        <input id="ti" className={inputCls} value={form.title} onChange={set("title")} required minLength={3} maxLength={255} />
      </div>
      <div className="md:col-span-2">
        <Label htmlFor="org">Organisation</Label>
        <input id="org" className={inputCls} value={form.organization} onChange={set("organization")} maxLength={255} />
      </div>
      <div className="md:col-span-2">
        <Label htmlFor="desc">Incident description</Label>
        <textarea id="desc" className={textareaCls} rows={3} value={form.description} onChange={set("description")} maxLength={20000} />
      </div>
      <div className="flex gap-2 md:col-span-2">
        <Button type="submit" variant="primary" busy={busy === "create"} icon="plus">
          Create case
        </Button>
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
      </div>
    </form>
  );
}

function CaseEditor({ c, canEdit, onSaved }: { c: Case; canEdit: boolean; onSaved: () => Promise<void> }) {
  const toast = useToast();
  const { busy, run } = useAction();
  const [form, setForm] = useState({ title: c.title, description: c.description, status: c.status, priority: c.priority, conclusions: c.conclusions });
  const [rebuilt, setRebuilt] = useState<Record<string, number> | null>(null);
  useEffect(() => {
    setForm({ title: c.title, description: c.description, status: c.status, priority: c.priority, conclusions: c.conclusions });
  }, [c]);
  useEffect(() => setRebuilt(null), [c.id]);
  const dirty =
    form.title !== c.title || form.description !== c.description || form.status !== c.status || form.priority !== c.priority || form.conclusions !== c.conclusions;

  async function save() {
    try {
      await run("save", () => api.patch(`/api/cases/${c.id}`, form));
      toast.success("Case updated (recorded in the audit ledger)");
      await onSaved();
    } catch (e) {
      toast.error(e);
    }
  }

  async function rebuild() {
    try {
      const r = await run("rebuild", () => api.post<Record<string, number>>(`/api/cases/${c.id}/rebuild`));
      setRebuilt(r);
      toast.success("Reconstruction complete");
      await onSaved();
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <Panel
      title={<span className="font-mono normal-case tracking-normal">{c.case_number}</span>}
      subtitle={`Created ${formatUtc(c.created_at)} UTC · updated ${formatUtc(c.updated_at)} UTC`}
      actions={
        canEdit && (
          <>
            <Button size="sm" icon="refresh" busy={busy === "rebuild"} onClick={rebuild} title="Rebuild timeline, correlations and IOCs from stored analysis results">
              Re-run reconstruction
            </Button>
            <Button size="sm" variant="primary" busy={busy === "save"} disabled={!dirty} onClick={save}>
              Save changes
            </Button>
          </>
        )
      }
    >
      {rebuilt && (
        <div className="mb-3 rounded-md border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm text-emerald-200">
          Reconstructed: {rebuilt.timeline_events} timeline events · {rebuilt.correlations} correlations · {rebuilt.iocs} indicators
        </div>
      )}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
        <div className="md:col-span-2">
          <Label htmlFor="et">Title</Label>
          <input id="et" className={inputCls} value={form.title} disabled={!canEdit} onChange={(e) => setForm({ ...form, title: e.target.value })} maxLength={255} />
        </div>
        <div>
          <Label htmlFor="es">Status</Label>
          <select id="es" className={selectCls} value={form.status} disabled={!canEdit} onChange={(e) => setForm({ ...form, status: e.target.value as Case["status"] })}>
            {["open", "analysis", "reporting", "closed"].map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </select>
        </div>
        <div>
          <Label htmlFor="ep">Priority</Label>
          <select id="ep" className={selectCls} value={form.priority} disabled={!canEdit} onChange={(e) => setForm({ ...form, priority: e.target.value as Case["priority"] })}>
            {["low", "medium", "high", "critical"].map((s) => (
              <option key={s} value={s}>
                {titleCase(s)}
              </option>
            ))}
          </select>
        </div>
        <div className="md:col-span-4">
          <Label htmlFor="ed">Incident description</Label>
          <textarea id="ed" className={textareaCls} rows={4} value={form.description} disabled={!canEdit} onChange={(e) => setForm({ ...form, description: e.target.value })} />
        </div>
        <div className="md:col-span-4">
          <Label htmlFor="ec">Analyst conclusions</Label>
          <p className="mb-1.5 text-xs text-ink-400">Separate confirmed facts from hypotheses. Included verbatim in generated reports.</p>
          <textarea id="ec" className={cx(textareaCls, "font-mono text-[12.5px] leading-relaxed")} rows={14} value={form.conclusions} disabled={!canEdit} onChange={(e) => setForm({ ...form, conclusions: e.target.value })} />
        </div>
      </div>
      <div className="mt-4">
        <KV
          rows={[
            ["Organisation", c.organization || "–"],
            ["Lead", c.lead_investigator ?? "–"],
            ["Data", c.is_synthetic ? <Badge tone="warn">Simulated training dataset</Badge> : "Case evidence"],
          ]}
        />
      </div>
    </Panel>
  );
}

export default function CasesPage() {
  const { cases, caseId, select, refresh, loading } = useCase();
  const { can } = useAuth();
  const [creating, setCreating] = useState(false);
  const current = cases.find((c) => c.id === caseId) ?? null;

  return (
    <div>
      <PageHeader
        title="Investigations"
        description="Cases group evidence, analysis results, the reconstructed timeline and reports. Every change is written to the audit ledger."
        actions={can("investigator") && !creating && (
          <Button variant="primary" icon="plus" onClick={() => setCreating(true)}>
            New case
          </Button>
        )}
      />
      {creating && (
        <Panel title="New investigation" className="mb-4">
          <CreateCaseForm
            onCancel={() => setCreating(false)}
            onCreated={async (c) => {
              setCreating(false);
              await refresh();
              select(c.id);
            }}
          />
        </Panel>
      )}
      <Panel title="Case register" bodyClass="p-0" className="mb-4">
        {loading ? (
          <Loading />
        ) : !cases.length ? (
          <div className="p-4">
            <Empty>No cases yet.</Empty>
          </div>
        ) : (
          <TableWrap>
            <table className={tableCls}>
              <thead>
                <tr>
                  {["Case", "Title", "Status", "Priority", "Lead", "Evidence", "Findings", "Correlations", "IOCs", "Created (UTC)"].map((h) => (
                    <th key={h} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.id} className={cx(trCls, "cursor-pointer", c.id === caseId && "bg-accent-500/5")} onClick={() => select(c.id)}>
                    <td className={cx(tdCls, "whitespace-nowrap font-mono text-[12.5px] text-accent-400")}>{c.case_number}</td>
                    <td className={cx(tdCls, "min-w-[240px]")}>
                      {c.title} {c.is_synthetic && <Badge tone="warn">simulated</Badge>}
                    </td>
                    <td className={tdCls}>
                      <Badge tone="info">{titleCase(c.status)}</Badge>
                    </td>
                    <td className={tdCls}>
                      <SeverityChip severity={c.priority} />
                    </td>
                    <td className={cx(tdCls, "whitespace-nowrap")}>{c.lead_investigator ?? "–"}</td>
                    {(["evidence", "findings", "correlations", "iocs"] as const).map((k) => (
                      <td key={k} className={cx(tdCls, "text-right font-mono tabular-nums")}>
                        {c.counts?.[k] ?? 0}
                      </td>
                    ))}
                    <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(c.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>
      {current && <CaseEditor c={current} canEdit={can("investigator")} onSaved={refresh} />}
    </div>
  );
}
