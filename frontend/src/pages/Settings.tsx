import { useEffect, useState, type FormEvent } from "react";
import { api } from "../api/client";
import type { Role, User } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useToast } from "../components/Toast";
import {
  Badge, Button, cx, Empty, ErrorBox, inputCls, KV, Label, Loading, Mono, PageHeader, Panel, selectCls, SeverityChip, tableCls, TableWrap, Tabs, tdCls,
  textareaCls, thCls, trCls,
} from "../components/ui";
import { formatBytes, formatUtc, titleCase } from "../lib/format";
import { useAction, useApi } from "../lib/hooks";

interface SettingsResp {
  values: {
    assumed_timezone: string;
    correlation_window_minutes: number;
    large_transfer_bytes: number;
    sensitive_path_keywords: string[];
    internal_domains: string[];
  };
  descriptions: Record<string, string>;
  static: Record<string, string | number>;
}

interface RulesResp {
  yara: { files: string[]; errors: string[]; engine: string; rules: { name: string; file: string; id: string; description: string; severity: string; explanation: string }[] };
  windows_events: { id: string; title: string; event_ids: number[]; severity: string; classification: string; confidence: string; description: string; rationale: string; prerequisites?: string; mitre?: string[] }[];
  correlation: { id: string; title: string; severity: string; description: string; steps: string[] }[];
  artifact: { id: string; source: string; title: string; severity: string }[];
}

function GeneralSettings() {
  const { can } = useAuth();
  const toast = useToast();
  const { busy, run } = useAction();
  const s = useApi<SettingsResp>("/api/settings");
  const [form, setForm] = useState({ tz: "", window: "", bytes: "", keywords: "", domains: "" });
  const editable = can("admin");

  useEffect(() => {
    if (!s.data) return;
    const v = s.data.values;
    setForm({
      tz: v.assumed_timezone,
      window: String(v.correlation_window_minutes),
      bytes: String(v.large_transfer_bytes),
      keywords: v.sensitive_path_keywords.join("\n"),
      domains: v.internal_domains.join("\n"),
    });
  }, [s.data]);

  async function save(e: FormEvent) {
    e.preventDefault();
    const lines = (t: string) => t.split("\n").map((x) => x.trim()).filter(Boolean);
    try {
      const r = await run("save", () =>
        api.put<{ note: string }>("/api/settings", {
          values: {
            assumed_timezone: form.tz.trim(),
            correlation_window_minutes: Number(form.window),
            large_transfer_bytes: Number(form.bytes),
            sensitive_path_keywords: lines(form.keywords),
            internal_domains: lines(form.domains),
          },
        }),
      );
      toast.success(`Settings saved. ${r.note}`);
      s.reload();
    } catch (err) {
      toast.error(err);
    }
  }

  if (s.loading && !s.data) return <Loading />;
  if (s.error) return <ErrorBox error={s.error} onRetry={s.reload} />;
  const d = s.data?.descriptions ?? {};
  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <Panel title="Analysis settings" subtitle={editable ? "Changes are validated server-side and recorded in the audit ledger" : "Read-only: administrator role required to edit"} className="xl:col-span-2">
        <form onSubmit={save} className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <div>
            <Label htmlFor="tz">Assumed timezone</Label>
            <input id="tz" className={cx(inputCls, "font-mono")} value={form.tz} disabled={!editable} onChange={(e) => setForm({ ...form, tz: e.target.value })} />
            <p className="mt-1 text-xs text-ink-400">{d.assumed_timezone}</p>
          </div>
          <div>
            <Label htmlFor="win">Correlation window (minutes)</Label>
            <input id="win" type="number" min={5} className={cx(inputCls, "font-mono")} value={form.window} disabled={!editable} onChange={(e) => setForm({ ...form, window: e.target.value })} />
            <p className="mt-1 text-xs text-ink-400">{d.correlation_window_minutes}</p>
          </div>
          <div>
            <Label htmlFor="bytes">Large transfer threshold (bytes)</Label>
            <input id="bytes" type="number" min={1024} className={cx(inputCls, "font-mono")} value={form.bytes} disabled={!editable} onChange={(e) => setForm({ ...form, bytes: e.target.value })} />
            <p className="mt-1 text-xs text-ink-400">
              {formatBytes(Number(form.bytes) || 0)} · {d.large_transfer_bytes}
            </p>
          </div>
          <div />
          <div>
            <Label htmlFor="kw">Sensitive path keywords (one per line)</Label>
            <textarea id="kw" rows={5} className={cx(textareaCls, "font-mono text-xs")} value={form.keywords} disabled={!editable} onChange={(e) => setForm({ ...form, keywords: e.target.value })} />
            <p className="mt-1 text-xs text-ink-400">{d.sensitive_path_keywords}</p>
          </div>
          <div>
            <Label htmlFor="dom">Internal domains (one per line)</Label>
            <textarea id="dom" rows={5} className={cx(textareaCls, "font-mono text-xs")} value={form.domains} disabled={!editable} onChange={(e) => setForm({ ...form, domains: e.target.value })} />
            <p className="mt-1 text-xs text-ink-400">{d.internal_domains}</p>
          </div>
          {editable && (
            <div className="md:col-span-2">
              <Button type="submit" variant="primary" busy={busy === "save"}>
                Save settings
              </Button>
            </div>
          )}
        </form>
      </Panel>
      <Panel title="Platform limits" subtitle="Set via environment variables at deployment">
        <KV
          rows={[
            ["Environment", String(s.data?.static.environment)],
            ["Max evidence size", formatBytes(Number(s.data?.static.max_upload_bytes))],
            ["Files per request", String(s.data?.static.max_files_per_upload)],
            ["Session lifetime", `${s.data?.static.session_ttl_minutes} min`],
            ["Idle timeout", `${s.data?.static.session_idle_minutes} min`],
          ]}
        />
      </Panel>
    </div>
  );
}

function UsersAdmin() {
  const { user: me } = useAuth();
  const toast = useToast();
  const { busy, run } = useAction();
  const users = useApi<User[]>("/api/users");
  const [form, setForm] = useState({ username: "", display_name: "", role: "investigator" as Role, password: "" });

  async function create(e: FormEvent) {
    e.preventDefault();
    try {
      await run("create", () => api.post<User>("/api/users", form));
      toast.success(`User ${form.username} created`);
      setForm({ username: "", display_name: "", role: "investigator", password: "" });
      users.reload();
    } catch (err) {
      toast.error(err);
    }
  }
  async function patch(u: User, body: Partial<Pick<User, "role" | "is_active">>) {
    try {
      await run(`u${u.id}`, () => api.patch<User>(`/api/users/${u.id}`, body));
      toast.success(`Updated ${u.username}`);
      users.reload();
    } catch (err) {
      toast.error(err);
    }
  }

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
      <Panel title="Accounts" className="xl:col-span-2" bodyClass="p-0">
        <ErrorBox error={users.error} onRetry={users.reload} />
        {users.loading && !users.data ? (
          <Loading />
        ) : (
          <TableWrap>
            <table className={tableCls}>
              <thead>
                <tr>
                  {["Username", "Display name", "Role", "Status", "Last login (UTC)", ""].map((h, i) => (
                    <th key={i} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {(users.data ?? []).map((u) => (
                  <tr key={u.id} className={trCls}>
                    <td className={cx(tdCls, "font-mono")}>{u.username}</td>
                    <td className={tdCls}>{u.display_name}</td>
                    <td className={tdCls}>
                      <select
                        className={cx(selectCls, "h-7 w-36 text-xs")}
                        value={u.role}
                        disabled={u.id === me?.id || busy === `u${u.id}`}
                        onChange={(e) => void patch(u, { role: e.target.value as Role })}
                        aria-label={`Role for ${u.username}`}
                      >
                        {["viewer", "investigator", "admin"].map((r) => (
                          <option key={r} value={r}>
                            {r}
                          </option>
                        ))}
                      </select>
                    </td>
                    <td className={tdCls}>{u.is_active ? <Badge tone="ok">active</Badge> : <Badge tone="danger">disabled</Badge>}</td>
                    <td className={cx(tdCls, "font-mono text-xs")}>{formatUtc(u.last_login_at)}</td>
                    <td className={tdCls}>
                      {u.id !== me?.id && (
                        <Button size="sm" variant={u.is_active ? "ghost" : "secondary"} busy={busy === `u${u.id}`} onClick={() => patch(u, { is_active: !u.is_active })}>
                          {u.is_active ? "Disable" : "Enable"}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        )}
      </Panel>
      <Panel title="Create account">
        <form onSubmit={create} className="space-y-3">
          <div>
            <Label htmlFor="nu">Username</Label>
            <input id="nu" className={cx(inputCls, "font-mono")} value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value.toLowerCase() })} required pattern="[a-z0-9._\-]+" minLength={3} maxLength={64} />
          </div>
          <div>
            <Label htmlFor="nd">Display name</Label>
            <input id="nd" className={inputCls} value={form.display_name} onChange={(e) => setForm({ ...form, display_name: e.target.value })} required maxLength={128} />
          </div>
          <div>
            <Label htmlFor="nr">Role</Label>
            <select id="nr" className={selectCls} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
              <option value="viewer">viewer – read-only</option>
              <option value="investigator">investigator – acquire, analyse, report</option>
              <option value="admin">admin – settings and users</option>
            </select>
          </div>
          <div>
            <Label htmlFor="np">Initial password</Label>
            <input id="np" type="password" autoComplete="new-password" className={inputCls} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required minLength={12} maxLength={256} />
            <p className="mt-1 text-xs text-ink-400">≥ 12 characters with three of: lowercase, uppercase, digit, symbol. Stored as Argon2id.</p>
          </div>
          <Button type="submit" variant="primary" busy={busy === "create"}>
            Create account
          </Button>
        </form>
      </Panel>
    </div>
  );
}

function RulesBrowser() {
  const r = useApi<RulesResp>("/api/rules");
  if (r.loading && !r.data) return <Loading />;
  if (r.error) return <ErrorBox error={r.error} onRetry={r.reload} />;
  if (!r.data) return null;
  const { yara, windows_events, correlation, artifact } = r.data;
  return (
    <div className="space-y-4">
      <Panel title={`YARA rules (${yara.rules.length})`} subtitle={`${yara.engine} · ${yara.files.join(", ")}`} bodyClass="p-0">
        {yara.errors.length > 0 && <div className="px-4 py-2 text-xs text-rose-300">{yara.errors.join("; ")}</div>}
        <TableWrap>
          <table className={tableCls}>
            <thead>
              <tr>
                {["ID", "Rule", "Severity", "Description / explanation"].map((h) => (
                  <th key={h} className={thCls}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {yara.rules.map((y) => (
                <tr key={y.name} className={trCls}>
                  <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{y.id}</td>
                  <td className={cx(tdCls, "font-mono text-xs text-ink-100")}>{y.name}</td>
                  <td className={tdCls}>
                    <SeverityChip severity={y.severity} />
                  </td>
                  <td className={tdCls}>
                    <div className="text-ink-100">{y.description}</div>
                    <div className="text-xs text-ink-400">{y.explanation}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Panel>
      <Panel title={`Windows event rules (${windows_events.length})`} bodyClass="p-0">
        <TableWrap>
          <table className={tableCls}>
            <thead>
              <tr>
                {["ID", "Title", "Event IDs", "Severity", "Class", "Rationale / prerequisites", "ATT&CK"].map((h) => (
                  <th key={h} className={thCls}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {windows_events.map((w) => (
                <tr key={w.id} className={trCls}>
                  <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{w.id}</td>
                  <td className={tdCls}>{w.title}</td>
                  <td className={cx(tdCls, "font-mono text-xs")}>{w.event_ids.join(", ")}</td>
                  <td className={tdCls}>
                    <SeverityChip severity={w.severity} />
                  </td>
                  <td className={cx(tdCls, "text-xs")}>{w.classification}</td>
                  <td className={cx(tdCls, "max-w-[460px] text-xs text-ink-300")}>
                    {w.rationale}
                    {w.prerequisites && <div className="mt-1 text-amber-200/80">Requires: {w.prerequisites}</div>}
                  </td>
                  <td className={cx(tdCls, "font-mono text-xs")}>{(w.mitre ?? []).join(" ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </TableWrap>
      </Panel>
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <Panel title={`Correlation rules (${correlation.length})`}>
          <ul className="space-y-3">
            {correlation.map((c) => (
              <li key={c.id}>
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityChip severity={c.severity} />
                  <Mono className="text-ink-400">{c.id}</Mono>
                  <span className="text-sm text-ink-100">{c.title}</span>
                </div>
                <p className="mt-0.5 text-xs text-ink-400">{c.description}</p>
                <div className="mt-1 flex flex-wrap items-center gap-1 text-[11px]">
                  {c.steps.map((s, i) => (
                    <span key={s} className="flex items-center gap-1">
                      {i > 0 && <span className="text-ink-500">→</span>}
                      <Badge>{titleCase(s)}</Badge>
                    </span>
                  ))}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
        <Panel title={`Browser, network & file rules (${artifact.length})`} bodyClass="p-0">
          <TableWrap>
            <table className={tableCls}>
              <thead>
                <tr>
                  {["ID", "Source", "Title", "Severity"].map((h) => (
                    <th key={h} className={thCls}>
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {artifact.map((a) => (
                  <tr key={a.id} className={trCls}>
                    <td className={cx(tdCls, "font-mono text-xs")}>{a.id}</td>
                    <td className={tdCls}>{a.source}</td>
                    <td className={tdCls}>{a.title}</td>
                    <td className={tdCls}>
                      <SeverityChip severity={a.severity} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        </Panel>
      </div>
    </div>
  );
}

const SAMPLE_RULE = `rule Example_Test_Rule
{
    meta:
        id = "LOCAL-001"
        description = "Example rule"
        severity = "low"
        explanation = "Matches a harmless test string."
    strings:
        $a = "EXAMPLE-TEST-STRING"
    condition:
        $a
}`;

function YaraValidator() {
  const { can } = useAuth();
  const { busy, run } = useAction();
  const toast = useToast();
  const [source, setSource] = useState(SAMPLE_RULE);
  const [result, setResult] = useState<{ valid: boolean; error: string | null; rules: { name: string; meta: Record<string, unknown>; tags: string[] }[] } | null>(null);
  if (!can("investigator")) return <Empty>Rule validation requires the investigator role.</Empty>;
  async function validate() {
    try {
      setResult(await run("v", () => api.post("/api/rules/yara/validate", { source })));
    } catch (e) {
      toast.error(e);
    }
  }
  return (
    <Panel title="YARA rule validator" subtitle="Compiles the rule with yara-python and checks required metadata (id, description, severity, explanation). Nothing is saved or scanned.">
      <textarea className={cx(textareaCls, "font-mono text-xs leading-relaxed")} rows={16} value={source} onChange={(e) => setSource(e.target.value)} spellCheck={false} aria-label="YARA rule source" />
      <div className="mt-3 flex items-center gap-3">
        <Button variant="primary" busy={busy === "v"} onClick={validate}>
          Compile &amp; validate
        </Button>
        {result && (result.valid ? <Badge tone="ok">valid – {result.rules.length} rule(s)</Badge> : <Badge tone="danger">invalid</Badge>)}
      </div>
      {result && !result.valid && <pre className="mt-3 whitespace-pre-wrap rounded-md border border-rose-500/40 bg-rose-950/30 p-3 font-mono text-xs text-rose-200">{result.error}</pre>}
      {result?.valid && (
        <ul className="mt-3 space-y-1 text-xs text-ink-300">
          {result.rules.map((r) => (
            <li key={r.name}>
              <Mono className="text-ink-100">{r.name}</Mono> · {String(r.meta.id)} · severity {String(r.meta.severity)}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

type Tab = "general" | "users" | "rules" | "yara";

export default function SettingsPage() {
  const { can } = useAuth();
  const [tab, setTab] = useState<Tab>("general");
  const items: { id: Tab; label: string }[] = [
    { id: "general", label: "Analysis settings" },
    ...(can("admin") ? [{ id: "users" as Tab, label: "Users & roles" }] : []),
    { id: "rules", label: "Detection rules" },
    { id: "yara", label: "YARA validator" },
  ];
  return (
    <div>
      <PageHeader title="System Settings" description="Analysis parameters, accounts, and the transparent rule sets that drive every detection." />
      <Tabs value={tab} onChange={setTab} items={items} />
      {tab === "general" && <GeneralSettings />}
      {tab === "users" && can("admin") && <UsersAdmin />}
      {tab === "rules" && <RulesBrowser />}
      {tab === "yara" && <YaraValidator />}
    </div>
  );
}
