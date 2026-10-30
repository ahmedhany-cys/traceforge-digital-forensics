import { Link } from "react-router-dom";
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { Dashboard } from "../api/types";
import { useCase } from "../auth/CaseContext";
import { FindingList } from "../components/FindingList";
import { Icon } from "../components/Icon";
import {
  AssessmentBadge, Badge, ClassificationBadge, ConfidenceTag, ErrorBox, Loading, PageHeader, Panel, SEV_HEX, SeverityChip, Stat, cx,
} from "../components/ui";
import { formatBytes, formatUtc, SEVERITY_ORDER, titleCase } from "../lib/format";
import { useApi } from "../lib/hooks";

export function SimulatedBanner() {
  return (
    <div className="mb-4 flex items-start gap-2.5 rounded-md border border-amber-500/40 bg-amber-500/10 px-3.5 py-2.5 text-[13px] text-amber-200">
      <Icon name="alert" className="mt-0.5 h-4 w-4 shrink-0" />
      <span>
        <b className="font-semibold">SIMULATED DATA.</b> This investigation uses a synthetic training dataset. All organisations, people, hosts,
        addresses and events are fictional.
      </span>
    </div>
  );
}

const tooltipStyle = { background: "#0f1520", border: "1px solid #263246", borderRadius: 6, fontSize: 12 };

function MiniBars({ data, color = "#3fd0c9" }: { data: Record<string, number>; color?: string }) {
  const total = Object.values(data).reduce((a, b) => a + b, 0) || 1;
  const rows = Object.entries(data).sort((a, b) => b[1] - a[1]);
  return (
    <div className="space-y-1.5">
      {rows.map(([k, v]) => (
        <div key={k} className="grid grid-cols-[120px_1fr_36px] items-center gap-2 text-xs">
          <span className="truncate text-ink-300" title={k}>
            {titleCase(k)}
          </span>
          <span className="h-2 overflow-hidden rounded-sm bg-ink-800">
            <span className="block h-full rounded-sm" style={{ width: `${(v / total) * 100}%`, background: color }} />
          </span>
          <span className="text-right font-mono tabular-nums text-ink-200">{v}</span>
        </div>
      ))}
      {!rows.length && <div className="text-xs text-ink-400">No data</div>}
    </div>
  );
}

export default function OverviewPage() {
  const { caseId } = useCase();
  const { data, error, loading, reload } = useApi<Dashboard>(caseId ? `/api/cases/${caseId}/dashboard` : null);

  if (loading && !data) return <Loading />;
  if (error) return <ErrorBox error={error} onRetry={reload} />;
  if (!data) return null;
  const c = data.case;
  const sevData = SEVERITY_ORDER.map((s) => ({ severity: s, count: data.findings_by_severity[s] ?? 0 }));
  const activity = data.activity.map((a) => ({ ...a, label: formatUtc(a.bucket, { date: false }).slice(0, 5) }));
  const integrityOk = (data.evidence_integrity.verified ?? 0) === data.evidence_total;
  const highPlus = (data.findings_by_severity.critical ?? 0) + (data.findings_by_severity.high ?? 0);

  return (
    <div>
      {c.is_synthetic && <SimulatedBanner />}
      <PageHeader
        title={`${c.case_number} · ${c.title}`}
        description={
          <>
            {c.organization} · Lead: {c.lead_investigator ?? "unassigned"} · Status <Badge tone="info">{titleCase(c.status)}</Badge> · Priority{" "}
            <SeverityChip severity={c.priority === "critical" ? "critical" : c.priority} />
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
        <Stat label="Evidence items" value={data.evidence_total} hint={formatBytes(data.evidence_bytes) + " acquired"} />
        <Stat
          label="Integrity"
          value={integrityOk ? "Verified" : "Attention"}
          tone={integrityOk ? "ok" : "danger"}
          hint={`${data.evidence_integrity.verified ?? 0}/${data.evidence_total} match · ${data.integrity_checks} checks`}
        />
        <Stat label="High / critical" value={highPlus} tone={highPlus ? "danger" : "default"} hint="suspicious + confirmed" />
        <Stat label="Rule matches" value={data.findings_by_classification.confirmed_rule_match ?? 0} tone="accent" hint="YARA + watchlist" />
        <Stat label="Correlations" value={data.correlations.length} hint="hypotheses" />
        <Stat label="Timeline events" value={data.timeline_total} hint={data.timeline_range ? `${formatUtc(data.timeline_range[0], { date: false })} → ${formatUtc(data.timeline_range[1], { date: false })} UTC` : "–"} />
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Activity over time" subtitle="Timeline events per 10-minute window, stacked by severity (UTC)" className="xl:col-span-2">
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={activity} margin={{ top: 4, right: 8, left: -18, bottom: 0 }}>
                <CartesianGrid stroke="#1b2535" vertical={false} />
                <XAxis dataKey="label" tickLine={false} axisLine={{ stroke: "#263246" }} interval="preserveStartEnd" />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(63,208,201,0.06)" }} labelFormatter={(l) => `${l} UTC`} />
                {[...SEVERITY_ORDER].reverse().map((s) => (
                  <Bar isAnimationActive={false} key={s} dataKey={s} stackId="a" fill={SEV_HEX[s]} maxBarSize={28} />
                ))}
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Findings by severity" subtitle="Suspicious observations and confirmed rule matches">
          <div className="h-60">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={sevData} layout="vertical" margin={{ top: 4, right: 16, left: 4, bottom: 0 }}>
                <CartesianGrid stroke="#1b2535" horizontal={false} />
                <XAxis type="number" allowDecimals={false} tickLine={false} axisLine={false} />
                <YAxis type="category" dataKey="severity" tickLine={false} axisLine={false} width={64} tickFormatter={(s: string) => s.toUpperCase()} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(63,208,201,0.06)" }} />
                <Bar isAnimationActive={false} dataKey="count" radius={[0, 3, 3, 0]} maxBarSize={22}>
                  {sevData.map((d) => (
                    <Cell key={d.severity} fill={SEV_HEX[d.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel
          title="Correlated sequences"
          subtitle="Hypotheses linking events across evidence sources"
          className="xl:col-span-2"
          actions={
            <Link to="/timeline" className="text-xs text-accent-400 hover:underline">
              Open timeline →
            </Link>
          }
          bodyClass="p-0"
        >
          {data.correlations.length ? (
            <ul className="divide-y divide-ink-800">
              {data.correlations.map((co) => (
                <li key={co.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-2.5">
                  <SeverityChip severity={co.severity} />
                  <span className="font-mono text-xs text-ink-400">{co.rule_id}</span>
                  <span className="min-w-0 flex-1 basis-[240px] text-[13.5px] text-ink-100">{co.title}</span>
                  <span className="font-mono text-xs text-ink-400">
                    {formatUtc(co.start_time, { date: false })} → {formatUtc(co.end_time, { date: false })}
                  </span>
                  <span className="text-xs text-ink-400">{co.steps.length} steps</span>
                  <ConfidenceTag value={co.confidence} />
                  <ClassificationBadge classification="hypothesis" />
                </li>
              ))}
            </ul>
          ) : (
            <div className="px-4 py-6 text-sm text-ink-400">No correlated sequences.</div>
          )}
        </Panel>
        <Panel title="Indicators of compromise">
          <div className="mb-3 flex flex-wrap gap-2">
            {Object.entries(data.iocs_by_assessment).map(([k, v]) => (
              <span key={k} className="inline-flex items-center gap-1.5">
                <AssessmentBadge assessment={k} />
                <span className="font-mono text-sm text-ink-200">{v}</span>
              </span>
            ))}
          </div>
          <MiniBars data={data.iocs_by_type} color="#5b8def" />
          <Link to="/iocs" className="mt-3 inline-block text-xs text-accent-400 hover:underline">
            Explore indicators →
          </Link>
        </Panel>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title="Highest-priority findings" className="xl:col-span-2" actions={<span className="text-xs text-ink-400">click a finding for rationale</span>}>
          <FindingList findings={data.top_findings} />
        </Panel>
        <div className="space-y-4">
          <Panel title="Findings by source">
            <MiniBars data={data.findings_by_source} color="#f59e0b" />
          </Panel>
          <Panel title="Evidence by type">
            <MiniBars data={data.evidence_by_type} />
            <div className="mt-3 flex flex-wrap gap-1.5 text-xs">
              {Object.entries(data.analysis_status).map(([k, v]) => (
                <Badge key={k} tone={k === "complete" ? "ok" : k === "error" ? "danger" : "neutral"}>
                  analysis {k}: {v}
                </Badge>
              ))}
            </div>
          </Panel>
          <Panel title="Classification legend" bodyClass="p-3">
            <div className={cx("grid gap-1.5 text-xs text-ink-300")}>
              <div className="flex items-center gap-2"><ClassificationBadge classification="confirmed_rule_match" /> rule condition provably satisfied</div>
              <div className="flex items-center gap-2"><ClassificationBadge classification="suspicious" /> consistent with malicious activity; benign explanations exist</div>
              <div className="flex items-center gap-2"><ClassificationBadge classification="informational" /> context only</div>
              <div className="flex items-center gap-2"><ClassificationBadge classification="hypothesis" /> correlation – requires validation</div>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
