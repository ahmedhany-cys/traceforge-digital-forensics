import { api } from "../api/client";
import type { Report } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { useCase } from "../auth/CaseContext";
import { Icon } from "../components/Icon";
import { useToast } from "../components/Toast";
import { Badge, Button, cx, Empty, ErrorBox, Hash, Loading, PageHeader, Panel, tableCls, TableWrap, tdCls, thCls, trCls } from "../components/ui";
import { formatBytes, formatUtc } from "../lib/format";
import { useAction, useApi } from "../lib/hooks";

const SECTIONS = [
  "Investigation information & incident description",
  "Evidence inventory with SHA-256 / SHA-1 / MD5",
  "Acquisition records from the audit ledger",
  "Integrity verification (re-hashed at generation) and ledger verification",
  "Malware static analysis and YARA matches",
  "Windows event findings and browser artifacts",
  "Network / file findings and IOC inventory",
  "Reconstructed timeline and correlated sequences",
  "Findings separated into confirmed, suspicious, informational, hypotheses",
  "Analyst conclusions, limitations and uncertainties",
];

export default function ReportsPage() {
  const { caseId } = useCase();
  const { can } = useAuth();
  const toast = useToast();
  const { busy, run } = useAction();
  const list = useApi<Report[]>(caseId ? `/api/cases/${caseId}/reports` : null);
  const reports = list.data ?? [];
  const contentHashes = new Set(reports.map((r) => r.content_sha256));

  async function generate(format: "pdf" | "json") {
    try {
      const r = await run(format, () => api.post<Report>(`/api/cases/${caseId}/reports`, { format }));
      toast.success(`${r.id} generated (${format.toUpperCase()}, ${formatBytes(r.size_bytes)})`);
      list.reload();
    } catch (e) {
      toast.error(e);
    }
  }

  return (
    <div>
      <PageHeader
        title="Forensic Reports"
        description="Reports are generated from stored investigation data only. Evidence is re-verified at generation time and the ledger head hash is embedded."
        actions={
          can("investigator") && (
            <>
              <Button variant="primary" icon="reports" busy={busy === "pdf"} disabled={!!busy} onClick={() => generate("pdf")}>
                Generate PDF
              </Button>
              <Button icon="reports" busy={busy === "json"} disabled={!!busy} onClick={() => generate("json")}>
                Generate JSON
              </Button>
            </>
          )
        }
      />
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
        <Panel title={`Generated reports (${reports.length})`} className="xl:col-span-2" bodyClass="p-0">
          <ErrorBox error={list.error} onRetry={list.reload} />
          {list.loading && !list.data ? (
            <Loading />
          ) : reports.length ? (
            <TableWrap>
              <table className={tableCls}>
                <thead>
                  <tr>
                    {["Report", "Format", "Generated (UTC)", "By", "Size", "File SHA-256", "Content SHA-256", ""].map((h, i) => (
                      <th key={i} className={thCls}>
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {reports.map((r) => (
                    <tr key={r.id} className={trCls}>
                      <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs text-accent-400")}>{r.id}</td>
                      <td className={tdCls}>
                        <Badge tone={r.format === "pdf" ? "danger" : "info"}>{r.format.toUpperCase()}</Badge>
                      </td>
                      <td className={cx(tdCls, "whitespace-nowrap font-mono text-xs")}>{formatUtc(r.generated_at)}</td>
                      <td className={tdCls}>{r.generated_by}</td>
                      <td className={cx(tdCls, "whitespace-nowrap text-right font-mono text-xs")}>{formatBytes(r.size_bytes)}</td>
                      <td className={tdCls}>
                        <Hash value={r.sha256} keep={6} />
                      </td>
                      <td className={tdCls}>
                        <Hash value={r.content_sha256} keep={6} />
                      </td>
                      <td className={tdCls}>
                        <a
                          href={`/api/reports/${r.id}/download`}
                          className="inline-flex items-center gap-1 rounded-md border border-ink-600 bg-ink-800 px-2 py-1 text-xs text-ink-100 hover:bg-ink-700"
                        >
                          <Icon name="download" className="h-3.5 w-3.5" /> Download
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          ) : (
            <div className="p-4">
              <Empty>No reports generated for this case yet.</Empty>
            </div>
          )}
        </Panel>
        <div className="space-y-4">
          <Panel title="Reproducibility">
            <p className="text-sm text-ink-300">
              The <b className="text-ink-100">content SHA-256</b> covers every analytical section of a report. Reports generated from the same investigation state
              produce the same content hash — regardless of format or generation time — so a reviewer can confirm a report reflects the stored analysis.
            </p>
            {reports.length > 1 && (
              <div className={cx("mt-3 rounded-md border px-3 py-2 text-xs", contentHashes.size === 1 ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-200" : "border-ink-600 text-ink-300")}>
                {contentHashes.size === 1
                  ? `All ${reports.length} reports share one content hash: the investigation state has not changed between them.`
                  : `${contentHashes.size} distinct content hashes across ${reports.length} reports: the analysis or conclusions changed between generations.`}
              </div>
            )}
            <p className="mt-3 text-xs text-ink-400">The file SHA-256 differs between generations because it also covers generation metadata (time, report ID).</p>
          </Panel>
          <Panel title="Report contents">
            <ul className="space-y-1.5 text-sm text-ink-300">
              {SECTIONS.map((s) => (
                <li key={s} className="flex gap-2">
                  <Icon name="check" className="mt-0.5 h-4 w-4 shrink-0 text-accent-400" />
                  {s}
                </li>
              ))}
            </ul>
          </Panel>
        </div>
      </div>
    </div>
  );
}
