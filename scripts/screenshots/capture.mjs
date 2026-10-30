// Capture documentation screenshots from a RUNNING TraceForge instance.
//
//   TF_BASE_URL=http://127.0.0.1:8000 TF_USER=arivera TF_PASSWORD=... \
//   TF_REPORT_DIR=../../docs/sample-reports node capture.mjs
//
// Uses the locally installed Google Chrome through playwright-core (no browser
// download). Nothing here fabricates content: every image is the real UI
// rendering data served by the backend. The generated PDF/JSON reports are
// downloaded through the authenticated API and saved alongside.
import { chromium } from "playwright-core";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const BASE = process.env.TF_BASE_URL ?? "http://127.0.0.1:8000";
const OUT = resolve(process.env.TF_OUT ?? join(here, "../../screenshots"));
const REPORTS = resolve(process.env.TF_REPORT_DIR ?? join(here, "../../docs/sample-reports"));
const CHROME = process.env.TF_CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const DATASET = resolve(here, "../../dataset/meridian/evidence");
if (!process.env.TF_USER || !process.env.TF_PASSWORD) throw new Error("set TF_USER and TF_PASSWORD");
mkdirSync(OUT, { recursive: true });
mkdirSync(REPORTS, { recursive: true });

const browser = await chromium.launch({ executablePath: CHROME, headless: true });
const context = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: "dark" });
const page = await context.newPage();
const errors = [];
// 401 (session probe before login) and 409/415 (the deliberate rejected uploads) are expected.
const EXPECTED = /status of (401|409|415)/;
page.on("console", (m) => m.type() === "error" && !EXPECTED.test(m.text()) && errors.push(m.text()));
page.on("pageerror", (e) => errors.push(String(e)));

const settle = async () => {
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(600);
};
const shot = async (name) => {
  await page.screenshot({ path: join(OUT, name) });
  console.log("saved", name);
};
const go = async (path) => {
  await page.goto(BASE + path);
  await settle();
};
const scrollTo = async (text) => {
  // The app scrolls inside its main pane, so scroll the element itself to the top of its container.
  await page.getByText(text, { exact: false }).first().evaluate((el) => el.scrollIntoView({ block: "start" }));
  await page.waitForTimeout(400);
};

// --- login -----------------------------------------------------------------
await go("/");
await page.getByLabel("Username").fill(process.env.TF_USER);
await page.getByLabel("Password").fill(process.env.TF_PASSWORD);
await page.getByRole("button", { name: /sign in/i }).click();
await page.getByText("Overview").first().waitFor();
await settle();

// 1. overview
await shot("01-dashboard-overview.png");

// 2. investigation details
await go("/cases");
await shot("02-investigation-details.png");

// 3. upload & acquisition: a duplicate and a disguised file are submitted to show validation
await go("/evidence");
await page.locator("#src-host").fill("WS-FIN-042");
await page.locator("#src-desc").fill("Re-submitted during review");
await page.locator('[data-testid="evidence-input"]').setInputFiles([
  { name: "WS-FIN-042_Security.evtx", mimeType: "application/octet-stream", buffer: readFileSync(join(DATASET, "WS-FIN-042_Security.evtx")) },
  { name: "Remittance_Advice.pdf.exe", mimeType: "application/octet-stream", buffer: Buffer.from("This is plain text renamed to .exe\n".repeat(20)) },
]);
await page.getByText("rejected", { exact: false }).nth(1).waitFor({ timeout: 30000 });
await settle();
await shot("03-evidence-upload.png");

// 4. inventory
await scrollTo("Evidence inventory");
await shot("04-evidence-inventory.png");

// 5. malware analysis, 6. YARA
await go("/malware");
await shot("05-malware-analysis.png");
await scrollTo("Sections");
await shot("05b-malware-sections-imports.png");
await scrollTo("YARA scan of this sample");
await shot("06-yara-results.png");

// 7. windows events (expand a flagged PowerShell process-creation record)
await go("/events");
const psRow = page.locator("tr", { hasText: "powershell.exe" }).first();
if (await psRow.count()) {
  await psRow.click();
  await page.waitForTimeout(400);
}
await shot("07-windows-events.png");

// 8. browser forensics
await go("/browser");
await shot("08-browser-forensics.png");

// 9. timeline + correlations
await go("/timeline");
await shot("09-timeline.png");
await scrollTo("Chronology (");
await shot("09b-timeline-events.png");

// 10. IOC explorer
await go("/iocs");
await shot("10-ioc-explorer.png");

// 11/12. chain of custody + verification
await go("/custody");
await page.getByRole("button", { name: /verify ledger/i }).click();
await page.getByText(/chain intact|chain broken/i).first().waitFor({ timeout: 30000 });
await settle();
await shot("11-chain-of-custody.png");
await go("/evidence");
await page.getByRole("button", { name: /verify all/i }).click();
await page.waitForTimeout(1500);
await go("/custody");
await scrollTo("Evidence integrity verification history");
await shot("12-integrity-verification.png");

// 13/14. reports: generate PDF + JSON through the UI, download through the API
await go("/reports");
await page.getByRole("button", { name: /generate pdf/i }).click();
await page.waitForTimeout(2500);
await page.getByRole("button", { name: /generate json/i }).click();
await page.waitForTimeout(2000);
await settle();
await shot("14-reports.png");
const caseId = await page.evaluate(() => window.localStorage.getItem("traceforge.caseId"));
const reports = await (await page.request.get(`${BASE}/api/cases/${caseId}/reports`)).json();
for (const fmt of ["pdf", "json"]) {
  const r = reports.find((x) => x.format === fmt);
  const body = await (await page.request.get(`${BASE}/api/reports/${r.id}/download`)).body();
  writeFileSync(join(REPORTS, `${r.id}.${fmt}`), body);
  console.log("report", r.id, fmt, r.content_sha256);
}

await browser.close();
if (errors.length) {
  console.error("browser console errors:\n" + errors.join("\n"));
  process.exitCode = 1;
}
