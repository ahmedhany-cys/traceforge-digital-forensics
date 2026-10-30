# Testing and Quality Assurance

## How to run

```bash
cd backend
../.venv/bin/python -m pytest                       # backend suite
../.venv/bin/python -m pytest --cov=app             # with coverage
../.venv/bin/bandit -q -r app                       # static security analysis
../.venv/bin/pip-audit -r requirements.txt          # dependency vulnerabilities

cd ../frontend
npm test            # Vitest + Testing Library
npm run lint        # TypeScript type-check
npm run build       # type-check + production build
npm audit           # dependency vulnerabilities
```

CI (`.github/workflows/ci.yml`) runs the same commands on every push and pull request.

## Results for this release

Recorded on 2026-10-30 (macOS, Python 3.12.16, Node 26.12.1):

| Check | Result |
|---|---|
| Backend tests (pytest) | **97 passed**, 0 failed (~10 s) |
| Backend coverage | **89 %** of 3,878 statements in `app/` |
| Frontend tests (Vitest) | **18 passed**, 0 failed (4 files) |
| TypeScript (`tsc --noEmit`) | no errors |
| Production build (`vite build`) | succeeds (JS 695 kB / 201 kB gzip) |
| `bandit -r app` | **0 issues** (3 reviewed false positives annotated with `# nosec` and a justification) |
| `pip-audit -r requirements.txt` | **No known vulnerabilities** |
| `npm audit` (all dependencies) | **0 vulnerabilities** (after upgrading `react-router-dom` 6 → 7.18.5 and `vitest` 3 → 5.0.5, which the first audit flagged) |
| End-to-end browser check | All 11 sections exercised against the running app with the demo case; screenshots in `screenshots/` captured with `scripts/screenshots/capture.mjs` |

## What the backend suite covers

Tests exercise real behaviour: they parse the committed dataset files, build malformed inputs on the fly and drive the HTTP API. No test asserts a hard-coded value that the code under test merely echoes.

| Area (requirement) | Tests |
|---|---|
| SHA-256 generation | known vectors, multi-chunk streaming vs `hashlib`, manifest hashes (`test_core_primitives.py`) |
| Evidence acquisition | metadata, sanitised filenames, random storage names, ledger record (`test_api_security.py::test_acquisition_records_metadata_and_ledger`) |
| Duplicate detection | same bytes under a new name → 409 with existing ID |
| Integrity verification / tampering | match → mismatch after modification → missing after deletion; analysis refused; vault file mode 0400; pre/post-analysis checks (`test_ledger_integrity.py`) |
| Hash-linked ledger | link structure, modified content, deleted record, rewritten hash breaking the next link, API verification |
| EVTX parsing | field extraction, exact timestamps, UserData, corrupted chunk CRC, truncated and non-EVTX files, record-level errors (`test_parsers.py`) |
| Browser history | visits/downloads, WebKit conversion, danger types, original unchanged, hostile strings inert, malformed and non-Chromium SQLite |
| PE metadata, entropy | indicators on the suspicious sample, clean control sample, future compile time, truncated PE, entropy known values (`test_malware_yara_ioc.py`) |
| YARA | rule metadata validation, positive/negative test patterns, sample matches, syntax/meta/severity rejection, API validator |
| IOC extraction | refanging, normalisation, invalid IPs, file-extension pseudo-TLDs, .NET namespaces, hashes, IP range classification |
| Timestamp normalisation | Z/offset/`-0400` forms, assumed timezone with DST, epoch, implausible values, unknown zones, FILETIME/WebKit |
| Logs | CSV, JSON envelope with offsets, DNS text with bad line, JSONL errors, ragged CSV |
| Timeline reconstruction | 79 events, chronological, UTC, traceable source refs, original timestamps, filters (`test_investigation.py`) |
| Event correlation | full chain with entity/lineage/embedded-indicator links, low confidence for temporal-only links, no invented steps, window and host constraints, unrelated events excluded, deterministic rebuild |
| PDF/JSON reports | reproducible `content_sha256` across formats, required sections, integrity snapshot, PDF signature |
| Invalid / oversized files | wrong-content `.exe`, CSV as `.evtx`, ZIP, script, empty; 413 with temp cleanup; JSON body limit |
| Authentication & authorisation | cookie flags, generic failures, lockout, logout, idle expiry, CSRF, viewer read-only, admin-only settings/users, self-demotion guard |
| API error handling | 404s, path-like IDs, 422 shape, generic 500 without leaking details, security headers, audited export |
| Dataset | generator determinism vs committed manifest, cross-source consistency, only private/documentation addresses and reserved domains |
| CLI | `load-demo` (idempotent, 0600 credential file), `verify-ledger`, `create-user` policy |

## Frontend tests

`frontend/src/__tests__/`: API client (CSRF header on unsafe methods only, structured error details, multipart uploads without JSON content type), formatting helpers (bytes, UTC timestamps, gaps), timeline filtering/grouping, badges and text-only rendering of evidence strings, and the login form.

## Notes and known gaps

* The Docker image and compose file were not built in this environment (Docker unavailable).
* The frontend bundle is ~695 kB (201 kB gzip), mostly Recharts; the Vite size warning threshold is set to 900 kB in `vite.config.ts`. Code-splitting per page would reduce initial load.
* There are no automated browser (E2E) tests in CI; the end-to-end check was performed with the screenshot script and manual inspection.
