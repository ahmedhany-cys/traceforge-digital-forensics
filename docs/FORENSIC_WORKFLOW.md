# Forensic Workflow

This walkthrough follows the synthetic **Meridian Financial Services** case (`MFS-IR-2026-0147`). All data is simulated.

## 1. Open or create a case

*Investigations* → **New case** (case number, title, organisation, description, priority). Case creation is ledgered. Analyst conclusions are edited on the same page and are stored with the case (they feed the report).

## 2. Acquire evidence

*Evidence Vault* → drop files (one request per file), optionally with the **source host** (used to attribute host-less artifacts such as browser history) and a source description.

For each file TraceForge:

1. streams it to a private temporary file while computing SHA-256, SHA-1 and MD5 and enforcing the size limit;
2. identifies the type from content and checks the extension is consistent (`.evtx` must be EVTX, `.exe` must be PE, …);
3. rejects exact duplicates within the case (HTTP 409, pointing at the existing evidence ID) and flags cross-case duplicates;
4. moves it into the vault under a random name, makes it read-only and re-hashes the stored copy;
5. writes an `evidence_acquired` ledger record (hashes, detected type, actor, UTC time).

Rejections (`evidence_rejected`, `duplicate_evidence_rejected`) are ledgered too.

## 3. Analyse

Analysis runs automatically after acquisition (and on demand via **Re-analyze**). It refuses to run if the stored hash no longer matches, and re-verifies the hash afterwards to show analysis did not change the evidence.

| Evidence | Analyzer | Output |
|---|---|---|
| `.evtx` | python-evtx + defusedxml | Parsed events (ID, provider, channel, computer, UTC time + original, EventData/UserData), header/chunk CRC status, per-record errors, rule findings |
| Chromium `History` | read-only SQLite on a verified private copy | Visits (URL, title, time, count, transition), downloads (path, URL chain, referrer, size, state, danger type, hash) |
| CSV / JSON / text logs | generic parsers | Normalised records (network, DNS, file, generic) with UTC + original timestamps and line-level errors |
| PE | pefile + entropy + strings | Headers, sections, imports, suspicious APIs, categorised strings, indicators, assessment |
| everything | YARA | Rule matches with matched strings and offsets |

## 4. Reconstruct

Case reconstruction (automatic after upload; **Re-run reconstruction** on the case page) rebuilds:

* the **timeline** – every timestamped record from every source, normalised to UTC, with original value, source evidence and record reference, severity inherited from findings and extracted entities (host, PID, parent PID, image, file, hash, destination, bytes);
* **correlations** – sequence hypotheses with link reasons and caveats;
* the **IOC inventory** – indicators with namespace classification, assessment and every occurrence.

## 5. What the Meridian case shows

The reconstruction (all times UTC, 2026-10-14):

| Time | Source | Event |
|---|---|---|
| 12:31 | Security 4624 | `jmorales` logs on interactively |
| 12:58 | Security 4625 ×3 | Failed logons for `administrator` from WS-HR-015 (unrelated; not linked to any sequence) |
| 13:41:45 | Chrome history | `Q3_Vendor_Invoice.pdf.exe` downloaded from `files.invoice-portal.example`, referrer webmail, danger type `user_validated` |
| 13:41:49 | EDR | File written; SHA-256 equals the acquired sample |
| 13:43:10 | Security 4688 | Sample executed from Downloads (PID 0x1A2C) |
| 13:43:12–14 | DNS / firewall / 5156 | `cdn.meridian-sync.example` → 203.0.113.77:443 |
| 13:43:31 | 4688 + 4104 | Hidden, encoded PowerShell (decoded: create `C:\ProgramData\MSync`, copy sample to `msync.exe`) |
| 13:44 | 4688, 4698, 7045, 4720, 4732 | `msync.exe` launched; scheduled task, service, new account `svc_msync` added to Administrators |
| 13:52–13:55 | 4663 + EDR | `msync.exe` (in the sample's process lineage) reads four files in `Documents\Confidential` |
| 13:57 | 4688 + 4104 + EDR | PowerShell archives the folder to `q3_archive.zip` |
| 13:58:06 | firewall + 5156 + DNS | 48,213,904 bytes sent to 203.0.113.77:443 (`upload.meridian-sync.example`) |
| 14:03 | 4104, System 104, EDR | `Windows PowerShell` log cleared; archive deleted |
| 14:15 | Chrome history | User visits the intranet "Report a suspicious email" page |
| 14:22 | firewall | IR block rule denies 203.0.113.77 |

`CORR-002` links the download, file write (same SHA-256), execution (same name), confidential-file access (PID lineage) and transfer (destination hard-coded in the analysed binary) with **high** confidence. `CORR-004` (archive → transfer) is **low** confidence because only host and time connect the two steps — the report says so.

What the evidence **cannot** show: the content of the transfer (no packet capture/proxy body), whether the archive contained exactly the four documents (archive deleted; size and timing are consistent), or activity outside the logged audit categories.

## 6. Verify and preserve

* *Evidence Vault* → **Verify integrity** / **Verify all** re-hash vault copies (history on the evidence page and *Chain of Custody*).
* *Chain of Custody* → **Verify ledger** walks the whole hash chain and reports the head hash. Record it externally.

## 7. Report

*Reports* → **Generate PDF** / **Generate JSON**. Generation re-verifies every evidence item and the ledger, then builds:

* deterministic **content** (case, inventory, hashes, acquisition records, malware analysis, YARA, Windows findings, browser artifacts, network/file findings, IOCs, timeline, correlations, findings by classification, analyst conclusions, limitations) → `content_sha256`;
* an **integrity snapshot** and **metadata** (time-dependent).

Regenerating from the same state yields the same `content_sha256` (tested). Report generation and downloads are ledgered.
