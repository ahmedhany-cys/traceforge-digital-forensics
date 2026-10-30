# Meridian Financial Services – synthetic incident scenario

> **SIMULATED DATA.** Every artifact in this folder was produced by `dataset/generator/generate.py`. The organisation, people, hosts, accounts and events are fictional. External IP addresses come from the RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and all domains use the reserved `.example` TLD (RFC 2606). The executables are inert: their code section is `xor eax, eax; ret` and they contain the marker `TRACEFORGE-SYNTHETIC-TEST-SAMPLE`.

## Situation

Meridian Financial Services' security team received an alert about finance workstation **WS-FIN-042** (`10.20.4.42`, user `MERIDIANFS\jmorales`) on **2026-10-14**. The IR team exported the workstation's event logs and Chrome history, pulled firewall, DNS and EDR telemetry, and recovered an executable from the user's Downloads folder.

## Ground-truth timeline (UTC)

| Time | Activity | Recorded in |
|---|---|---|
| 12:31:04 | Interactive logon by jmorales | Security 4624 |
| 12:32–12:40 | Chrome started, intranet and news browsing, budget template downloaded and opened in Excel | Security 4688, Chrome history, EDR, firewall, DNS |
| 12:58:40–49 | Three failed network logons for `administrator` from WS-HR-015 (10.20.9.15) – **unrelated noise** | Security 4625 |
| 13:38–13:41 | Webmail opened; message "RE: Overdue Q3 vendor invoice – action required" viewed | Chrome history |
| 13:41:45 | `Q3_Vendor_Invoice.pdf.exe` downloaded from `files.invoice-portal.example`; Chrome warned, user kept it (`user_validated`) | Chrome history, EDR (13:41:49), DNS, firewall |
| 13:43:10 | Sample executed (PID 0x1A2C) | Security 4688 |
| 13:43:12–14 | Beacon to `cdn.meridian-sync.example` / 203.0.113.77:443 | DNS, Security 5156, firewall |
| 13:43:31 | Hidden encoded PowerShell copies the sample to `C:\ProgramData\MSync\msync.exe` | Security 4688, PowerShell 4104, EDR (13:44:02) |
| 13:44:06–13:45:03 | `msync.exe` started; scheduled task `\Microsoft\Windows\MSync\Updater`; service `MeridianSyncSvc`; account `svc_msync` created and added to Administrators | Security 4688/4698/4720/4732, System 7045/7036 |
| 13:48, 13:53 | Periodic beacons | DNS, firewall |
| 13:52:10–13:55:47 | `msync.exe` reads four files in `Documents\Confidential` | Security 4663, EDR |
| 13:57:02–20 | PowerShell (child of msync.exe) archives the folder to `q3_archive.zip` | Security 4688/4663, PowerShell 4104, EDR |
| 13:58:04–06 | Upload to `upload.meridian-sync.example`: 48,213,904 bytes to 203.0.113.77:443 | PowerShell 4104, DNS, Security 5156, firewall |
| 14:03:09–16 | `Windows PowerShell` log cleared, archive deleted, final beacon | PowerShell 4104, System 104, EDR, firewall |
| 14:15:22 | User opens the intranet "Report a suspicious email" page | Chrome history, Security 4688 |
| 14:22:40 | IR firewall rule blocks 203.0.113.77 | Firewall |
| 14:31:40 | User logs off | Security 4647 |

## Deliberate characteristics

* **Timezones vary by source:** EVTX and firewall are UTC; EDR JSON and DNS log are local time (EDT, UTC−4) with explicit offsets.
* **Imperfect data:** the DNS log contains a truncated line (log rotation) that must be reported as a parse error.
* **Noise:** failed logons from another host, benign browsing, a benign download, a benign PowerShell script block and a known-good control executable (`MFS_ReportViewer.exe`).
* **Cross-source keys:** the sample's SHA-256 appears in Chrome's download record, the EDR export and the watchlist; the C2 IP/domains appear in the PE strings, DNS, firewall and 5156 events; PIDs link 4688/4663/5156/4104 events into one process tree.
* **Limits of the evidence:** no packet capture or proxy content, so the transferred data cannot be proven to be the archive; the `Windows PowerShell` classic log was cleared (the Operational log survived).

## Files

See `manifest.json` for SHA-256 hashes and sizes. `intel/meridian_ioc_watchlist.csv` is a synthetic local watchlist; `yara_test_patterns/` holds YARA positive/negative test inputs.
