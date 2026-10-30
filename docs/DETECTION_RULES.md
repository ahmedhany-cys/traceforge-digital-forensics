# Detection Rules and Methodology

TraceForge produces four kinds of output. They are kept distinct in the database, the UI and reports:

| Classification | Meaning | Example |
|---|---|---|
| **Confirmed rule match** | A rule's condition is provably satisfied by the evidence bytes / an exact reference match. The *significance* depends on the rule. | YARA rule matched; indicator equals a watchlist entry |
| **Suspicious** | An observation consistent with malicious activity that also has stated benign explanations. | PowerShell with `-EncodedCommand`; executable in Downloads |
| **Informational** | Recorded for context; not an indicator of compromise by itself. | Successful logon; compile timestamp |
| **Inconclusive** | The analysis could not complete or the input is damaged. | Truncated PE; malformed record |
| **Hypothesis** | A correlated sequence of events (see below). Never presented as proven causation. | Download → execution → data access → transfer |

Every finding carries a stable rule ID, severity (`info/low/medium/high/critical`), confidence (`low/medium/high`), a description of *what* matched and a rationale explaining *why it matters and what else could explain it*.

## 1. Static PE indicators (`forensics/pe_analysis.py`)

Samples are never executed.

| ID | Indicator | Class | Notes |
|---|---|---|---|
| PE-000 | PE structure could not be parsed | inconclusive | |
| PE-001 | Document-style double extension (`.pdf.exe`) | suspicious/high | Social engineering |
| PE-002 | Section both writable and executable | suspicious/medium | Packers, self-modifying code |
| PE-003 | Section entropy ≥ 7.2 bits/byte | suspicious/medium (low confidence) | Compressed resources also score high |
| PE-004 | Process-injection import combination | suspicious/high | Debuggers and EDR share these APIs |
| PE-005 | HTTP client APIs (+ embedded URLs → suspicious) | informational / suspicious | |
| PE-006 | Service/registry persistence APIs (+ autostart strings → suspicious) | informational / suspicious | |
| PE-007 | Debugger-detection API | informational | Common in compiler runtimes |
| PE-008 | Known packer / non-standard section names | suspicious / informational | |
| PE-009 | Overlay data after last section (high entropy → suspicious) | informational / suspicious | Installers, signatures |
| PE-010 | Compile timestamp (zero → inconclusive, future → suspicious) | informational | Trivially forgeable; never used for the timeline |
| PE-011 | Embedded hidden / encoded PowerShell command line | suspicious/high | |
| PE-012 | Tiny import table + high entropy | suspicious/medium | Packer heuristic |
| PE-013 | PE checksum mismatch | informational | Only enforced for drivers |
| PE-014 | Network indicators embedded in strings | informational | Extracted as IOCs |
| PE-015 | Image truncated (section data past EOF) | inconclusive | |

The overall assessment is one of `no_suspicious_indicators`, `suspicious`, `suspicious_high`, `inconclusive`. **The word "malicious" is never used**: static traits justify prioritising dynamic analysis, not a verdict.

## 2. YARA rules (`backend/rules/yara/traceforge_core.yar`)

All rules are original to this project and require `id`, `description`, `severity` and `explanation` metadata (enforced at load time; the Settings page validates custom rule text the same way without saving it).

| ID | Rule | Severity | Detects |
|---|---|---|---|
| TF-YARA-001 | TF_Synthetic_Test_Marker | info | Marker string embedded in every synthetic sample |
| TF-YARA-002 | TF_PE_Process_Injection_Imports | high | `WriteProcessMemory` + `CreateRemoteThread` + allocation API (uses the `pe` module) |
| TF-YARA-003 | TF_PE_WX_HighEntropy_Section | medium | W+X section with entropy > 7.2 (uses `pe` + `math`) |
| TF-YARA-004 | TF_Encoded_Hidden_PowerShell | high | `powershell` with `-enc…`/`-w hidden` (ASCII and UTF-16, so it also fires on EVTX) |
| TF-YARA-005 | TF_Archive_And_Upload_Staging | medium | Archive cmdlet + web upload cmdlet + `-Method Post` |
| TF-YARA-006 | TF_Autostart_Persistence_Strings | medium | Run key / schtasks / CreateServiceW + executable path in ProgramData/AppData |
| TF-YARA-007 | TF_Sensitive_Document_Targeting | low | Hard-coded `\Documents\Confidential` |

YARA scans **every** evidence item (logs and EVTX included), with a 64 MiB size cap and 30 s timeout. Test patterns live in `dataset/meridian/yara_test_patterns/` (three positives, one negative).

## 3. Windows event rules (`backend/rules/detections/windows_events.json`)

Rules match on Event ID, channel and conditions over `EventData`/`UserData` fields (`equals`, `contains`, `startswith`, `in`, `regex`, `external_ip`). Optional aggregation (group-by fields, threshold, sliding window). Each rule documents **audit-policy prerequisites**: if the policy is off, the event is never generated and the rule cannot fire — absence of a match is not evidence of absence.

| ID | Event IDs | Title | Severity |
|---|---|---|---|
| WIN-AUTH-001 | 4625 | ≥3 failed logons, same account + source, 5 min | medium |
| WIN-AUTH-002 | 4624 | Successful logon (context) | info |
| WIN-PROC-001 | 4688 | Process from user-writable location | medium |
| WIN-PROC-002 | 4688 | Double-extension executable run | high |
| WIN-PROC-003 | 4688 | PowerShell with encoded command / hidden window (command decoded into the finding) | high |
| WIN-PROC-004 | 4688 | Parent process in user-writable location | medium |
| WIN-PS-001 | 4104 | Script block with archive/upload/log-clear/dynamic-exec keywords | high |
| WIN-PS-002 | 4104 | Script block recorded (context) | info |
| WIN-PERSIST-001 | 4698 | Scheduled task created | medium |
| WIN-PERSIST-002 | 7045 | Service installed | medium |
| WIN-PERSIST-003 | 7045 | Service binary in user-writable/ProgramData path | high |
| WIN-ACCT-001 | 4720 | Local account created | medium |
| WIN-ACCT-002 | 4732 | Member added to BUILTIN\Administrators | high |
| WIN-DEF-001 | 1102 | Security log cleared | high |
| WIN-DEF-002 | 104 | Other event log cleared | high |
| WIN-FILE-001 | 4663 | Access under a sensitive folder (requires SACL) | medium |
| WIN-NET-001 | 5156 | Outbound connection to external address (context) | info |
| WIN-NET-002 | 5156 | PowerShell / user-path binary connecting externally | medium |

Event semantics follow Microsoft's documented Security auditing events (4624/4625/4663/4688/4698/4720/4732/5156/1102), Service Control Manager 7045/7036, Event Log 104 and PowerShell 4104.

## 4. Browser, network and file rules (`forensics/artifact_rules.py`)

| ID | Source | Rule | Severity |
|---|---|---|---|
| BRW-001 | Chromium downloads | Executable downloaded | low (informational) |
| BRW-002 | Chromium downloads | Double-extension executable downloaded | high |
| BRW-003 | Chromium downloads | Non-`not_dangerous` danger type (e.g. `user_validated`) | medium |
| BRW-004 | Chromium downloads | Executable reached from a webmail referrer | medium |
| NET-001 | Firewall/flow logs | ≥ *large_transfer_bytes* (default 10 MiB) sent to an external address in one session | high |
| NET-002 | Firewall/flow logs | Connection blocked | info |
| FILE-001 | EDR/file logs | Executable created in a user-writable path | medium |
| FILE-002 | EDR/file logs | Archive created | low |
| FILE-003 | EDR/file logs | Read of a file under a sensitive path keyword | medium |
| FILE-004 | EDR/file logs | Archive deleted | low |

## 5. Correlation (`backend/rules/detections/correlation.json`, `forensics/correlation.py`)

A correlation rule is an ordered list of steps. Each step has a match predicate (event type, file extension, tags, external destination, minimum bytes, minimum severity), a maximum gap from the previous step and optional **links** to earlier steps:

| Link type | Meaning | Strength |
|---|---|---|
| `same_entity` | Same file name or SHA-256 as an earlier step | entity |
| `lineage` | Event's PID (or, if no PID, its image path) belongs to the process tree rooted at an earlier process-creation event, built from 4688 `NewProcessId`/`ProcessId` and from files written with the root image's SHA-256 | entity |
| `embedded_indicator` | Destination IP/domain is hard-coded in the analysed binary of an earlier step | entity |
| *(none)* | Same host within the time window only | temporal |

Confidence = `high` if every subsequent step is entity-linked, `medium` if at least half are, otherwise `low`. All steps must be on the same host (when the host is known) and within the correlation window (default 180 min). Results are stored as **hypotheses** with an explanation listing each step, its source evidence, its gap from the previous step and the link reasons, plus caveats on causality, clock skew and assumed timezones.

| ID | Sequence |
|---|---|
| CORR-001 | Executable download → execution of the same file name |
| CORR-002 | Download → file written (same hash/name) → execution → sensitive file access → large external transfer |
| CORR-003 | Execution from user-writable path → scheduled task/service whose target is in the process lineage |
| CORR-004 | Archive created → large external transfer (≤15 min) |
| CORR-005 | High-severity execution → event log cleared (≤4 h) |

The engine never fabricates events: every step references an existing timeline event, which references a stored record in a specific evidence item.

## 6. Indicator assessment (`services/case_analysis.py`)

IOCs (IPv4, domains, URLs, SHA-256/SHA-1/MD5, suspicious file names, process images) are extracted from structured fields and from free text (PE strings, script blocks, decoded commands). Each indicator gets:

* a **namespace classification** – e.g. `private`, `documentation` (RFC 5737), `loopback`, `public`; `reserved_example` for RFC 2606 domains; `double_extension_executable`, `archive`;
* an **assessment**, in priority order:
  1. `watchlist_match` – equals a local watchlist entry (synthetic intel in the demo);
  2. `benign_context` – under a configured internal domain;
  3. `suspicious` – referenced by a medium+ severity finding or a correlation (processes: only if a creation event *of that image* was flagged);
  4. `benign_context` – private/loopback address;
  5. `observed` – everything else.

No indicator is labelled malicious merely because it was extracted.
