# Limitations

TraceForge is a portfolio-scale investigation platform. It performs real parsing and analysis, but it is not a validated forensic tool and must not be relied on as one.

## Forensic scope

* **Not legally validated.** No claim of admissibility, tool validation (e.g. NIST CFTT) or compliance with any chain-of-custody standard is made.
* **Logical artifacts only.** No disk images, memory images, registry hives, MFT/USN journal, prefetch, LNK/jump lists, or mobile artifacts.
* **Chromium only** for browser history (Chrome/Edge/Brave `History` schema). Firefox `places.sqlite` and Safari are not parsed.
* **EVTX** parsing relies on python-evtx. Very large logs are parsed synchronously and capped at 500 000 records. Chunk CRC failures are reported but records in those chunks are still parsed (their integrity is flagged as not assured). Recovery of records from slack space / deleted chunks is not attempted.
* **Event semantics depend on audit policy.** 4663 needs a SACL, 4688 command lines need the "include command line" policy, 5156 is often disabled, 4104 needs Script Block Logging. Missing events do not prove missing activity.
* **Generic log parsing is heuristic.** CSV/JSON/text logs are mapped by field-name conventions (`dst_ip`, `event_time`, ...). Unusual schemas may parse with fewer derived entities; unparsed lines are reported, not dropped silently.

## Malware analysis

* Static only; no sandbox, emulation or unpacking. Packed or staged payloads may show few indicators.
* YARA rules are a small original set for demonstration and generic techniques, not a production signature feed.
* No external reputation lookups (VirusTotal etc.) – by design, to keep the project zero-cost and offline. A local CSV watchlist is supported instead.
* PE compile timestamps are reported but never trusted.

## Correlation and timeline

* Correlations are hypotheses based on time, host and shared entities. They do not prove causation.
* Timestamp normalisation trusts each source's clock. Clock skew is not estimated or corrected; it is called out in correlation caveats.
* Sources without timezone information use the configured assumed timezone and are flagged (`timezone_assumed`).
* PID-based process lineage can mis-link when PIDs are reused; lineage is bounded by host and the correlation window.
* Host attribution for browser history and single-host logs comes from the *source host* entered at acquisition.

## IOC handling

* IPv4 only (IPv6 addresses are classified in `netclass.py` but not extracted from free text).
* Some real TLDs collide with file extensions (`.zip`, `.mov`, `.md`); these are treated as file extensions to avoid false positives.
* Assessments reflect the local watchlist and in-case findings only.

## Platform

* SQLite, single node; analysis runs inside the request (no job queue), so very large uploads block that request.
* No encryption at rest; rely on volume/disk encryption.
* No MFA/SSO; local accounts only.
* The audit ledger is **tamper-evident, not immutable** (see below).
* Docker configuration is provided but was **not built or run** in the development environment used for this release (Docker was not installed there). The application was verified by running backend and frontend directly.

## Tamper-evident vs. immutable

A *tamper-evident* log makes undetected modification hard: each record commits to the previous one, so editing, deleting, inserting or re-ordering records breaks the chain at a locatable point. It does **not** prevent modification. An attacker with write access to the database can recompute every hash after their change and produce a new, internally consistent chain.

An *immutable* (WORM) store prevents modification at the storage layer (e.g. object lock, append-only media, a third-party transparency log). TraceForge does not provide one. To close the gap, record the ledger **head hash** (shown on the Chain of Custody page and printed in every report) somewhere outside the attacker's reach – a ticket, an e-mail to a second party, a signed timestamp – and compare later.
