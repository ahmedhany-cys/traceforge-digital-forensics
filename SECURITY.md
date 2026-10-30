# Security Policy

TraceForge handles untrusted files and sensitive investigation data, so it is built as security-sensitive software. The full analysis is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's **"Report a vulnerability"** (Security Advisories) on this repository rather than opening a public issue. Include reproduction steps, affected version/commit and impact. You can expect an acknowledgement within a few days.

## Supported versions

Only the latest commit on `main` receives fixes.

## Security controls (summary)

| Area | Control |
|---|---|
| Uploaded files | Never executed; content-based type detection with extension consistency checks; size limit enforced while streaming and at the ASGI layer; random storage names; vault files read-only (0400); vault never served statically |
| Paths | Client filenames used for display only; resolved storage paths confined to the vault |
| Parsing | Read-only/immutable SQLite on a hash-verified private copy; `defusedxml`; record, line, size and time caps; per-record error capture |
| Database | SQLAlchemy ORM and bound parameters; constant SQL only in the Chromium parser (allow-listed column names) |
| Web | Strict CSP, `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` on API responses; React text rendering only |
| Authentication | Argon2id; password policy; login throttling/lockout; generic failure messages |
| Sessions | Random 256-bit tokens stored hashed; `HttpOnly`, `SameSite=Strict`, optional `Secure`; absolute + idle expiry |
| CSRF | Per-session synchroniser token in `X-CSRF-Token` on all state-changing requests |
| Authorisation | Roles `viewer` < `investigator` < `admin`, enforced server-side on every mutating endpoint |
| Integrity | SHA-256 at acquisition; re-verified before/after analysis, on demand and for reports; hash-chained audit ledger |
| Errors | Generic 500 responses; stack traces only in server logs; API docs disabled in production |
| Dependencies | Pinned; `pip-audit`, `npm audit` and `bandit` run during QA |

## Operating guidance

* Run TraceForge on an isolated analysis host or container. Treat uploaded samples as live malware even though TraceForge never executes them.
* Terminate TLS in a reverse proxy and set `TRACEFORGE_COOKIE_SECURE=true`.
* Encrypt the data volume; back up `TRACEFORGE_DATA_DIR`.
* Record the ledger head hash outside the system after significant actions (it is also printed in reports).
* Never commit `.env`, `backend/data/` or `demo-credentials.txt` (all are git-ignored).

## Known limitations

The audit ledger is tamper-evident, not immutable; there is no MFA, no encryption at rest and no sandboxing of parser libraries beyond process/container isolation. See [docs/LIMITATIONS.md](docs/LIMITATIONS.md).
