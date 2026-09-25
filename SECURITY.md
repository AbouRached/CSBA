# Security model

CSBA protects third parties' personal data (callers' numbers and voices), so it is built as
layers that each hold on their own — one failure is not a breach.

| Layer | Controls |
|---|---|
| **Edge** (Cloudflare, recommended) | Tunnel (no inbound port), WAF custom rules scoped to the portal hostname: country allow-list, known-bot block, app-paths-only allow-list (`/`, `/static/*`, `/api/*`, `/cdn-cgi/access/*`). Tunnel health alerts. |
| **Host** | App listens on `127.0.0.1` only. Runs as a dedicated local account with batch-logon only (interactive/RDP denied), **read & execute** on recordings with write/delete/permission changes explicitly **denied**. Production code in an admin-only folder so SYSTEM tasks can't be hijacked by an ordinary account. |
| **Identity** | Argon2id passwords (12+ chars, 3 classes), forced change on first login, mandatory TOTP for every role (secrets Fernet-encrypted, single-use codes, ±1 step), lockout after 5 failures, per-IP limiter using the real client IP. |
| **Sessions** | Random tokens stored as SHA-256, `HttpOnly; Secure; SameSite=Strict`, idle timeout + absolute cap (shorter for superadmins), CSRF header on every mutating call, step-up code for sensitive admin actions. |
| **Staff (superadmin)** | Usable only from configured staff networks, the local console, or with a verified Cloudflare Access identity that is on the in-app Staff access list. Checked at login **and** on every request. |
| **Authorization** | One function (`scope.scope_sql`) builds the WHERE clause for every recordings query; files are addressed by index id only and the resolved path is re-checked to be inside the client's root. No delete route exists. |
| **Privileged changes** | NTFS grants are queued by the web app and applied by a SYSTEM worker that re-validates each path itself (local fixed/removable drives, no junctions, nothing on the system drive unless an admin allow-listed it). |
| **Evidence** | Append-only audit log, mirrored to the Windows Event Log; nightly backups of the database and the secrets needed to restore. |
| **Tooling** | MCP endpoint on its own loopback listener, Host-header checked, bearer tokens (hashed, revocable, read/operate scopes), every call audited; no audio, deletes, passwords or MFA. |

## Reporting a vulnerability

Please open a private security advisory on this repository rather than a public issue.
