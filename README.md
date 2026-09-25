# CSBA — Client Secure Backup Access

**CSBA** (code name *TeleVault*) is a self-hosted web portal that gives an operator's clients
secure, **read-only** access to their archived call recordings — search, play and download —
while the recordings themselves stay on the operator's storage, one drive or folder per client.

It was built for FreePBX / Asterisk `monitor` archives offloaded to a Windows server, but
works with any folder tree of `.wav`, `.mp3`, `.gsm` or `.ogg` files.

```
Browser ──HTTPS──▶ Cloudflare (WAF, geo rules) ──tunnel──▶ CSBA on 127.0.0.1 (FastAPI + SQLite)
                                                              │ read-only
                                                              ▼
                                                D:\  E:\  F:\ …  one drive/folder per client
```

## Features

- **Per-client isolation** — every query goes through one authorization choke point; a client
  only ever sees its own drive.
- **Departments** — narrow a user to the recordings of their department by extension,
  queue, DID (parsed from FreePBX `recordcheck` filenames) and/or **folders** on the drive.
- **Play in the browser** (HTTP Range, seekable), download single files or **zips** of a
  filtered set (configurable limits).
- **Admin UI** — clients, departments, users, audit log, a drive/folder picker, and a
  *Service access* view that requests read-only NTFS rights through a privileged worker.
- **Mandatory two-step verification** (TOTP — Microsoft Authenticator, Google Authenticator …)
  for every account; step-up re-verification for sensitive admin actions.
- **Operator staff gating** — superadmin accounts only work from configured staff networks,
  the local console, or with a verified Cloudflare Access identity on an in-app allow-list.
- **Append-only audit log** of every sign-in, playback, download and change, mirrored to the
  Windows Event Log.
- **Local MCP endpoint** for AI-assisted troubleshooting (health, logs, audit,
  "why can/can't this user see this recording") — loopback only, token-scoped, audited.
- **No delete path** — the service account has read-only (write/delete *denied*) NTFS rights.

## Requirements

- Windows 10/11 or Windows Server, Python 3.12+ (3.13 recommended, installed for all users)
- Optional: Cloudflare account (Tunnel, WAF, Access) for internet exposure

## Quick start (development)

```powershell
py -3.13 -m venv .venv; .\.venv\Scripts\pip install -r requirements.txt
copy config.example.json config.json          # then edit
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m televault.cli init
.\.venv\Scripts\python -m televault.cli make-cert --hostname archive.example.local
.\.venv\Scripts\python -m televault.cli create-superadmin admin
.\.venv\Scripts\python -m televault.cli serve   # https://localhost:8443
```

## Production on Windows

| Script | Purpose |
|---|---|
| `scripts\deploy-production.ps1` | Copies the app to a locked `C:\TeleVault`, machine-wide Python, venv, one-time data move, then runs `install-boot.ps1`. Re-run to deploy updates. |
| `scripts\install-boot.ps1` | Service account (`televault-svc`, batch-logon only), scheduled tasks (app, nightly backup, grant worker), Event Log source, cloudflared service, no inbound port. |
| `scripts\grant-drive.ps1` | Read-only NTFS access for the service account on a client folder (also available from the UI). |
| `scripts\grant-worker.ps1` | SYSTEM task that applies UI access requests after its own path checks. |
| `scripts\backup.ps1` | Online SQLite backup + secrets needed to restore (`mfa.key`, TLS pair, tunnel credentials). |

See [SECURITY.md](SECURITY.md) for the security model.

## Configuration (`config.json`)

| Key | Default | Meaning |
|---|---|---|
| `host` / `port` | 127.0.0.1 / 8443 | HTTPS listener (keep loopback behind a tunnel) |
| `vendor_name` | "" | Operator name shown in authenticator apps, MCP title, TLS certificate |
| `staff_networks` | [] | CIDRs where superadmin accounts may be used (the local console always may) |
| `trust_cloudflare_header` | false | Use `CF-Connecting-IP` (only from loopback) as the client IP |
| `session_ttl_hours` / `session_max_hours` / `superadmin_session_max_hours` | 12 / 168 / 8 | Idle timeout and absolute caps |
| `step_up_minutes` | 10 | Freshness of the code required for sensitive admin actions |
| `access_team_domain` / `access_aud` | "" | Cloudflare Access application for staff verification (off when empty) |
| `staff_emails` | [] | Seeds the in-app Staff access list on first run |
| `mcp_port` | 8765 | Local MCP endpoint (127.0.0.1 only; 0 disables) |
| `zip_max_files` / `zip_max_bytes` | 500 / 2 GB | Bulk download limits |
| `login_max_failures` / `login_lock_minutes` | 5 / 15 | Account lockout |
| `index_interval_minutes` | 15 | Rescan interval |

**Branding:** put `logo.png` (login page) and `logo-small.png` (top bar) in
`televault/static/brand/` and change the two colours at the top of `styles.css`. Without a
logo the UI simply shows the name.

## MCP (troubleshooting with AI assistants)

A superadmin creates a token under **Developer access**; it is shown once with the command:

```
claude mcp add --transport http televault http://127.0.0.1:8765/mcp --header "Authorization: Bearer tv_..."
```

`read` tokens: health, config, logs, audit, clients, departments, users, index runs, stats,
folders, `explain_access`, `parse_filename`. `operate` tokens add reindex, unlock user,
request folder access. No audio, no deletes, no passwords or MFA.

## Tests

```powershell
.\.venv\Scripts\python -m pytest -q
```
