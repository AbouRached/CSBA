"""Read-only folder access for the service account, requested from the admin UI.

The web app runs as the unprivileged service account and cannot change NTFS permissions.
It only *queues* a request here; the SYSTEM task "TeleVault Grant Worker"
(scripts/grant-worker.ps1) takes pending rows, re-checks the path against its own policy
(local fixed/removable drive, no junctions, nothing on the Windows drive unless an admin
allow-listed it) and applies the same read-only rule as scripts/grant-drive.ps1.
"""
from __future__ import annotations

import os
import sqlite3
import subprocess
from datetime import timedelta

from .config import Config
from .security import iso, now_utc

# A request stuck in "running" this long (worker killed mid-way) is offered again.
STALE_RUNNING_MINUTES = 30


def queue_grant(conn: sqlite3.Connection, customer_id: int, path: str, requested_by: str) -> int | None:
    """Queue a grant unless the same folder already has one waiting. Returns the id queued."""
    open_ = conn.execute(
        "SELECT id FROM access_grants WHERE customer_id = ? AND path = ? AND status IN ('pending','running')",
        (customer_id, path)).fetchone()
    if open_:
        return None
    return conn.execute("INSERT INTO access_grants(customer_id, path, requested_by) VALUES (?,?,?)",
                        (customer_id, path, requested_by)).lastrowid


def last_grant(conn: sqlite3.Connection, customer_id: int) -> dict | None:
    r = conn.execute("SELECT id, path, requested_by, requested_at, status, message, finished_at "
                     "FROM access_grants WHERE customer_id = ? ORDER BY id DESC LIMIT 1", (customer_id,)).fetchone()
    return dict(r) if r else None


def _icacls(path: str) -> str | None:
    if os.name != "nt":
        return None
    try:
        out = subprocess.run(["icacls", path], capture_output=True, timeout=5,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return out.stdout.decode("oem", "replace")  # icacls writes in the console (OEM) code page


def access_status(root: str, cfg: Config) -> dict:
    """What the service account can do with a customer folder, as far as this process can tell.
    readable: this process (the service account, in production) can list the folder.
    protected: an explicit DENY entry for the service account is present (read-only enforced);
               None when it cannot be determined (not Windows, folder offline, icacls failed)."""
    try:
        with os.scandir(root):
            readable = True
    except OSError:
        readable = False
    protected = None
    text = _icacls(root) if os.path.isdir(root) else None
    if text is not None:
        acct = cfg.service_account.lower()
        protected = any(f"\\{acct}:" in line.lower() and "(deny)" in line.lower() for line in text.splitlines())
    return {"readable": readable, "protected": protected}


# ---------------------------------------------------------------- worker side (CLI, runs as SYSTEM)

def take_pending(conn: sqlite3.Connection) -> list[dict]:
    """Claim every pending (or stale running) request and return them."""
    stale = iso(now_utc() - timedelta(minutes=STALE_RUNNING_MINUTES))
    rows = conn.execute(
        "SELECT id, customer_id, path FROM access_grants "
        "WHERE status = 'pending' OR (status = 'running' AND started_at < ?) ORDER BY id", (stale,)).fetchall()
    for r in rows:
        conn.execute("UPDATE access_grants SET status = 'running', started_at = ? WHERE id = ?",
                     (iso(now_utc()), r["id"]))
    return [dict(r) for r in rows]


def finish(conn: sqlite3.Connection, grant_id: int, ok: bool, message: str) -> None:
    conn.execute("UPDATE access_grants SET status = ?, message = ?, finished_at = ? WHERE id = ?",
                 ("done" if ok else "error", message[:500], iso(now_utc()), grant_id))
