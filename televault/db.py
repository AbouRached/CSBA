"""SQLite schema and connection helper.

One file, WAL mode, foreign keys on. Schema changes are applied idempotently at start.
There is deliberately no DELETE path for recordings other than the indexer removing
rows for files that no longer exist on an *online* drive.
"""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS customers (
    id          INTEGER PRIMARY KEY,
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    root_path   TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1,
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS departments (
    id              INTEGER PRIMARY KEY,
    customer_id     INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    extensions_json TEXT NOT NULL DEFAULT '[]',
    queues_json     TEXT NOT NULL DEFAULT '[]',
    dids_json       TEXT NOT NULL DEFAULT '[]',
    UNIQUE (customer_id, name)
);

CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY,
    customer_id          INTEGER REFERENCES customers(id) ON DELETE CASCADE,
    username             TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash        TEXT NOT NULL,
    role                 TEXT NOT NULL CHECK (role IN ('superadmin','customer_admin','department')),
    display_name         TEXT NOT NULL DEFAULT '',
    must_change_password INTEGER NOT NULL DEFAULT 1,
    active               INTEGER NOT NULL DEFAULT 1,
    failed_attempts      INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT,
    last_login           TEXT,
    created_at           TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);

CREATE TABLE IF NOT EXISTS user_departments (
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    department_id INTEGER NOT NULL REFERENCES departments(id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, department_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    ip          TEXT NOT NULL DEFAULT '',
    user_agent  TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS recordings (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    rel_path    TEXT NOT NULL,
    filename    TEXT NOT NULL,
    rec_type    TEXT NOT NULL DEFAULT 'unknown',
    target      TEXT NOT NULL DEFAULT '',
    party       TEXT NOT NULL DEFAULT '',
    rec_ts      TEXT NOT NULL,
    uniqueid    TEXT NOT NULL DEFAULT '',
    size        INTEGER NOT NULL DEFAULT 0,
    mtime       REAL NOT NULL DEFAULT 0,
    empty       INTEGER NOT NULL DEFAULT 0,
    seen_at     TEXT NOT NULL,
    UNIQUE (customer_id, rel_path)
);
CREATE INDEX IF NOT EXISTS idx_rec_cust_ts    ON recordings(customer_id, rec_ts DESC);
CREATE INDEX IF NOT EXISTS idx_rec_cust_party ON recordings(customer_id, party);
CREATE INDEX IF NOT EXISTS idx_rec_cust_type_target ON recordings(customer_id, rec_type, target);
CREATE INDEX IF NOT EXISTS idx_rec_seen       ON recordings(customer_id, seen_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    user_id     INTEGER,
    username    TEXT NOT NULL DEFAULT '',
    customer_id INTEGER,
    ip          TEXT NOT NULL DEFAULT '',
    action      TEXT NOT NULL,
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);

CREATE TABLE IF NOT EXISTS index_runs (
    id          INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id) ON DELETE CASCADE,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    status      TEXT NOT NULL DEFAULT 'running',
    files_seen  INTEGER NOT NULL DEFAULT 0,
    files_added INTEGER NOT NULL DEFAULT 0,
    files_removed INTEGER NOT NULL DEFAULT 0,
    message     TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_index_runs_cust ON index_runs(customer_id, id DESC);

-- Requests (from the admin UI) to give the service account read-only NTFS access to a
-- customer folder. The web app cannot change permissions itself; the SYSTEM "TeleVault Grant
-- Worker" task applies them after its own path checks (scripts/grant-worker.ps1).
CREATE TABLE IF NOT EXISTS access_grants (
    id           INTEGER PRIMARY KEY,
    customer_id  INTEGER REFERENCES customers(id) ON DELETE CASCADE,
    path         TEXT NOT NULL,
    requested_by TEXT NOT NULL DEFAULT '',
    requested_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    status       TEXT NOT NULL DEFAULT 'pending',   -- pending | running | done | error
    message      TEXT NOT NULL DEFAULT '',
    started_at   TEXT,
    finished_at  TEXT
);
CREATE INDEX IF NOT EXISTS idx_access_grants_cust ON access_grants(customer_id, id DESC);

-- Tokens for the local MCP endpoint (troubleshooting / development tools). Only the SHA-256
-- of the token is stored; the token itself is shown once, when a superadmin creates it.
CREATE TABLE IF NOT EXISTS mcp_tokens (
    id           INTEGER PRIMARY KEY,
    name         TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    scope        TEXT NOT NULL CHECK (scope IN ('read','operate')),
    created_by   TEXT NOT NULL DEFAULT '',
    created_at   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    last_used_at TEXT,
    revoked_at   TEXT
);

-- Who counts as operator staff when verified by Cloudflare Access away from the office.
-- pattern: a full email (a@b.com) or a whole domain (@b.com). Managed in the admin UI.
CREATE TABLE IF NOT EXISTS staff_access (
    id          INTEGER PRIMARY KEY,
    pattern     TEXT NOT NULL UNIQUE,
    note        TEXT NOT NULL DEFAULT '',
    created_by  TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
"""


def connect(db_path: Path) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# Columns added after the first release: (table, column, definition). Applied idempotently.
MIGRATIONS = [
    ("users", "mfa_secret", "TEXT"),                              # Fernet-encrypted TOTP secret
    ("users", "mfa_enabled", "INTEGER NOT NULL DEFAULT 0"),       # 1 once the user proved a code
    ("users", "mfa_last_step", "INTEGER NOT NULL DEFAULT 0"),     # replay guard: last accepted 30 s step
    ("sessions", "mfa_ok", "INTEGER NOT NULL DEFAULT 0"),         # second factor passed for this session
    ("sessions", "mfa_failures", "INTEGER NOT NULL DEFAULT 0"),
    ("sessions", "mfa_verified_at", "TEXT"),                      # last code entry (step-up window)
    ("departments", "folders_json", "TEXT NOT NULL DEFAULT '[]'"),  # folders under the customer root
    ("customers", "volume_serial", "TEXT"),  # serial of the disk the root is on (guards against letter swaps)
]


def init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    for table, col, ddl in MIGRATIONS:
        have = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
        if col not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    conn.commit()


class Database:
    """Tiny connection factory. One connection per request/thread."""

    def __init__(self, db_path: Path):
        self.db_path = db_path
        with self.conn() as c:
            init_schema(c)

    @contextmanager
    def conn(self) -> Iterator[sqlite3.Connection]:
        c = connect(self.db_path)
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()
