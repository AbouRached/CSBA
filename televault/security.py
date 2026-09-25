"""Passwords, sessions, login throttling, CSRF.

- Argon2id for password hashes.
- Sessions: 32 random bytes → cookie; only the SHA-256 of the token is stored, so a
  database read cannot be replayed as a session.
- Per-account lockout after N failures and a per-IP sliding window limiter.
- CSRF: cookies are SameSite=Strict and every non-GET request must carry the
  X-Requested-With header (browsers do not add it cross-site without CORS consent).
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

from .config import Config
from .scope import Principal

SESSION_COOKIE = "televault_session"
CSRF_HEADER = "x-requested-with"
CSRF_VALUE = "TeleVault"

_ph = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def hash_password(pw: str) -> str:
    return _ph.hash(pw)


def verify_password(pw_hash: str, pw: str) -> bool:
    try:
        return _ph.verify(pw_hash, pw)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_policy_error(pw: str, cfg: Config) -> str | None:
    if len(pw) < cfg.min_password_length:
        return f"Password must be at least {cfg.min_password_length} characters."
    classes = sum(
        [any(c.islower() for c in pw), any(c.isupper() for c in pw),
         any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)]
    )
    if classes < 3:
        return "Password must mix at least three of: lowercase, uppercase, digits, symbols."
    return None


# ---------------------------------------------------------------- sessions

def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_session(conn: sqlite3.Connection, user_id: int, ip: str, ua: str, cfg: Config,
                   mfa_ok: bool = False) -> str:
    """New sessions start with the second factor pending unless it was already proven
    (only when rotating the token of a session that had passed MFA)."""
    token = secrets.token_urlsafe(32)
    created = now_utc()
    conn.execute(
        "INSERT INTO sessions(token_hash,user_id,created_at,expires_at,ip,user_agent,mfa_ok) VALUES (?,?,?,?,?,?,?)",
        (_token_hash(token), user_id, iso(created),
         iso(created + timedelta(hours=cfg.session_ttl_hours)), ip, ua[:200], int(mfa_ok)),
    )
    return token


def session_hash(token: str) -> str:
    return _token_hash(token)


def destroy_session(conn: sqlite3.Connection, token: str) -> None:
    conn.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))


def destroy_user_sessions(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


def purge_expired_sessions(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM sessions WHERE expires_at < ?", (iso(now_utc()),))


def resolve_session(conn: sqlite3.Connection, token: str | None, cfg: Config) -> Principal | None:
    if not token:
        return None
    row = conn.execute(
        """SELECT s.token_hash, s.created_at, s.expires_at, s.mfa_ok, s.mfa_verified_at,
                  u.id, u.username, u.role, u.customer_id,
                  u.active, u.must_change_password, u.mfa_enabled
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ?""",
        (_token_hash(token),),
    ).fetchone()
    if row is None:
        return None
    # Idle timeout, plus an absolute cap that sliding expiry can never extend
    # (shorter for superadmins, who can see every customer).
    max_h = cfg.superadmin_session_max_hours if row["role"] == "superadmin" else cfg.session_max_hours
    too_old = row["created_at"] < iso(now_utc() - timedelta(hours=max_h))
    if row["expires_at"] < iso(now_utc()) or too_old or not row["active"]:
        conn.execute("DELETE FROM sessions WHERE token_hash = ?", (row["token_hash"],))
        return None
    # sliding expiry
    conn.execute(
        "UPDATE sessions SET expires_at = ? WHERE token_hash = ?",
        (iso(now_utc() + timedelta(hours=cfg.session_ttl_hours)), row["token_hash"]),
    )
    dept_ids = [
        r["department_id"]
        for r in conn.execute("SELECT department_id FROM user_departments WHERE user_id = ?", (row["id"],))
    ]
    return Principal(
        user_id=row["id"],
        username=row["username"],
        role=row["role"],
        customer_id=row["customer_id"],
        department_ids=dept_ids,
        must_change_password=bool(row["must_change_password"]),
        mfa_ok=bool(row["mfa_ok"]),
        mfa_enrolled=bool(row["mfa_enabled"]),
        mfa_verified_at=row["mfa_verified_at"],
    )


# ---------------------------------------------------------------- login throttle

class IpLimiter:
    """Sliding-window attempt counter per IP. In-memory; adequate for one process."""

    def __init__(self, max_attempts: int, window_seconds: int):
        self.max = max_attempts
        self.window = window_seconds
        self._hits: dict[str, deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, dq: deque, now: float) -> None:
        while dq and dq[0] < now - self.window:
            dq.popleft()

    def allowed(self, ip: str) -> bool:
        now = time.monotonic()
        with self._lock:
            dq = self._hits[ip]
            self._trim(dq, now)
            return len(dq) < self.max

    def hit(self, ip: str) -> None:
        now = time.monotonic()
        with self._lock:
            dq = self._hits[ip]
            self._trim(dq, now)
            dq.append(now)


def account_locked(row: sqlite3.Row) -> bool:
    lu = row["locked_until"]
    return bool(lu) and lu > iso(now_utc())


def register_failure(conn: sqlite3.Connection, user_id: int, cfg: Config) -> None:
    row = conn.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,)).fetchone()
    n = (row["failed_attempts"] if row else 0) + 1
    locked_until = None
    if n >= cfg.login_max_failures:
        locked_until = iso(now_utc() + timedelta(minutes=cfg.login_lock_minutes))
        n = 0
    conn.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (n, locked_until, user_id),
    )


def register_success(conn: sqlite3.Connection, user_id: int) -> None:
    conn.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
        (iso(now_utc()), user_id),
    )


# ---------------------------------------------------------------- CSRF

def csrf_ok(method: str, headers) -> bool:
    if method in ("GET", "HEAD", "OPTIONS"):
        return True
    return headers.get(CSRF_HEADER, "") == CSRF_VALUE
