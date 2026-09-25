"""Mandatory second factor: TOTP (RFC 6238) for Microsoft Authenticator or any authenticator app.

Flow:
  1. POST /api/auth/login (password) -> session with mfa_ok = 0. Every data/admin route
     refuses it (deps.current_user).
  2. Not enrolled yet -> POST /api/auth/mfa/setup returns a QR code; the user scans it and
     POSTs a code to /api/auth/mfa/verify, which confirms the enrolment.
     Enrolled -> POST /api/auth/mfa/verify with the 6-digit code.
  3. Success sets mfa_ok = 1 on this session only.

Secrets are Fernet-encrypted with a key kept in data/mfa.key (separate from the DB, so a
copy of the database alone does not reveal them). A code is accepted once (replay guard),
+-1 step of clock drift is tolerated, and wrong codes count toward the account lockout.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import sqlite3
import struct
import time
from pathlib import Path
from urllib.parse import quote

import segno
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from . import audit
from .config import APP_NAME, Config
from .deps import client_ip, get_cfg, get_conn, session_user
from .scope import Principal
from .security import (
    SESSION_COOKIE,
    destroy_session,
    iso,
    now_utc,
    register_failure,
    session_hash,
)

STEP = 30
DIGITS = 6
MAX_SESSION_FAILURES = 5
def issuer(cfg: Config) -> str:
    """Name shown in the authenticator app, e.g. 'TeleVault (Acme Ltd)'."""
    return f"{APP_NAME} ({cfg.vendor_name})" if cfg.vendor_name else APP_NAME

router = APIRouter(prefix="/api/auth/mfa", tags=["mfa"])


# ---------------------------------------------------------------- TOTP

def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _hotp(secret_b32: str, counter: int) -> str:
    key = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    off = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF) % (10 ** DIGITS)
    return str(code).zfill(DIGITS)


def totp_now(secret_b32: str, at: float | None = None) -> str:
    return _hotp(secret_b32, int((time.time() if at is None else at) // STEP))


def match_step(secret_b32: str, code: str, at: float | None = None, window: int = 1) -> int | None:
    """Return the time step the code belongs to (within +-window), or None."""
    code = "".join(ch for ch in code if ch.isdigit())
    if len(code) != DIGITS:
        return None
    now = int((time.time() if at is None else at) // STEP)
    for step in range(now - window, now + window + 1):
        if hmac.compare_digest(_hotp(secret_b32, step), code):
            return step
    return None


def otpauth_uri(secret_b32: str, username: str, issuer_name: str = APP_NAME) -> str:
    label = quote(f"{issuer_name}:{username}")
    return f"otpauth://totp/{label}?secret={secret_b32}&issuer={quote(issuer_name)}&algorithm=SHA1&digits={DIGITS}&period={STEP}"


# ---------------------------------------------------------------- secret storage

def _fernet(cfg: Config) -> Fernet:
    key_path: Path = cfg.data_dir / "mfa.key"
    if not key_path.exists():
        key_path.write_bytes(Fernet.generate_key())
    return Fernet(key_path.read_bytes().strip())


def encrypt_secret(cfg: Config, secret_b32: str) -> str:
    return _fernet(cfg).encrypt(secret_b32.encode("ascii")).decode("ascii")


def decrypt_secret(cfg: Config, blob: str | None) -> str | None:
    if not blob:
        return None
    try:
        return _fernet(cfg).decrypt(blob.encode("ascii")).decode("ascii")
    except InvalidToken:
        return None


def reset_user_mfa(conn: sqlite3.Connection, user_id: int) -> None:
    """Forget the authenticator; the user enrols again at next sign-in."""
    conn.execute("UPDATE users SET mfa_secret = NULL, mfa_enabled = 0, mfa_last_step = 0 WHERE id = ?", (user_id,))
    conn.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))


# ---------------------------------------------------------------- routes

class CodeIn(BaseModel):
    code: str = Field(min_length=6, max_length=12)


def _token(request: Request) -> str:
    t = request.cookies.get(SESSION_COOKIE)
    if not t:
        raise HTTPException(401, "Not signed in.")
    return t


@router.post("/setup")
def setup(request: Request, p: Principal = Depends(session_user),
          conn: sqlite3.Connection = Depends(get_conn), cfg: Config = Depends(get_cfg)):
    """Start enrolment: returns the QR code to scan. Refused once an authenticator is
    confirmed, so a stolen password alone can never replace it."""
    if p.mfa_enrolled:
        raise HTTPException(409, "An authenticator is already registered. Ask an administrator to reset it.")
    row = conn.execute("SELECT mfa_secret FROM users WHERE id = ?", (p.user_id,)).fetchone()
    secret = decrypt_secret(cfg, row["mfa_secret"])
    if secret is None:  # keep a pending secret across page reloads until it is confirmed
        secret = new_secret()
        conn.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (encrypt_secret(cfg, secret), p.user_id))
    uri = otpauth_uri(secret, p.username, issuer(cfg))
    qr = segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#0b2545", light="#ffffff")
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return {"issuer": issuer(cfg), "account": p.username, "secret": grouped, "qr": qr}


@router.post("/verify")
def verify(body: CodeIn, request: Request, p: Principal = Depends(session_user),
           conn: sqlite3.Connection = Depends(get_conn), cfg: Config = Depends(get_cfg)):
    """Second factor at sign-in, and again as step-up before sensitive admin actions."""
    token = _token(request)
    ip = client_ip(request)
    limiter = request.app.state.ip_limiter
    if not limiter.allowed(ip):
        raise HTTPException(429, "Too many attempts. Try again later.")

    row = conn.execute("SELECT mfa_secret, mfa_last_step, customer_id FROM users WHERE id = ?", (p.user_id,)).fetchone()
    secret = decrypt_secret(cfg, row["mfa_secret"])
    if secret is None:
        raise HTTPException(409, "No authenticator set up yet. Start the setup first.")

    step = match_step(secret, body.code)
    if step is None or step <= row["mfa_last_step"]:
        limiter.hit(ip)
        register_failure(conn, p.user_id, cfg)
        th = session_hash(token)
        conn.execute("UPDATE sessions SET mfa_failures = mfa_failures + 1 WHERE token_hash = ?", (th,))
        fails = conn.execute("SELECT mfa_failures FROM sessions WHERE token_hash = ?", (th,)).fetchone()
        audit.log(conn, "mfa.fail", ip=ip, username=p.username, user_id=p.user_id, customer_id=row["customer_id"],
                  detail="reused code" if step is not None else "wrong code")
        if fails is None or fails["mfa_failures"] >= MAX_SESSION_FAILURES:
            destroy_session(conn, token)
            raise HTTPException(401, "Too many wrong codes. Sign in again.")
        raise HTTPException(400, "That code is not valid. Check the time on your phone and try the current code.")

    enrolling = not p.mfa_enrolled
    conn.execute("UPDATE users SET mfa_enabled = 1, mfa_last_step = ?, failed_attempts = 0 WHERE id = ?",
                 (step, p.user_id))
    conn.execute("UPDATE sessions SET mfa_ok = 1, mfa_failures = 0, mfa_verified_at = ? WHERE token_hash = ?",
                 (iso(now_utc()), session_hash(token)))
    action = "mfa.enrolled" if enrolling else ("mfa.step_up" if p.mfa_ok else "mfa.ok")
    audit.log(conn, action, ip=ip, username=p.username, user_id=p.user_id, customer_id=row["customer_id"])
    return {"ok": True, "enrolled": enrolling}
