"""Cloudflare Access proof for operator staff away from the office (ADR-0001, phase 3).

Split of duties:
- Cloudflare Access protects only /api/auth/staff-login and proves that the visitor owns an
  email address (email one-time code today, Microsoft Entra later). Its policy is open to
  any address; it does not decide who is staff.
- TeleVault decides: the verified email must match an entry in the `staff_access` table,
  which superadmins manage in the admin UI (a full address, or a whole @domain).

Once verified, the browser carries the signed CF_Authorization cookie on every request; a
superadmin session is accepted from outside the staff networks only when that JWT verifies
(signature from the team's certs, audience = the Access application, issuer, not expired)
and its email is on the list. Customers never touch this path.
"""
from __future__ import annotations

import logging
import re
import sqlite3

import jwt
from fastapi import Request

from .config import Config

log = logging.getLogger("televault.access")
_jwks: dict[str, jwt.PyJWKClient] = {}

_EMAIL = re.compile(r"^[a-z0-9._%+'-]+@[a-z0-9-]+(\.[a-z0-9-]+)+$")
_DOMAIN = re.compile(r"^@?[a-z0-9-]+(\.[a-z0-9-]+)+$")


def normalize_pattern(raw: str) -> str | None:
    """'User@X.com' -> 'user@x.com'; 'x.com' or '@x.com' -> '@x.com'; anything else -> None."""
    p = raw.strip().lower()
    if p.startswith("*@"):
        p = p[1:]
    if _EMAIL.match(p):
        return p
    if _DOMAIN.match(p):
        return p if p.startswith("@") else "@" + p
    return None


def email_allowed(conn: sqlite3.Connection, email: str) -> bool:
    email = email.lower()
    if "@" not in email:
        return False
    domain = "@" + email.split("@", 1)[1]
    return conn.execute("SELECT 1 FROM staff_access WHERE pattern IN (?, ?)", (email, domain)).fetchone() is not None


def _client(team_domain: str) -> jwt.PyJWKClient:
    if team_domain not in _jwks:
        _jwks[team_domain] = jwt.PyJWKClient(f"https://{team_domain}/cdn-cgi/access/certs",
                                             cache_keys=True, lifespan=3600, timeout=5)
    return _jwks[team_domain]


def verified_email(request: Request, cfg: Config) -> str | None:
    """Email proven by a valid Cloudflare Access JWT, or None. Says nothing about staff status."""
    if not (cfg.access_team_domain and cfg.access_aud):
        return None
    token = request.headers.get("cf-access-jwt-assertion") or request.cookies.get("CF_Authorization")
    if not token:
        return None
    try:
        key = _client(cfg.access_team_domain).get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], audience=cfg.access_aud,
                            issuer=f"https://{cfg.access_team_domain}",
                            options={"require": ["exp", "iat", "aud", "iss"]})
    except Exception as e:  # noqa: BLE001 - any failure means "no proof"
        log.info("access jwt rejected: %s", type(e).__name__)
        return None
    email = str(claims.get("email", "")).strip().lower()
    return email or None


def staff_identity(request: Request, cfg: Config) -> str | None:
    """Verified email that is on the staff access list, or None."""
    email = verified_email(request, cfg)
    if not email:
        return None
    from .db import connect
    conn = connect(request.app.state.db.db_path)
    try:
        return email if email_allowed(conn, email) else None
    finally:
        conn.close()


def seed_from_config(conn: sqlite3.Connection, cfg: Config) -> None:
    """First run: carry config.json's staff_emails into the managed list."""
    if conn.execute("SELECT COUNT(*) FROM staff_access").fetchone()[0]:
        return
    for raw in cfg.staff_emails:
        p = normalize_pattern(raw)
        if p:
            conn.execute("INSERT OR IGNORE INTO staff_access(pattern, note, created_by) VALUES (?, ?, 'config.json')",
                         (p, "initial"))
