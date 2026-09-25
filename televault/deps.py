"""FastAPI dependencies shared by the routers."""
from __future__ import annotations

import ipaddress
import sqlite3
from datetime import timedelta
from typing import Iterator

from fastapi import Depends, HTTPException, Request

from .config import Config
from .db import Database, connect
from .scope import Principal
from .security import SESSION_COOKIE, iso, now_utc, resolve_session


def get_cfg(request: Request) -> Config:
    return request.app.state.cfg


def get_db(request: Request) -> Database:
    return request.app.state.db


def get_conn(request: Request) -> Iterator[sqlite3.Connection]:
    """Request-scoped connection.

    An HTTPException is a *result* (401, 404, 413 ...), not a failure: whatever the
    route wrote before raising (failed-login counters, audit rows) must persist.
    Only unexpected exceptions roll back.
    """
    db: Database = request.app.state.db
    c = connect(db.db_path)
    try:
        yield c
        c.commit()
    except HTTPException:
        c.commit()
        raise
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


_LOOPBACK = {"127.0.0.1", "::1"}


def client_ip(request: Request) -> str:
    # Never trust X-Forwarded-For. CF-Connecting-IP is honoured only when enabled in
    # config and the peer is loopback (the local cloudflared connector), so a LAN
    # client cannot spoof it.
    peer = request.client.host if request.client else ""
    cfg: Config = request.app.state.cfg
    if cfg.trust_cloudflare_header and peer in _LOOPBACK:
        cf = request.headers.get("cf-connecting-ip", "").strip()
        if cf:
            return cf
    return peer


def session_user(
    request: Request,
    conn: sqlite3.Connection = Depends(get_conn),
    cfg: Config = Depends(get_cfg),
) -> Principal:
    """Any valid session, including one still waiting for its authenticator code.
    Only /me, logout and the MFA endpoints accept this."""
    p = resolve_session(conn, request.cookies.get(SESSION_COOKIE), cfg)
    if p is None:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return p


def from_staff_network(request: Request) -> bool:
    """True for the staff office/VPN networks in config, or the local console on this PC.
    A request that came through the tunnel is never 'local', whatever its peer address."""
    cfg: Config = request.app.state.cfg
    peer = request.client.host if request.client else ""
    via_tunnel = "cf-ray" in request.headers or "cf-connecting-ip" in request.headers
    if peer in _LOOPBACK and not via_tunnel:
        return True
    try:
        addr = ipaddress.ip_address(client_ip(request))
    except ValueError:
        addr = None
    if addr is not None and any(addr in ipaddress.ip_network(n, strict=False) for n in cfg.staff_networks):
        return True
    # Away from the office: a verified Cloudflare Access (Entra SSO) staff identity.
    from .access import staff_identity
    return staff_identity(request, cfg) is not None


STAFF_ONLY = "Staff accounts can only be used from the office network or VPN."


def current_user(request: Request, p: Principal = Depends(session_user)) -> Principal:
    """A session that passed MFA (mandatory for every role, no bypass). Superadmin sessions
    are additionally confined to staff networks on every request (ADR-0001)."""
    if not p.mfa_ok:
        raise HTTPException(status_code=403, detail="Authenticator code required.")
    if p.is_superadmin and not from_staff_network(request):
        raise HTTPException(status_code=403, detail=STAFF_ONLY)
    return p


STEP_UP = "step_up_required"


def recent_mfa(request: Request, p: Principal = Depends(current_user)) -> Principal:
    """Sensitive admin actions: the authenticator code must have been entered on this
    session within step_up_minutes; otherwise the UI asks for a fresh code and retries."""
    cfg: Config = request.app.state.cfg
    limit = iso(now_utc() - timedelta(minutes=cfg.step_up_minutes))
    if not p.mfa_verified_at or p.mfa_verified_at < limit:
        raise HTTPException(status_code=403, detail=STEP_UP)
    return p


def active_user(p: Principal = Depends(current_user)) -> Principal:
    """A user who has satisfied the forced password change."""
    if p.must_change_password:
        raise HTTPException(status_code=403, detail="Password change required.")
    return p


def require_superadmin(p: Principal = Depends(active_user)) -> Principal:
    if not p.is_superadmin:
        raise HTTPException(status_code=403, detail="Superadmin only.")
    return p


def require_admin(p: Principal = Depends(active_user)) -> Principal:
    if p.role not in ("superadmin", "customer_admin"):
        raise HTTPException(status_code=403, detail="Admin only.")
    return p


def require_admin_stepup(p: Principal = Depends(require_admin), _s: Principal = Depends(recent_mfa)) -> Principal:
    return p


def require_superadmin_stepup(p: Principal = Depends(require_superadmin), _s: Principal = Depends(recent_mfa)) -> Principal:
    return p
