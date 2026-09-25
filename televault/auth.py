"""Login, logout, session info, password change."""
from __future__ import annotations

import sqlite3

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from . import audit
from .config import Config
from .deps import STAFF_ONLY, client_ip, current_user, from_staff_network, get_cfg, get_conn, session_user
from .scope import Principal, load_memberships
from .security import (
    SESSION_COOKIE,
    account_locked,
    create_session,
    destroy_session,
    destroy_user_sessions,
    hash_password,
    password_policy_error,
    purge_expired_sessions,
    register_failure,
    register_success,
    verify_password,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class ChangePasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=1, max_length=256)


def _set_cookie(resp: Response, token: str, cfg: Config) -> None:
    resp.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=cfg.session_ttl_hours * 3600,
        httponly=True,
        secure=True,
        samesite="strict",
        path="/",
    )


def principal_json(p: Principal, conn: sqlite3.Connection) -> dict:
    customers = []
    if p.customer_ids:
        q = ",".join("?" * len(p.customer_ids))
        customers = [dict(r) for r in conn.execute(
            f"SELECT id, slug, name FROM customers WHERE id IN ({q}) ORDER BY name", p.customer_ids)]
    depts = []
    if p.department_ids:
        q = ",".join("?" * len(p.department_ids))
        depts = [dict(r) for r in conn.execute(
            f"SELECT d.id, d.name, d.customer_id, c.name AS customer_name FROM departments d "
            f"JOIN customers c ON c.id = d.customer_id WHERE d.id IN ({q}) ORDER BY c.name, d.name", p.department_ids)]
    return {
        "id": p.user_id,
        "username": p.username,
        "role": p.role,
        "customers": customers,
        "customer": customers[0] if len(customers) == 1 else None,  # single-customer convenience
        "departments": depts,
        "must_change_password": p.must_change_password,
        "mfa_ok": p.mfa_ok,
        "mfa_enrolled": p.mfa_enrolled,
    }


@router.post("/login")
def login(
    body: LoginIn,
    request: Request,
    response: Response,
    conn: sqlite3.Connection = Depends(get_conn),
    cfg: Config = Depends(get_cfg),
):
    ip = client_ip(request)
    limiter = request.app.state.ip_limiter
    if not limiter.allowed(ip):
        audit.log(conn, "login.ratelimited", ip=ip, username=body.username)
        raise HTTPException(status_code=429, detail="Too many attempts. Try again later.")

    row = conn.execute("SELECT * FROM users WHERE username = ?", (body.username,)).fetchone()
    generic = HTTPException(status_code=401, detail="Invalid username or password.")

    if row is None or not row["active"]:
        limiter.hit(ip)
        audit.log(conn, "login.fail", ip=ip, username=body.username, detail="unknown or inactive")
        # burn time so unknown users cost the same as wrong passwords
        verify_password(hash_password("x"), "y")
        raise generic

    if account_locked(row):
        limiter.hit(ip)
        audit.log(conn, "login.locked", ip=ip, username=row["username"], user_id=row["id"])
        raise HTTPException(status_code=423, detail="Account temporarily locked. Try again later.")

    if not verify_password(row["password_hash"], body.password):
        limiter.hit(ip)
        register_failure(conn, row["id"], cfg)
        audit.log(conn, "login.fail", ip=ip, username=row["username"], user_id=row["id"], customer_id=row["customer_id"])
        raise generic

    if row["role"] == "superadmin" and not from_staff_network(request):
        # Correct password from outside the staff networks: refuse, and leave a trail (ADR-0001).
        audit.log(conn, "login.staff_blocked", ip=ip, username=row["username"], user_id=row["id"])
        raise HTTPException(status_code=403, detail=STAFF_ONLY)

    register_success(conn, row["id"])
    purge_expired_sessions(conn)
    token = create_session(conn, row["id"], ip, request.headers.get("user-agent", ""), cfg)
    _set_cookie(response, token, cfg)
    # Password accepted; the session is useless until the authenticator code is verified.
    audit.log(conn, "login.password_ok", ip=ip, username=row["username"], user_id=row["id"], customer_id=row["customer_id"])
    cust_ids, dept_ids = load_memberships(conn, row["id"], row["role"], row["customer_id"])
    p = Principal(
        user_id=row["id"], username=row["username"], role=row["role"],
        customer_id=row["customer_id"], must_change_password=bool(row["must_change_password"]),
        mfa_ok=False, mfa_enrolled=bool(row["mfa_enabled"]),
        department_ids=dept_ids, customer_ids=cust_ids,
    )
    return principal_json(p, conn)


@router.get("/staff-login")
def staff_login(request: Request, conn: sqlite3.Connection = Depends(get_conn), cfg: Config = Depends(get_cfg)):
    """Protected by Cloudflare Access (Entra SSO) at the edge. Reaching it means Access has set
    the CF_Authorization cookie; log who, then send the browser back to the normal sign-in."""
    from fastapi.responses import RedirectResponse
    from .access import email_allowed, verified_email
    email = verified_email(request, cfg)
    if not email:
        audit.log(conn, "staff.sso.unverified", ip=client_ip(request), detail="no valid Access token")
    elif email_allowed(conn, email):
        audit.log(conn, "staff.sso.ok", ip=client_ip(request), username=email)
    else:
        # Owns the address but is not on the Staff access list: proof accepted, grants nothing.
        audit.log(conn, "staff.sso.not_listed", ip=client_ip(request), username=email)
    return RedirectResponse("/", status_code=303)


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    conn: sqlite3.Connection = Depends(get_conn),
):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        destroy_session(conn, token)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return {"ok": True}


@router.get("/me")
def me(p: Principal = Depends(session_user), conn: sqlite3.Connection = Depends(get_conn)):
    return principal_json(p, conn)


@router.post("/change-password")
def change_password(
    body: ChangePasswordIn,
    request: Request,
    response: Response,
    p: Principal = Depends(current_user),
    conn: sqlite3.Connection = Depends(get_conn),
    cfg: Config = Depends(get_cfg),
):
    row = conn.execute("SELECT password_hash FROM users WHERE id = ?", (p.user_id,)).fetchone()
    if not verify_password(row["password_hash"], body.current_password):
        audit.log(conn, "password.change.fail", ip=client_ip(request), username=p.username, user_id=p.user_id)
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    err = password_policy_error(body.new_password, cfg)
    if err:
        raise HTTPException(status_code=400, detail=err)
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must differ from the current one.")
    conn.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        (hash_password(body.new_password), p.user_id),
    )
    # rotate: every other session for this user is invalidated
    destroy_user_sessions(conn, p.user_id)
    # current_user guarantees this session already passed MFA, so the rotated one keeps it.
    token = create_session(conn, p.user_id, client_ip(request), request.headers.get("user-agent", ""), cfg, mfa_ok=True)
    _set_cookie(response, token, cfg)
    audit.log(conn, "password.change.ok", ip=client_ip(request), username=p.username, user_id=p.user_id, customer_id=p.customer_id)
    return {"ok": True}
