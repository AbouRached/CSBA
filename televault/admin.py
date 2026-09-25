"""Administration: customers, departments, users, audit log, reindex.

Superadmin: everything. Customer admin: departments and department users inside
their own customer only. Nobody can create a superadmin from the web.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import sqlite3
import string
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from . import audit, grants
from .config import Config
from .deps import (client_ip, get_cfg, get_conn, get_db, require_admin, require_admin_stepup, require_superadmin,
                   require_superadmin_stepup)
from .indexer import root_online
from .access import normalize_pattern
from .mfa import reset_user_mfa
from .scope import Principal
from .security import destroy_user_sessions, hash_password, password_policy_error

router = APIRouter(prefix="/api/admin", tags=["admin"])

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
_USERNAME = re.compile(r"^[A-Za-z0-9._@-]{3,64}$")
_NUM = re.compile(r"^[0-9*#+]{1,32}$")


def _gen_password() -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(16))
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)):
            return pw


def _clean_numbers(xs: list[str], what: str) -> list[str]:
    out = []
    for x in xs:
        x = str(x).strip()
        if not x:
            continue
        if not _NUM.match(x):
            raise HTTPException(400, f"Bad {what}: {x!r}")
        out.append(x)
    return sorted(set(out))


def _own_customer(p: Principal, customer_id: int) -> None:
    if not p.is_superadmin and p.customer_id != customer_id:
        raise HTTPException(403, "Not your customer.")


# ---------------------------------------------------------------- customers

class CustomerIn(BaseModel):
    slug: str
    name: str = Field(min_length=1, max_length=120)
    root_path: str = Field(min_length=2, max_length=260)
    enabled: bool = True


def _norm_root(p: str) -> str:
    """Comparable form of a root path: absolute, case-folded on Windows, trailing separator."""
    return os.path.normcase(os.path.abspath(p)).rstrip("\\/") + os.sep


def _check_root(conn: sqlite3.Connection, root: str, exclude_id: int | None = None) -> str:
    """Validate a customer root. Two customers must never share or nest folders, otherwise
    one customer's recordings would be indexed into the other's archive."""
    root = root.strip()
    if not os.path.isabs(root):
        raise HTTPException(400, "Root path must be absolute, e.g. D:\\ or E:\\Recordings\\Acme.")
    mine = _norm_root(root)
    for r in conn.execute("SELECT id, slug, root_path FROM customers").fetchall():
        if r["id"] == exclude_id:
            continue
        other = _norm_root(r["root_path"])
        if mine.startswith(other) or other.startswith(mine):
            raise HTTPException(409, f"Folder overlaps customer '{r['slug']}' ({r['root_path']}).")
    return root


@router.get("/customers")
def list_customers(p: Principal = Depends(require_admin), conn: sqlite3.Connection = Depends(get_conn),
                   cfg: Config = Depends(get_cfg)):
    if p.is_superadmin:
        rows = conn.execute("SELECT * FROM customers ORDER BY name").fetchall()
    else:
        rows = conn.execute("SELECT * FROM customers WHERE id = ?", (p.customer_id,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["online"] = root_online(r["root_path"])
        d["recordings"] = conn.execute("SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (r["id"],)).fetchone()[0]
        lr = conn.execute(
            "SELECT started_at, finished_at, status, files_seen, files_added, files_removed, message "
            "FROM index_runs WHERE customer_id = ? ORDER BY id DESC LIMIT 1", (r["id"],)).fetchone()
        d["last_index"] = dict(lr) if lr else None
        if p.is_superadmin:
            d["access"] = {**grants.access_status(r["root_path"], cfg), "grant": grants.last_grant(conn, r["id"])}
        out.append(d)
    return out


@router.post("/customers")
def create_customer(body: CustomerIn, request: Request, p: Principal = Depends(require_superadmin_stepup),
                    conn: sqlite3.Connection = Depends(get_conn)):
    if not _SLUG.match(body.slug):
        raise HTTPException(400, "Slug: lowercase letters, digits and dashes, 2-32 chars.")
    root = _check_root(conn, body.root_path)
    try:
        cur = conn.execute(
            "INSERT INTO customers(slug, name, root_path, enabled) VALUES (?,?,?,?)",
            (body.slug, body.name.strip(), root, int(body.enabled)),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Slug already exists.")
    audit.log(conn, "admin.customer.create", user_id=p.user_id, username=p.username,
              customer_id=cur.lastrowid, ip=client_ip(request), detail=f"{body.slug} -> {body.root_path}")
    _request_access(conn, request, p, cur.lastrowid, root)
    request.app.state.indexer.trigger()
    return {"id": cur.lastrowid}


def _request_access(conn: sqlite3.Connection, request: Request, p: Principal, cid: int, root: str) -> bool:
    gid = grants.queue_grant(conn, cid, root, p.username)
    if gid:
        audit.log(conn, "admin.access.request", user_id=p.user_id, username=p.username, customer_id=cid,
                  ip=client_ip(request), detail=f"read-only for service account on {root}")
    return gid is not None


@router.post("/customers/{cid}/grant-access")
def grant_access(cid: int, request: Request, p: Principal = Depends(require_superadmin_stepup),
                 conn: sqlite3.Connection = Depends(get_conn)):
    """Ask the SYSTEM grant worker to give the service account read-only access to this
    customer's folder (applied within about a minute)."""
    row = conn.execute("SELECT root_path FROM customers WHERE id = ?", (cid,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such customer.")
    queued = _request_access(conn, request, p, cid, row["root_path"])
    return {"queued": queued, "grant": grants.last_grant(conn, cid)}


@router.put("/customers/{cid}")
def update_customer(cid: int, body: CustomerIn, request: Request, p: Principal = Depends(require_superadmin_stepup),
                    conn: sqlite3.Connection = Depends(get_conn)):
    if not _SLUG.match(body.slug):
        raise HTTPException(400, "Bad slug.")
    old = conn.execute("SELECT root_path FROM customers WHERE id = ?", (cid,)).fetchone()
    if old is None:
        raise HTTPException(404, "No such customer.")
    root = _check_root(conn, body.root_path, exclude_id=cid)
    try:
        conn.execute("UPDATE customers SET slug=?, name=?, root_path=?, enabled=? WHERE id=?",
                     (body.slug, body.name.strip(), root, int(body.enabled), cid))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Slug already exists.")
    audit.log(conn, "admin.customer.update", user_id=p.user_id, username=p.username,
              customer_id=cid, ip=client_ip(request),
              detail=f"{body.slug} root {old['root_path']} -> {root} enabled={body.enabled}")
    if _norm_root(old["root_path"]) != _norm_root(root):
        # Rows from the old folder drop out of the index on the next run over the new one.
        _request_access(conn, request, p, cid, root)
        request.app.state.indexer.trigger()
    return {"ok": True}


@router.get("/customers/{cid}/folders")
def customer_folders(cid: int, path: str = "", p: Principal = Depends(require_admin),
                     conn: sqlite3.Connection = Depends(get_conn)):
    """Sub-folders of one customer's recording folder, for choosing department folders.
    Customer admins may use it for their own customer. Never leaves the customer root and
    returns folder names only."""
    _own_customer(p, cid)
    row = conn.execute("SELECT root_path FROM customers WHERE id = ?", (cid,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such customer.")
    root = Path(row["root_path"]).resolve()
    rel = "/".join(_clean_folders([path])) if path.strip("/\\ ") else ""
    target = (root / rel).resolve() if rel else root
    try:
        target.relative_to(root)
    except ValueError:
        raise HTTPException(400, "Outside the customer's folder.")
    dirs: list[str] = []
    try:
        with os.scandir(target) as it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False) and not e.name.startswith("$") \
                            and e.name.lower() not in _SKIP_DIRS:
                        dirs.append(e.name)
                except OSError:
                    continue
    except FileNotFoundError:
        raise HTTPException(404, "Folder not found or drive offline.")
    except PermissionError:
        raise HTTPException(403, "The service account cannot read this folder.")
    except OSError:
        raise HTTPException(404, "Folder not found or drive offline.")
    dirs.sort(key=str.lower)
    parent = rel.rsplit("/", 1)[0] if "/" in rel else ("" if rel else None)
    return {"root": row["root_path"], "path": rel, "parent": parent,
            "dirs": [{"name": d, "path": f"{rel}/{d}" if rel else d} for d in dirs[:1000]],
            "truncated": len(dirs) > 1000}


# ---------------------------------------------------------------- folder picker
# Superadmin-only, directory listing only: no file names, no contents, no writes.

_SKIP_DIRS = {"system volume information", "$recycle.bin", "recovery"}


def _volume_label(root: str) -> str:
    if os.name != "nt":
        return ""
    try:
        import ctypes
        buf = ctypes.create_unicode_buffer(261)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(ctypes.c_wchar_p(root), buf, 261, None, None, None, None, 0)
        return buf.value if ok else ""
    except Exception:  # noqa: BLE001
        return ""


def _owner_map(conn: sqlite3.Connection) -> list[tuple[str, dict]]:
    return [(_norm_root(r["root_path"]), {"id": r["id"], "slug": r["slug"], "name": r["name"]})
            for r in conn.execute("SELECT id, slug, name, root_path FROM customers")]


def _owners_of(path: str, owners: list[tuple[str, dict]]) -> dict:
    """Which customers use exactly this folder, and which sit inside / above it."""
    me = _norm_root(path)
    exact = [c for r, c in owners if r == me]
    overlap = [c for r, c in owners if r != me and (r.startswith(me) or me.startswith(r))]
    return {"assigned_to": exact, "overlaps": overlap}


@router.get("/fs/drives")
def fs_drives(p: Principal = Depends(require_superadmin), conn: sqlite3.Connection = Depends(get_conn)):
    roots = [f"{L}:\\" for L in string.ascii_uppercase] if os.name == "nt" else ["/"]
    owners = _owner_map(conn)
    out = []
    for root in roots:
        try:
            if not os.path.isdir(root):
                continue
            usage = shutil.disk_usage(root)
            total, free = usage.total, usage.free
        except OSError:
            continue
        out.append({"path": root, "label": _volume_label(root), "total": total, "free": free,
                    **_owners_of(root, owners)})
    return out


@router.get("/fs/browse")
def fs_browse(path: str, p: Principal = Depends(require_superadmin), conn: sqlite3.Connection = Depends(get_conn),
              cfg: Config = Depends(get_cfg)):
    if path.startswith(("\\\\", "//")):
        # Browsing a UNC path would make this PC authenticate to that host.
        raise HTTPException(400, "Network paths cannot be browsed; type the path instead.")
    if not os.path.isabs(path):
        raise HTTPException(400, "Path must be absolute.")
    base = Path(os.path.abspath(path))
    try:
        st = os.stat(base)
    except PermissionError:
        raise HTTPException(403, "The service account cannot read this folder.")
    except OSError:
        raise HTTPException(404, "Folder not found or drive offline.")
    import stat as _stat
    if not _stat.S_ISDIR(st.st_mode):
        raise HTTPException(404, "Folder not found or drive offline.")
    exts = set(cfg.audio_extensions)
    dirs: list[str] = []
    audio = 0
    try:
        with os.scandir(base) as it:
            for e in it:
                try:
                    if e.is_dir(follow_symlinks=False):
                        if not e.name.startswith("$") and e.name.lower() not in _SKIP_DIRS:
                            dirs.append(e.name)
                    elif os.path.splitext(e.name)[1].lower() in exts:
                        audio += 1
                except OSError:
                    continue
    except PermissionError:
        raise HTTPException(403, "The service account cannot read this folder.")
    owners = _owner_map(conn)
    dirs.sort(key=str.lower)
    parent = str(base.parent) if base.parent != base else None
    return {
        "path": str(base), "parent": parent, "audio_files_here": audio, "truncated": len(dirs) > 1000,
        "dirs": [{"name": d, "path": str(base / d), **_owners_of(str(base / d), owners)} for d in dirs[:1000]],
        **_owners_of(str(base), owners),
    }


@router.post("/customers/{cid}/reindex")
def reindex_customer(cid: int, request: Request, p: Principal = Depends(require_admin),
                     conn: sqlite3.Connection = Depends(get_conn)):
    _own_customer(p, cid)
    if conn.execute("SELECT 1 FROM customers WHERE id = ?", (cid,)).fetchone() is None:
        raise HTTPException(404, "No such customer.")
    request.app.state.indexer.trigger()
    audit.log(conn, "admin.reindex", user_id=p.user_id, username=p.username, customer_id=cid, ip=client_ip(request))
    return {"ok": True, "queued": True}


# ---------------------------------------------------------------- departments

class DepartmentIn(BaseModel):
    customer_id: int
    name: str = Field(min_length=1, max_length=80)
    extensions: list[str] = Field(default_factory=list, max_length=2000)
    queues: list[str] = Field(default_factory=list, max_length=500)
    dids: list[str] = Field(default_factory=list, max_length=500)
    folders: list[str] = Field(default_factory=list, max_length=200)


def _clean_folders(xs: list[str]) -> list[str]:
    """Folders are stored relative to the customer root, '/'-separated, never escaping it."""
    out = []
    for x in xs:
        f = str(x).strip().replace("\\", "/").strip("/")
        if not f:
            continue
        parts = [p for p in f.split("/") if p not in ("", ".")]
        if not parts or ".." in parts or ":" in f or len(f) > 400:
            raise HTTPException(400, f"Bad folder: {x!r} (use a folder inside the customer's drive, e.g. Support/2026)")
        out.append("/".join(parts))
    return sorted(set(out), key=str.lower)


def _dept_json(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"], "customer_id": r["customer_id"], "name": r["name"],
        "extensions": json.loads(r["extensions_json"]),
        "queues": json.loads(r["queues_json"]),
        "dids": json.loads(r["dids_json"]),
        "folders": json.loads(r["folders_json"] or "[]"),
    }


@router.get("/departments")
def list_departments(customer_id: int | None = None, p: Principal = Depends(require_admin),
                     conn: sqlite3.Connection = Depends(get_conn)):
    cid = customer_id if p.is_superadmin else p.customer_id
    if cid is None:
        rows = conn.execute("SELECT * FROM departments ORDER BY customer_id, name").fetchall()
    else:
        rows = conn.execute("SELECT * FROM departments WHERE customer_id = ? ORDER BY name", (cid,)).fetchall()
    return [_dept_json(r) for r in rows]


@router.post("/departments")
def create_department(body: DepartmentIn, request: Request, p: Principal = Depends(require_admin),
                      conn: sqlite3.Connection = Depends(get_conn)):
    _own_customer(p, body.customer_id)
    if conn.execute("SELECT 1 FROM customers WHERE id = ?", (body.customer_id,)).fetchone() is None:
        raise HTTPException(404, "No such customer.")
    try:
        cur = conn.execute(
            "INSERT INTO departments(customer_id, name, extensions_json, queues_json, dids_json, folders_json) "
            "VALUES (?,?,?,?,?,?)",
            (body.customer_id, body.name.strip(),
             json.dumps(_clean_numbers(body.extensions, "extension")),
             json.dumps(_clean_numbers(body.queues, "queue")),
             json.dumps(_clean_numbers(body.dids, "DID")),
             json.dumps(_clean_folders(body.folders))),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Department name already exists for this customer.")
    audit.log(conn, "admin.department.create", user_id=p.user_id, username=p.username,
              customer_id=body.customer_id, ip=client_ip(request), detail=body.name)
    return {"id": cur.lastrowid}


@router.put("/departments/{did}")
def update_department(did: int, body: DepartmentIn, request: Request, p: Principal = Depends(require_admin),
                      conn: sqlite3.Connection = Depends(get_conn)):
    row = conn.execute("SELECT * FROM departments WHERE id = ?", (did,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such department.")
    _own_customer(p, row["customer_id"])
    try:
        conn.execute(
            "UPDATE departments SET name=?, extensions_json=?, queues_json=?, dids_json=?, folders_json=? WHERE id=?",
            (body.name.strip(), json.dumps(_clean_numbers(body.extensions, "extension")),
             json.dumps(_clean_numbers(body.queues, "queue")), json.dumps(_clean_numbers(body.dids, "DID")),
             json.dumps(_clean_folders(body.folders)), did),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Department name already exists for this customer.")
    audit.log(conn, "admin.department.update", user_id=p.user_id, username=p.username,
              customer_id=row["customer_id"], ip=client_ip(request), detail=body.name)
    return {"ok": True}


@router.delete("/departments/{did}")
def delete_department(did: int, request: Request, p: Principal = Depends(require_admin),
                      conn: sqlite3.Connection = Depends(get_conn)):
    row = conn.execute("SELECT * FROM departments WHERE id = ?", (did,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such department.")
    _own_customer(p, row["customer_id"])
    conn.execute("DELETE FROM departments WHERE id = ?", (did,))
    audit.log(conn, "admin.department.delete", user_id=p.user_id, username=p.username,
              customer_id=row["customer_id"], ip=client_ip(request), detail=row["name"])
    return {"ok": True}


# ---------------------------------------------------------------- users

class UserIn(BaseModel):
    username: str
    display_name: str = Field(default="", max_length=120)
    role: str  # customer_admin | department
    customer_id: int | None = None
    department_ids: list[int] = Field(default_factory=list, max_length=200)
    active: bool = True
    password: str | None = None  # omitted => generated and returned once


def _user_json(conn: sqlite3.Connection, r: sqlite3.Row) -> dict:
    depts = [x["department_id"] for x in conn.execute(
        "SELECT department_id FROM user_departments WHERE user_id = ?", (r["id"],))]
    return {
        "id": r["id"], "username": r["username"], "display_name": r["display_name"], "role": r["role"],
        "customer_id": r["customer_id"], "department_ids": depts, "active": bool(r["active"]),
        "must_change_password": bool(r["must_change_password"]), "mfa_enabled": bool(r["mfa_enabled"]),
        "last_login": r["last_login"],
        "locked_until": r["locked_until"], "created_at": r["created_at"],
    }


def _validate_user(conn: sqlite3.Connection, p: Principal, body: UserIn) -> tuple[int, list[int]]:
    if not _USERNAME.match(body.username):
        raise HTTPException(400, "Username: 3-64 chars, letters, digits, . _ @ -")
    if body.role not in ("customer_admin", "department"):
        raise HTTPException(400, "Role must be customer_admin or department.")
    if not p.is_superadmin and body.role == "customer_admin":
        raise HTTPException(403, "Only staff (superadmins) can create customer admins.")
    cid = body.customer_id if p.is_superadmin else p.customer_id
    if cid is None:
        raise HTTPException(400, "customer_id is required.")
    if conn.execute("SELECT 1 FROM customers WHERE id = ?", (cid,)).fetchone() is None:
        raise HTTPException(404, "No such customer.")
    dept_ids: list[int] = []
    if body.role == "department":
        if not body.department_ids:
            raise HTTPException(400, "A department user needs at least one department.")
        q = ",".join("?" * len(body.department_ids))
        rows = conn.execute(
            f"SELECT id FROM departments WHERE id IN ({q}) AND customer_id = ?", body.department_ids + [cid]
        ).fetchall()
        dept_ids = [r["id"] for r in rows]
        if len(dept_ids) != len(set(body.department_ids)):
            raise HTTPException(400, "One or more departments do not belong to this customer.")
    return cid, dept_ids


@router.get("/users")
def list_users(customer_id: int | None = None, p: Principal = Depends(require_admin),
               conn: sqlite3.Connection = Depends(get_conn)):
    if p.is_superadmin:
        if customer_id is None:
            rows = conn.execute("SELECT * FROM users ORDER BY customer_id, username").fetchall()
        else:
            rows = conn.execute("SELECT * FROM users WHERE customer_id = ? ORDER BY username", (customer_id,)).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM users WHERE customer_id = ? AND role <> 'superadmin' ORDER BY username", (p.customer_id,)
        ).fetchall()
    return [_user_json(conn, r) for r in rows]


@router.post("/users")
def create_user(body: UserIn, request: Request, p: Principal = Depends(require_admin_stepup),
                conn: sqlite3.Connection = Depends(get_conn), cfg: Config = Depends(get_cfg)):
    cid, dept_ids = _validate_user(conn, p, body)
    pw = body.password or _gen_password()
    err = password_policy_error(pw, cfg)
    if err:
        raise HTTPException(400, err)
    try:
        cur = conn.execute(
            "INSERT INTO users(customer_id, username, password_hash, role, display_name, must_change_password, active) "
            "VALUES (?,?,?,?,?,1,?)",
            (cid, body.username, hash_password(pw), body.role, body.display_name.strip(), int(body.active)),
        )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists.")
    uid = cur.lastrowid
    conn.executemany("INSERT INTO user_departments(user_id, department_id) VALUES (?,?)",
                     [(uid, d) for d in dept_ids])
    audit.log(conn, "admin.user.create", user_id=p.user_id, username=p.username, customer_id=cid,
              ip=client_ip(request), detail=f"{body.username} role={body.role} depts={dept_ids}")
    # The initial password is shown exactly once, to the admin who created the account.
    return {"id": uid, "initial_password": pw}


@router.put("/users/{uid}")
def update_user(uid: int, body: UserIn, request: Request, p: Principal = Depends(require_admin_stepup),
                conn: sqlite3.Connection = Depends(get_conn)):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None or row["role"] == "superadmin":
        raise HTTPException(404, "No such user.")
    _own_customer(p, row["customer_id"])
    if not p.is_superadmin and row["role"] == "customer_admin":
        raise HTTPException(403, "Only staff (superadmins) can edit customer admins.")
    body.customer_id = row["customer_id"]
    cid, dept_ids = _validate_user(conn, p, body)
    try:
        conn.execute("UPDATE users SET username=?, display_name=?, role=?, active=? WHERE id=?",
                     (body.username, body.display_name.strip(), body.role, int(body.active), uid))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Username already exists.")
    conn.execute("DELETE FROM user_departments WHERE user_id = ?", (uid,))
    conn.executemany("INSERT INTO user_departments(user_id, department_id) VALUES (?,?)",
                     [(uid, d) for d in dept_ids])
    if not body.active:
        destroy_user_sessions(conn, uid)
    audit.log(conn, "admin.user.update", user_id=p.user_id, username=p.username, customer_id=cid,
              ip=client_ip(request), detail=f"{body.username} role={body.role} active={body.active} depts={dept_ids}")
    return {"ok": True}


@router.post("/users/{uid}/reset-password")
def reset_password(uid: int, request: Request, p: Principal = Depends(require_admin_stepup),
                   conn: sqlite3.Connection = Depends(get_conn)):
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None or row["role"] == "superadmin":
        raise HTTPException(404, "No such user.")
    _own_customer(p, row["customer_id"])
    if not p.is_superadmin and row["role"] == "customer_admin":
        raise HTTPException(403, "Only staff (superadmins) can reset customer admins.")
    pw = _gen_password()
    conn.execute(
        "UPDATE users SET password_hash=?, must_change_password=1, failed_attempts=0, locked_until=NULL WHERE id=?",
        (hash_password(pw), uid),
    )
    destroy_user_sessions(conn, uid)
    audit.log(conn, "admin.user.reset_password", user_id=p.user_id, username=p.username,
              customer_id=row["customer_id"], ip=client_ip(request), detail=row["username"])
    return {"initial_password": pw}


@router.post("/users/{uid}/reset-mfa")
def reset_mfa(uid: int, request: Request, p: Principal = Depends(require_admin_stepup),
              conn: sqlite3.Connection = Depends(get_conn)):
    """Lost or replaced phone: the user must scan a new QR code at next sign-in.
    Superadmin authenticators are reset only on the console (cli reset-mfa)."""
    row = conn.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if row is None or row["role"] == "superadmin":
        raise HTTPException(404, "No such user.")
    _own_customer(p, row["customer_id"])
    if not p.is_superadmin and row["role"] == "customer_admin":
        raise HTTPException(403, "Only staff (superadmins) can reset customer admins.")
    reset_user_mfa(conn, uid)
    audit.log(conn, "admin.user.reset_mfa", user_id=p.user_id, username=p.username,
              customer_id=row["customer_id"], ip=client_ip(request), detail=row["username"])
    return {"ok": True}


# ---------------------------------------------------------------- staff access (Cloudflare Access list)

class StaffAccessIn(BaseModel):
    pattern: str = Field(min_length=3, max_length=254)  # someone@any-domain.com  or  @any-domain.com
    note: str = Field(default="", max_length=200)


@router.get("/staff-access")
def list_staff_access(p: Principal = Depends(require_superadmin), conn: sqlite3.Connection = Depends(get_conn)):
    return [dict(r) for r in conn.execute("SELECT * FROM staff_access ORDER BY pattern")]


@router.post("/staff-access")
def add_staff_access(body: StaffAccessIn, request: Request, p: Principal = Depends(require_superadmin_stepup),
                     conn: sqlite3.Connection = Depends(get_conn)):
    pattern = normalize_pattern(body.pattern)
    if pattern is None:
        raise HTTPException(400, "Enter a full email address (name@domain.com) or a domain (@domain.com).")
    try:
        cur = conn.execute("INSERT INTO staff_access(pattern, note, created_by) VALUES (?,?,?)",
                           (pattern, body.note.strip(), p.username))
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Already on the list.")
    audit.log(conn, "admin.staff_access.add", user_id=p.user_id, username=p.username, ip=client_ip(request),
              detail=f"{pattern} {body.note.strip()}".strip())
    return {"id": cur.lastrowid, "pattern": pattern}


@router.delete("/staff-access/{sid}")
def remove_staff_access(sid: int, request: Request, p: Principal = Depends(require_superadmin_stepup),
                        conn: sqlite3.Connection = Depends(get_conn)):
    row = conn.execute("SELECT pattern FROM staff_access WHERE id = ?", (sid,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such entry.")
    conn.execute("DELETE FROM staff_access WHERE id = ?", (sid,))
    audit.log(conn, "admin.staff_access.remove", user_id=p.user_id, username=p.username, ip=client_ip(request),
              detail=row["pattern"])
    return {"ok": True}


# ---------------------------------------------------------------- MCP tokens (Developer access)

class McpTokenIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    scope: str = "read"


@router.get("/mcp-tokens")
def list_mcp_tokens(p: Principal = Depends(require_superadmin), conn: sqlite3.Connection = Depends(get_conn),
                    cfg: Config = Depends(get_cfg)):
    rows = conn.execute("SELECT id, name, scope, created_by, created_at, last_used_at, revoked_at "
                        "FROM mcp_tokens ORDER BY revoked_at IS NOT NULL, id DESC").fetchall()
    return {"endpoint": f"http://127.0.0.1:{cfg.mcp_port}/mcp" if cfg.mcp_port else None,
            "tokens": [dict(r) for r in rows]}


@router.post("/mcp-tokens")
def create_mcp_token(body: McpTokenIn, request: Request, p: Principal = Depends(require_superadmin_stepup),
                     conn: sqlite3.Connection = Depends(get_conn), cfg: Config = Depends(get_cfg)):
    from .mcp_server import create_token
    if body.scope not in ("read", "operate"):
        raise HTTPException(400, "Scope must be read or operate.")
    if not cfg.mcp_port:
        raise HTTPException(409, "The MCP endpoint is disabled (mcp_port = 0 in config.json).")
    tid, token = create_token(conn, body.name.strip(), body.scope, p.username)
    audit.log(conn, "admin.mcp_token.create", user_id=p.user_id, username=p.username, ip=client_ip(request),
              detail=f"#{tid} {body.name.strip()} scope={body.scope}")
    url = f"http://127.0.0.1:{cfg.mcp_port}/mcp"
    # Shown exactly once, to the superadmin who created it.
    return {"id": tid, "token": token, "endpoint": url,
            "claude_command": f'claude mcp add --transport http televault {url} --header "Authorization: Bearer {token}"'}


@router.delete("/mcp-tokens/{tid}")
def revoke_mcp_token(tid: int, request: Request, p: Principal = Depends(require_superadmin_stepup),
                     conn: sqlite3.Connection = Depends(get_conn)):
    row = conn.execute("SELECT name, revoked_at FROM mcp_tokens WHERE id = ?", (tid,)).fetchone()
    if row is None:
        raise HTTPException(404, "No such token.")
    if row["revoked_at"] is None:
        conn.execute("UPDATE mcp_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?", (tid,))
        audit.log(conn, "admin.mcp_token.revoke", user_id=p.user_id, username=p.username, ip=client_ip(request),
                  detail=f"#{tid} {row['name']}")
    return {"ok": True}


# ---------------------------------------------------------------- audit

@router.get("/audit")
def audit_log(customer_id: int | None = None, action: str | None = None, page: int = 1,
              p: Principal = Depends(require_admin), conn: sqlite3.Connection = Depends(get_conn)):
    page = max(1, min(page, 100000))
    clauses, params = [], []
    cid = customer_id if p.is_superadmin else p.customer_id
    if cid is not None:
        clauses.append("customer_id = ?")
        params.append(cid)
    if action:
        clauses.append("action LIKE ?")
        params.append(action.replace("%", "") + "%")
    where = " AND ".join(clauses) if clauses else "1"
    total = conn.execute(f"SELECT COUNT(*) FROM audit_log WHERE {where}", params).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM audit_log WHERE {where} ORDER BY id DESC LIMIT 100 OFFSET ?", params + [(page - 1) * 100]
    ).fetchall()
    return {"total": total, "page": page, "items": [dict(r) for r in rows]}


@router.get("/status")
def status(request: Request, p: Principal = Depends(require_admin), conn: sqlite3.Connection = Depends(get_conn)):
    idx = request.app.state.indexer
    return {
        "indexer_running": idx.running,
        "indexer_last_run": idx.last_run,
        "recordings": conn.execute("SELECT COUNT(*) FROM recordings").fetchone()[0] if p.is_superadmin else None,
        "sessions": conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] if p.is_superadmin else None,
    }
