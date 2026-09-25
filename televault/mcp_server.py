"""TeleVault MCP endpoint: troubleshooting and development tools for AI assistants (Claude Code etc.).

Transport: MCP "Streamable HTTP" (JSON responses, stateless), implemented directly - the
protocol surface TeleVault needs is small and this avoids tracking an SDK's major versions.

Security model
- Served on its own listener bound to 127.0.0.1 (config `mcp_port`), never through the
  Cloudflare tunnel and never on the LAN. Requests from a non-loopback peer or with a Host
  header other than localhost/127.0.0.1 are refused (DNS-rebinding protection).
- Every request needs `Authorization: Bearer tv_...`. Tokens are created by a superadmin in
  the admin UI (Developer access), shown once, stored as SHA-256, revocable.
- Scopes: `read` (inspect only) and `operate` (also reindex / unlock a user / request folder
  access). Nothing here plays or downloads audio, deletes data, or touches passwords or MFA.
- Every tools/call is written to the audit log (and so to the Windows Event Log) under the
  token's name.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import traceback
from collections import Counter
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from . import __version__, audit, grants
from .config import APP_NAME, Config
from .db import Database
from .indexer import index_customer, root_online
from .parser import parse_filename
from .scope import Principal, department_predicate, load_dept_rules, scope_sql
from .security import iso, now_utc

SUPPORTED_VERSIONS = ["2025-06-18", "2025-03-26", "2024-11-05"]
TOKEN_PREFIX = "tv_"
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "[::1]"}


# ---------------------------------------------------------------- tokens

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(conn: sqlite3.Connection, name: str, scope: str, created_by: str) -> tuple[int, str]:
    if scope not in ("read", "operate"):
        raise ValueError("scope must be read or operate")
    token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    tid = conn.execute("INSERT INTO mcp_tokens(name, token_hash, scope, created_by) VALUES (?,?,?,?)",
                       (name, hash_token(token), scope, created_by)).lastrowid
    return tid, token


def _auth(conn: sqlite3.Connection, header: str) -> sqlite3.Row | None:
    if not header.lower().startswith("bearer "):
        return None
    token = header[7:].strip()
    if not token.startswith(TOKEN_PREFIX):
        return None
    row = conn.execute("SELECT * FROM mcp_tokens WHERE token_hash = ? AND revoked_at IS NULL",
                       (hash_token(token),)).fetchone()
    if row:
        conn.execute("UPDATE mcp_tokens SET last_used_at = ? WHERE id = ?", (iso(now_utc()), row["id"]))
    return row


# ---------------------------------------------------------------- tool helpers

class ToolError(Exception):
    """Reported to the client as a tool result with isError=true."""


def _customer(conn: sqlite3.Connection, ref: Any) -> sqlite3.Row:
    ref = str(ref or "").strip()
    if not ref:
        raise ToolError("customer is required (slug or id)")
    row = conn.execute("SELECT * FROM customers WHERE slug = ? OR CAST(id AS TEXT) = ?", (ref, ref)).fetchone()
    if row is None:
        raise ToolError(f"no customer {ref!r}")
    return row


def _principal(conn: sqlite3.Connection, username: str) -> Principal:
    u = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if u is None:
        raise ToolError(f"no user {username!r}")
    depts = [r["department_id"] for r in conn.execute("SELECT department_id FROM user_departments WHERE user_id = ?", (u["id"],))]
    return Principal(user_id=u["id"], username=u["username"], role=u["role"], customer_id=u["customer_id"],
                     department_ids=depts, must_change_password=bool(u["must_change_password"]), mfa_ok=True)


def _int(v: Any, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------- tools

class Tools:
    def __init__(self, cfg: Config, db: Database, indexer: Any):
        self.cfg, self.db, self.indexer = cfg, db, indexer
        S = lambda props=None, req=None: {"type": "object", "properties": props or {}, "required": req or [],
                                           "additionalProperties": False}
        cust = {"type": "string", "description": "customer slug (e.g. acme) or numeric id"}
        # name -> (scope, description, input schema, handler)
        self.table: dict[str, tuple[str, str, dict, Callable]] = {
            "health": ("read", "Service health: indexer, customer drives online/offline, last index run, "
                       "disk space, service-account folder access, pending folder-access requests, sessions.",
                       S(), self.health),
            "get_config": ("read", "The running configuration (config.json merged with defaults). No secrets are stored in it.",
                           S(), self.get_config),
            "tail_log": ("read", "Last lines of the server log (data/televault.log), optionally filtered by a substring.",
                         S({"lines": {"type": "integer", "minimum": 1, "maximum": 2000, "default": 200},
                            "contains": {"type": "string"}}), self.tail_log),
            "audit_log": ("read", "Audit trail (logins, MFA, plays, downloads, admin changes, MCP calls), newest first.",
                          S({"action_prefix": {"type": "string", "description": "e.g. login., mfa., admin., recording."},
                             "username": {"type": "string"}, "customer": cust,
                             "since_hours": {"type": "integer", "minimum": 1, "maximum": 2160, "default": 24},
                             "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 100}}), self.audit_log),
            "list_customers": ("read", "Customers with recording folder, drive state, file count, last index run and service-account access.",
                               S(), self.list_customers),
            "list_departments": ("read", "Departments of a customer and their rules (extensions, queues, DIDs, folders).",
                                 S({"customer": cust}, ["customer"]), self.list_departments),
            "list_users": ("read", "Users (optionally of one customer): role, departments, active, MFA set up, lockout, last login. No secrets.",
                           S({"customer": cust}), self.list_users),
            "index_runs": ("read", "Recent indexer runs for a customer (status, files seen/added/removed, errors).",
                           S({"customer": cust, "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20}},
                             ["customer"]), self.index_runs),
            "recording_stats": ("read", "Aggregate statistics of a customer's indexed recordings: by type, empty, unparsed, "
                                "date range and the busiest folders (useful for department folder rules). No audio.",
                                S({"customer": cust}, ["customer"]), self.recording_stats),
            "list_folders": ("read", "Sub-folders of a customer's recording folder (names only).",
                             S({"customer": cust, "path": {"type": "string", "description": "relative, e.g. 2026/08"}},
                               ["customer"]), self.list_folders),
            "explain_access": ("read", "Can USER see RECORDING, and why? Uses the same authorization code as the web app. "
                               "recording = numeric id or exact filename.",
                               S({"username": {"type": "string"}, "recording": {"type": "string"}},
                                 ["username", "recording"]), self.explain_access),
            "parse_filename": ("read", "Parse a FreePBX recording filename and, if a customer is given, show which of its departments it would belong to.",
                               S({"filename": {"type": "string"}, "customer": cust}, ["filename"]), self.parse_filename),
            "access_requests": ("read", "Folder-access (grant worker) requests, newest first.",
                                S({"customer": cust, "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20}}),
                                self.access_requests),
            "reindex": ("operate", "Re-scan one customer's recording folder now and return the result.",
                        S({"customer": cust}, ["customer"]), self.reindex),
            "unlock_user": ("operate", "Clear a user's failed-login counter and lockout (does not change the password or MFA).",
                            S({"username": {"type": "string"}}, ["username"]), self.unlock_user),
            "request_folder_access": ("operate", "Queue a read-only folder-access request for a customer's folder "
                                      "(applied by the SYSTEM grant worker within a minute).",
                                      S({"customer": cust}, ["customer"]), self.request_folder_access),
        }

    def list(self, scope: str) -> list[dict]:
        return [{"name": n, "description": d + ("" if s == "read" else " [operate scope]"), "inputSchema": schema}
                for n, (s, d, schema, _) in self.table.items() if s == "read" or scope == "operate"]

    # -- read tools -------------------------------------------------------------

    def health(self, conn, a):
        customers = []
        for c in conn.execute("SELECT * FROM customers ORDER BY slug"):
            last = conn.execute("SELECT started_at, finished_at, status, files_seen, message FROM index_runs "
                                "WHERE customer_id = ? ORDER BY id DESC LIMIT 1", (c["id"],)).fetchone()
            disk = None
            try:
                import shutil
                u = shutil.disk_usage(c["root_path"])
                disk = {"free_gb": round(u.free / 1e9, 1), "total_gb": round(u.total / 1e9, 1)}
            except OSError:
                pass
            customers.append({
                "slug": c["slug"], "enabled": bool(c["enabled"]), "root": c["root_path"],
                "online": root_online(c["root_path"]),
                "recordings": conn.execute("SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (c["id"],)).fetchone()[0],
                "last_index": dict(last) if last else None, "disk": disk,
                "service_access": grants.access_status(c["root_path"], self.cfg),
            })
        return {
            "app": APP_NAME, "version": __version__, "time_utc": iso(now_utc()), "pid": os.getpid(),
            "indexer": {"running": getattr(self.indexer, "running", None), "last_run": getattr(self.indexer, "last_run", None),
                        "interval_minutes": self.cfg.index_interval_minutes},
            "customers": customers,
            "pending_access_requests": conn.execute(
                "SELECT COUNT(*) FROM access_grants WHERE status IN ('pending','running')").fetchone()[0],
            "active_sessions": conn.execute("SELECT COUNT(*) FROM sessions WHERE expires_at > ?", (iso(now_utc()),)).fetchone()[0],
            "locked_users": [r["username"] for r in conn.execute(
                "SELECT username FROM users WHERE locked_until > ?", (iso(now_utc()),))],
        }

    def get_config(self, conn, a):
        d = {k: (str(v) if isinstance(v, Path) else v) for k, v in vars(self.cfg).items()}
        return d

    def tail_log(self, conn, a):
        path = self.cfg.data_dir / "televault.log"
        if not path.exists():
            return {"log": str(path), "lines": []}
        n = _int(a.get("lines"), 200, 1, 2000)
        needle = str(a.get("contains") or "")
        with path.open("rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 4_000_000))
            lines = fh.read().decode("utf-8", "replace").splitlines()
        if needle:
            lines = [l for l in lines if needle.lower() in l.lower()]
        return {"log": str(path), "lines": lines[-n:]}

    def audit_log(self, conn, a):
        clauses, params = ["ts >= ?"], [iso(now_utc() - timedelta(hours=_int(a.get("since_hours"), 24, 1, 2160)))]
        if a.get("action_prefix"):
            clauses.append("action LIKE ?"); params.append(str(a["action_prefix"]).replace("%", "") + "%")
        if a.get("username"):
            clauses.append("username = ?"); params.append(str(a["username"]))
        if a.get("customer"):
            clauses.append("customer_id = ?"); params.append(_customer(conn, a["customer"])["id"])
        rows = conn.execute(f"SELECT ts, username, customer_id, ip, action, detail FROM audit_log WHERE {' AND '.join(clauses)} "
                            f"ORDER BY id DESC LIMIT ?", params + [_int(a.get("limit"), 100, 1, 500)]).fetchall()
        return [dict(r) for r in rows]

    def list_customers(self, conn, a):
        out = []
        for c in conn.execute("SELECT * FROM customers ORDER BY slug"):
            last = conn.execute("SELECT finished_at, status, files_seen, message FROM index_runs WHERE customer_id = ? "
                                "ORDER BY id DESC LIMIT 1", (c["id"],)).fetchone()
            out.append({"id": c["id"], "slug": c["slug"], "name": c["name"], "root": c["root_path"],
                        "enabled": bool(c["enabled"]), "online": root_online(c["root_path"]),
                        "recordings": conn.execute("SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (c["id"],)).fetchone()[0],
                        "last_index": dict(last) if last else None,
                        "service_access": grants.access_status(c["root_path"], self.cfg),
                        "last_access_request": grants.last_grant(conn, c["id"])})
        return out

    def list_departments(self, conn, a):
        c = _customer(conn, a.get("customer"))
        out = []
        for d in conn.execute("SELECT * FROM departments WHERE customer_id = ? ORDER BY name", (c["id"],)):
            users = [r["username"] for r in conn.execute(
                "SELECT u.username FROM users u JOIN user_departments ud ON ud.user_id = u.id WHERE ud.department_id = ?", (d["id"],))]
            out.append({"id": d["id"], "name": d["name"], "extensions": json.loads(d["extensions_json"]),
                        "queues": json.loads(d["queues_json"]), "dids": json.loads(d["dids_json"]),
                        "folders": json.loads(d["folders_json"] or "[]"), "users": users})
        return out

    def list_users(self, conn, a):
        q, params = "SELECT u.*, c.slug FROM users u LEFT JOIN customers c ON c.id = u.customer_id", []
        if a.get("customer"):
            q += " WHERE u.customer_id = ?"; params.append(_customer(conn, a["customer"])["id"])
        out = []
        for u in conn.execute(q + " ORDER BY u.username", params):
            depts = [r["name"] for r in conn.execute(
                "SELECT d.name FROM departments d JOIN user_departments ud ON ud.department_id = d.id WHERE ud.user_id = ?", (u["id"],))]
            out.append({"username": u["username"], "role": u["role"], "customer": u["slug"], "departments": depts,
                        "active": bool(u["active"]), "mfa_set_up": bool(u["mfa_enabled"]),
                        "must_change_password": bool(u["must_change_password"]), "failed_attempts": u["failed_attempts"],
                        "locked_until": u["locked_until"], "last_login": u["last_login"]})
        return out

    def index_runs(self, conn, a):
        c = _customer(conn, a.get("customer"))
        return [dict(r) for r in conn.execute("SELECT * FROM index_runs WHERE customer_id = ? ORDER BY id DESC LIMIT ?",
                                              (c["id"], _int(a.get("limit"), 20, 1, 200)))]

    def recording_stats(self, conn, a):
        c = _customer(conn, a.get("customer"))
        cid = c["id"]
        by_type = {r["rec_type"]: r["n"] for r in conn.execute(
            "SELECT rec_type, COUNT(*) n FROM recordings WHERE customer_id = ? GROUP BY rec_type", (cid,))}
        span = conn.execute("SELECT MIN(rec_ts), MAX(rec_ts), COUNT(*), COALESCE(SUM(size),0), SUM(empty) "
                            "FROM recordings WHERE customer_id = ?", (cid,)).fetchone()
        folders: Counter = Counter()
        for (rel,) in conn.execute("SELECT rel_path FROM recordings WHERE customer_id = ?", (cid,)):
            parts = rel.split("/")[:-1]
            for depth in (1, 2):
                if len(parts) >= depth:
                    folders["/".join(parts[:depth])] += 1
        unparsed = [r[0] for r in conn.execute(
            "SELECT rel_path FROM recordings WHERE customer_id = ? AND rec_type = 'unknown' LIMIT 20", (cid,))]
        return {"customer": c["slug"], "total": span[2], "bytes": span[3], "empty": span[4] or 0,
                "first": span[0], "last": span[1], "by_type": by_type,
                "top_folders": [{"folder": f, "recordings": n} for f, n in folders.most_common(25)],
                "unparsed_samples": unparsed}

    def list_folders(self, conn, a):
        c = _customer(conn, a.get("customer"))
        root = Path(c["root_path"]).resolve()
        rel = str(a.get("path") or "").replace("\\", "/").strip("/")
        if ".." in rel.split("/") or ":" in rel:
            raise ToolError("path must stay inside the customer's folder")
        target = (root / rel).resolve() if rel else root
        try:
            target.relative_to(root)
        except ValueError:
            raise ToolError("path must stay inside the customer's folder")
        try:
            with os.scandir(target) as it:
                dirs = sorted((e.name for e in it if e.is_dir(follow_symlinks=False) and not e.name.startswith("$")), key=str.lower)
        except OSError as e:
            raise ToolError(f"cannot list {target}: {e.strerror or e}")
        return {"root": c["root_path"], "path": rel, "folders": dirs[:1000], "truncated": len(dirs) > 1000}

    def explain_access(self, conn, a):
        p = _principal(conn, str(a["username"]))
        ref = str(a["recording"]).strip()
        rec = conn.execute("SELECT r.*, c.slug FROM recordings r JOIN customers c ON c.id = r.customer_id "
                           "WHERE CAST(r.id AS TEXT) = ? OR r.filename = ? ORDER BY r.id LIMIT 2", (ref, ref)).fetchall()
        if not rec:
            raise ToolError(f"no indexed recording {ref!r} (is the drive indexed? try reindex)")
        if len(rec) > 1:
            raise ToolError("that filename exists more than once; pass the numeric recording id")
        r = rec[0]
        where, params = scope_sql(conn, p, r["customer_id"] if p.is_superadmin else None)
        visible = conn.execute(f"SELECT 1 FROM recordings r WHERE {where} AND r.id = ?", params + [r["id"]]).fetchone() is not None
        reasons = []
        if p.is_superadmin:
            reasons.append("superadmin sees every customer")
        elif p.customer_id != r["customer_id"]:
            reasons.append(f"recording belongs to customer {r['slug']}, user belongs to another customer")
        elif p.role == "customer_admin":
            reasons.append("customer admin sees the whole customer drive")
        else:
            rules = load_dept_rules(conn, p.department_ids)
            if not rules:
                reasons.append("department user without any department sees nothing")
            for d_id, rule in zip(p.department_ids, rules):
                name = conn.execute("SELECT name FROM departments WHERE id = ?", (d_id,)).fetchone()
                hits = []
                if r["party"] in rule.extensions:
                    hits.append(f"party {r['party']} is a department extension")
                if r["rec_type"] in ("external", "internal") and r["target"] in rule.extensions:
                    hits.append(f"{r['rec_type']} target {r['target']} is a department extension")
                if r["rec_type"] == "q" and r["target"] in rule.queues:
                    hits.append(f"queue {r['target']} is a department queue")
                if r["rec_type"] == "in" and r["target"] in rule.dids:
                    hits.append(f"DID {r['target']} is a department DID")
                for f in rule.folders:
                    if r["rel_path"].lower().startswith(f.lower().strip("/") + "/"):
                        hits.append(f"stored under department folder {f}")
                reasons.append({"department": name["name"] if name else d_id, "matches": hits or ["no rule matches"]})
        user_state = conn.execute("SELECT active, locked_until, mfa_enabled FROM users WHERE id = ?", (p.user_id,)).fetchone()
        return {"visible": visible, "user": {"username": p.username, "role": p.role, "active": bool(user_state["active"]),
                                             "locked_until": user_state["locked_until"], "mfa_set_up": bool(user_state["mfa_enabled"])},
                "recording": {"id": r["id"], "customer": r["slug"], "rel_path": r["rel_path"], "type": r["rec_type"],
                              "target": r["target"], "party": r["party"], "time": r["rec_ts"], "empty": bool(r["empty"])},
                "why": reasons,
                "note": "visible is computed by the same scope_sql() the web app uses; 'why' explains it. "
                        "Empty recordings are hidden in the UI unless 'show empty' is ticked."}

    def parse_filename(self, conn, a):
        name = str(a["filename"]).strip().replace("\\", "/").split("/")[-1]
        parsed = parse_filename(name)
        out: dict = {"filename": name, "parsed": parsed.__dict__ if parsed else None}
        if parsed is None:
            out["note"] = "does not follow <type>-<target>-<party>-<YYYYMMDD>-<HHMMSS>-<uniqueid>.<ext>; it is indexed as type 'unknown' and only customer admins see it"
        if a.get("customer") and parsed:
            c = _customer(conn, a["customer"])
            matches = []
            for d in conn.execute("SELECT id, name FROM departments WHERE customer_id = ?", (c["id"],)):
                pred, params = department_predicate(load_dept_rules(conn, [d["id"]]))
                probe = conn.execute(f"SELECT 1 FROM (SELECT ? AS rec_type, ? AS target, ? AS party, ? AS rel_path) r WHERE {pred}",
                                     [parsed.rec_type, parsed.target, parsed.party, name] + params).fetchone()
                if probe:
                    matches.append(d["name"])
            out["departments_by_number"] = matches
            out["note"] = "folder rules also apply once the file's location on the drive is known (see explain_access)"
        return out

    def access_requests(self, conn, a):
        q, params = "SELECT g.*, c.slug FROM access_grants g LEFT JOIN customers c ON c.id = g.customer_id", []
        if a.get("customer"):
            q += " WHERE g.customer_id = ?"; params.append(_customer(conn, a["customer"])["id"])
        return [dict(r) for r in conn.execute(q + " ORDER BY g.id DESC LIMIT ?", params + [_int(a.get("limit"), 20, 1, 200)])]

    # -- operate tools ----------------------------------------------------------

    def reindex(self, conn, a):
        c = _customer(conn, a.get("customer"))
        return index_customer(self.db, self.cfg, c["id"])

    def unlock_user(self, conn, a):
        u = conn.execute("SELECT id, username, locked_until, failed_attempts FROM users WHERE username = ?",
                         (str(a["username"]),)).fetchone()
        if u is None:
            raise ToolError(f"no user {a['username']!r}")
        conn.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (u["id"],))
        return {"username": u["username"], "was_locked_until": u["locked_until"], "failed_attempts_cleared": u["failed_attempts"]}

    def request_folder_access(self, conn, a):
        c = _customer(conn, a.get("customer"))
        gid = grants.queue_grant(conn, c["id"], c["root_path"], "mcp")
        return {"queued": gid is not None, "request": grants.last_grant(conn, c["id"])}


# ---------------------------------------------------------------- JSON-RPC over HTTP

def _rpc_error(id_, code, message):
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def create_mcp_app(cfg: Config, db: Database, indexer: Any) -> Starlette:
    tools = Tools(cfg, db, indexer)

    def handle(conn: sqlite3.Connection, token: sqlite3.Row, msg: dict) -> dict | None:
        if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _rpc_error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Invalid Request")
        method, id_, params = msg["method"], msg.get("id"), msg.get("params") or {}
        if id_ is None:  # notification (e.g. notifications/initialized): nothing to answer
            return None
        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[0]
            return {"jsonrpc": "2.0", "id": id_, "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "televault", "title": f"{APP_NAME} ({cfg.vendor_name})" if cfg.vendor_name else APP_NAME,
                               "version": __version__},
                "instructions": ("TeleVault call-recording archive, local troubleshooting tools. Start with `health`. "
                                 "For 'user X cannot see recording Y' use `explain_access`. For department setup use "
                                 "`recording_stats` (top_folders) and `list_departments`. "
                                 f"This token's scope: {token['scope']}.")}}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": id_, "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": id_, "result": {"tools": tools.list(token["scope"])}}
        if method == "tools/call":
            name, args = params.get("name"), params.get("arguments") or {}
            entry = tools.table.get(name)
            if entry is None:
                return _rpc_error(id_, -32602, f"Unknown tool: {name}")
            scope = entry[0]
            audit.log(conn, "mcp.tool", username=f"mcp:{token['name']}", ip="127.0.0.1",
                      detail=f"{name} {json.dumps(args, ensure_ascii=False)[:500]}")
            # Commit now: the call is on record even if the tool fails, and tools that write
            # through their own connection (reindex) must not wait on this open transaction.
            conn.commit()
            if scope == "operate" and token["scope"] != "operate":
                return {"jsonrpc": "2.0", "id": id_, "result": {"isError": True, "content": [
                    {"type": "text", "text": f"'{name}' needs a token with the operate scope; this token is read-only."}]}}
            try:
                data = entry[3](conn, args)
                return {"jsonrpc": "2.0", "id": id_, "result": {"isError": False, "content": [
                    {"type": "text", "text": json.dumps(data, ensure_ascii=False, indent=1, default=str)}]}}
            except ToolError as e:
                return {"jsonrpc": "2.0", "id": id_, "result": {"isError": True, "content": [{"type": "text", "text": str(e)}]}}
            except Exception as e:  # noqa: BLE001
                return {"jsonrpc": "2.0", "id": id_, "result": {"isError": True, "content": [
                    {"type": "text", "text": f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}"}]}}
        return _rpc_error(id_, -32601, f"Method not found: {method}")

    async def endpoint(request: Request) -> Response:
        peer = request.client.host if request.client else ""
        host = request.headers.get("host", "").rsplit(":", 1)[0].lower()
        if peer not in {"127.0.0.1", "::1"} or host not in _LOCAL_HOSTS:
            return JSONResponse({"error": "local access only"}, status_code=403)
        if request.method != "POST":
            return Response(status_code=405, headers={"Allow": "POST"})
        try:
            body = await request.json()
        except Exception:  # noqa: BLE001
            return JSONResponse(_rpc_error(None, -32700, "Parse error"), status_code=400)

        def work():
            from .db import connect
            conn = connect(db.db_path)
            try:
                token = _auth(conn, request.headers.get("authorization", ""))
                if token is None:
                    conn.commit()
                    return None, 401
                if isinstance(body, list):
                    out = [r for r in (handle(conn, token, m) for m in body) if r is not None]
                else:
                    out = handle(conn, token, body)
                conn.commit()
                return out, 200
            finally:
                conn.close()

        from starlette.concurrency import run_in_threadpool
        out, status = await run_in_threadpool(work)
        if status == 401:
            return JSONResponse({"error": "missing or invalid token"}, status_code=401,
                                headers={"WWW-Authenticate": 'Bearer realm="televault-mcp"'})
        if out is None or out == []:
            return Response(status_code=202)
        return JSONResponse(out)

    return Starlette(routes=[Route("/mcp", endpoint, methods=["GET", "POST", "DELETE"])])
