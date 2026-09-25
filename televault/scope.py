"""Authorization scope: the single place that decides which recordings a user may see.

Every recordings query goes through `scope_sql()`. If this function is right, no route
can leak another customer's or another department's files.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field


@dataclass
class Principal:
    user_id: int
    username: str
    role: str  # superadmin | customer_admin | department
    customer_id: int | None
    department_ids: list[int] = field(default_factory=list)
    must_change_password: bool = False
    mfa_ok: bool = False        # this session passed the authenticator code
    mfa_enrolled: bool = False  # the user has a confirmed authenticator
    mfa_verified_at: str | None = None  # when a code was last entered on this session

    @property
    def is_superadmin(self) -> bool:
        return self.role == "superadmin"


@dataclass
class DeptRule:
    extensions: list[str]
    queues: list[str]
    dids: list[str]
    folders: list[str] = field(default_factory=list)  # relative to the customer root, "/"-separated


def load_dept_rules(conn: sqlite3.Connection, department_ids: list[int]) -> list[DeptRule]:
    if not department_ids:
        return []
    qmarks = ",".join("?" * len(department_ids))
    rows = conn.execute(
        f"SELECT extensions_json, queues_json, dids_json, folders_json FROM departments WHERE id IN ({qmarks})",
        department_ids,
    ).fetchall()
    return [
        DeptRule(
            extensions=[str(x) for x in json.loads(r["extensions_json"])],
            queues=[str(x) for x in json.loads(r["queues_json"])],
            dids=[str(x) for x in json.loads(r["dids_json"])],
            folders=[str(x) for x in json.loads(r["folders_json"] or "[]")],
        )
        for r in rows
    ]


def _like_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def department_predicate(rules: list[DeptRule]) -> tuple[str, list]:
    """SQL fragment (without leading AND) selecting recordings that belong to ANY rule.

    Rule (see spec §5). Which filename field holds the local extension depends on
    the recording type (FreePBX recordcheck: target=ARG3, party=RECFROMEXTEN):

        type      target            party
        external  the EXTENSION     outside caller
        exten     the EXTENSION     caller (outside CID or an extension) - older recordcheck
        internal  callee EXTENSION  caller EXTENSION
        out       dialled number    the EXTENSION
        q         queue number      caller (outside CID or an extension)
        in        DID               outside caller (or queue member ext)

      party IN extensions
      OR (rec_type IN ('external','exten','internal') AND target IN extensions)
      OR (rec_type='q'  AND target IN queues)
      OR (rec_type='in' AND target IN dids)
      OR rel_path is inside one of the department's folders

    Folders are for drives where the department's recordings are kept in their own
    directory (e.g. "Support/2026/..."): everything under the folder belongs to it,
    whatever the filename says. Matching is case-insensitive, like Windows paths.

    Returns ("0", []) when nothing can match, so a department user with no
    departments sees nothing rather than everything.
    """
    exts: set[str] = set()
    queues: set[str] = set()
    dids: set[str] = set()
    folders: set[str] = set()
    for r in rules:
        exts.update(r.extensions)
        queues.update(r.queues)
        dids.update(r.dids)
        folders.update(f for f in r.folders if f)

    clauses: list[str] = []
    params: list = []
    if exts:
        q = ",".join("?" * len(exts))
        clauses.append(f"r.party IN ({q})")
        params.extend(sorted(exts))
        clauses.append(f"(r.rec_type IN ('external','exten','internal') AND r.target IN ({q}))")
        params.extend(sorted(exts))
    if queues:
        q = ",".join("?" * len(queues))
        clauses.append(f"(r.rec_type = 'q' AND r.target IN ({q}))")
        params.extend(sorted(queues))
    if dids:
        q = ",".join("?" * len(dids))
        clauses.append(f"(r.rec_type = 'in' AND r.target IN ({q}))")
        params.extend(sorted(dids))
    for f in sorted(folders):
        clauses.append("r.rel_path LIKE ? ESCAPE '\\'")
        params.append(_like_escape(f.strip("/")) + "/%")
    if not clauses:
        return "0", []
    return "(" + " OR ".join(clauses) + ")", params


def scope_sql(
    conn: sqlite3.Connection, p: Principal, customer_id: int | None
) -> tuple[str, list]:
    """WHERE fragment restricting `recordings r` to what principal `p` may see.

    `customer_id` is the customer being browsed. Superadmins may pick any; everyone
    else is pinned to their own and the argument is ignored.
    """
    if p.is_superadmin:
        if customer_id is None:
            return "1", []
        return "r.customer_id = ?", [customer_id]

    if p.customer_id is None:
        return "0", []
    base = "r.customer_id = ?"
    params: list = [p.customer_id]
    if p.role == "customer_admin":
        return base, params
    if p.role == "department":
        pred, pp = department_predicate(load_dept_rules(conn, p.department_ids))
        return f"{base} AND {pred}", params + pp
    return "0", []


def effective_customer_id(p: Principal, requested: int | None) -> int | None:
    return requested if p.is_superadmin else p.customer_id
