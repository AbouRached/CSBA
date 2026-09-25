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
    customer_id: int | None     # legacy single-customer column (display / audit only)
    department_ids: list[int] = field(default_factory=list)
    # Every customer this user may see: administered customers (customer_admin) or the
    # customers of their departments (department). Authorization uses this, never customer_id.
    customer_ids: list[int] = field(default_factory=list)
    must_change_password: bool = False
    mfa_ok: bool = False        # this session passed the authenticator code
    mfa_enrolled: bool = False  # the user has a confirmed authenticator
    mfa_verified_at: str | None = None  # when a code was last entered on this session

    @property
    def is_superadmin(self) -> bool:
        return self.role == "superadmin"


def load_memberships(conn: sqlite3.Connection, user_id: int, role: str,
                     legacy_customer_id: int | None) -> tuple[list[int], list[int]]:
    """(customer_ids, department_ids) a user may see.
    customer_admin: user_customers plus the legacy users.customer_id.
    department: their departments, and the customers those departments belong to."""
    dept_ids = [r[0] for r in conn.execute(
        "SELECT department_id FROM user_departments WHERE user_id = ? ORDER BY department_id", (user_id,))]
    if role == "customer_admin":
        cids = {r[0] for r in conn.execute("SELECT customer_id FROM user_customers WHERE user_id = ?", (user_id,))}
        if legacy_customer_id is not None:
            cids.add(legacy_customer_id)
    elif role == "department" and dept_ids:
        q = ",".join("?" * len(dept_ids))
        cids = {r[0] for r in conn.execute(f"SELECT DISTINCT customer_id FROM departments WHERE id IN ({q})", dept_ids)}
    else:
        cids = set()
    return sorted(cids), dept_ids


@dataclass
class DeptRule:
    extensions: list[str]
    queues: list[str]
    dids: list[str]
    folders: list[str] = field(default_factory=list)  # relative to the customer root, "/"-separated
    customer_id: int | None = None  # the rule applies only inside this customer's recordings


def load_dept_rules(conn: sqlite3.Connection, department_ids: list[int]) -> list[DeptRule]:
    if not department_ids:
        return []
    qmarks = ",".join("?" * len(department_ids))
    rows = conn.execute(
        f"SELECT customer_id, extensions_json, queues_json, dids_json, folders_json FROM departments WHERE id IN ({qmarks})",
        department_ids,
    ).fetchall()
    return [
        DeptRule(
            extensions=[str(x) for x in json.loads(r["extensions_json"])],
            queues=[str(x) for x in json.loads(r["queues_json"])],
            dids=[str(x) for x in json.loads(r["dids_json"])],
            folders=[str(x) for x in json.loads(r["folders_json"] or "[]")],
            customer_id=r["customer_id"],
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

    Each department's rules apply only inside that department's own customer, so a user
    who is in departments of several customers can never see extension 436 of customer B
    because 436 is a Support extension at customer A.
    """
    clauses: list[str] = []
    params: list = []
    for rule in rules:
        c, pp = _rule_clauses(rule)
        if not c:
            continue
        body = "(" + " OR ".join(c) + ")"
        if rule.customer_id is not None:
            clauses.append(f"(r.customer_id = ? AND {body})")
            params.extend([rule.customer_id] + pp)
        else:  # parser probes (MCP parse_filename) that have no customer context
            clauses.append(body)
            params.extend(pp)
    if not clauses:
        return "0", []
    return "(" + " OR ".join(clauses) + ")", params


def _rule_clauses(rule: DeptRule) -> tuple[list[str], list]:
    exts = sorted(set(rule.extensions))
    queues = sorted(set(rule.queues))
    dids = sorted(set(rule.dids))
    clauses: list[str] = []
    params: list = []
    if exts:
        q = ",".join("?" * len(exts))
        clauses.append(f"r.party IN ({q})")
        params.extend(exts)
        clauses.append(f"(r.rec_type IN ('external','exten','internal') AND r.target IN ({q}))")
        params.extend(exts)
    if queues:
        q = ",".join("?" * len(queues))
        clauses.append(f"(r.rec_type = 'q' AND r.target IN ({q}))")
        params.extend(queues)
    if dids:
        q = ",".join("?" * len(dids))
        clauses.append(f"(r.rec_type = 'in' AND r.target IN ({q}))")
        params.extend(dids)
    for f in sorted({f for f in rule.folders if f}):
        clauses.append("r.rel_path LIKE ? ESCAPE '\\'")
        params.append(_like_escape(f.strip("/")) + "/%")
    return clauses, params


def scope_sql(
    conn: sqlite3.Connection, p: Principal, customer_id: int | None
) -> tuple[str, list]:
    """WHERE fragment restricting `recordings r` to what principal `p` may see.

    `customer_id` narrows to one customer being browsed (None = everything allowed).
    Superadmins may pick any customer. Everyone else may only narrow to one of their own
    customers; asking for any other customer yields nothing.
    """
    if p.is_superadmin:
        if customer_id is None:
            return "1", []
        return "r.customer_id = ?", [customer_id]

    allowed = list(p.customer_ids)
    if customer_id is not None:
        if customer_id not in allowed:
            return "0", []
        allowed = [customer_id]
    if not allowed:
        return "0", []
    q = ",".join("?" * len(allowed))
    base = f"r.customer_id IN ({q})"
    if p.role == "customer_admin":
        return base, allowed
    if p.role == "department":
        # department_predicate pins every rule to its own customer; `base` narrows further
        # when one customer is being browsed.
        pred, pp = department_predicate(load_dept_rules(conn, p.department_ids))
        return f"{base} AND {pred}", allowed + pp
    return "0", []


def effective_customer_id(p: Principal, requested: int | None) -> int | None:
    """The customer to narrow to: superadmins may pick any; others only one of their own
    (their only one when they have exactly one). None = all of the user's customers."""
    if p.is_superadmin:
        return requested
    if requested is not None and requested in p.customer_ids:
        return requested
    return p.customer_ids[0] if len(p.customer_ids) == 1 else None
