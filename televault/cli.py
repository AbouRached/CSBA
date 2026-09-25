"""Console commands. Run from the project root:

    py -3.12 -m televault.cli init
    py -3.12 -m televault.cli make-cert [--hostname archive.example.local] [--ip 192.168.1.50]
    py -3.12 -m televault.cli create-superadmin <username>
    py -3.12 -m televault.cli add-customer <slug> "<name>" <root_path>
    py -3.12 -m televault.cli list-customers
    py -3.12 -m televault.cli reindex [slug]
    py -3.12 -m televault.cli list-users
    py -3.12 -m televault.cli set-password <username> [--must-change]
    py -3.12 -m televault.cli reset-mfa <username>
    py -3.12 -m televault.cli backup <dest> [--keep 14]
    py -3.12 -m televault.cli serve

Superadmins are created only here, on the console — never through the web UI.
"""
from __future__ import annotations

import argparse
import getpass
import ipaddress
import logging
import sys
from datetime import datetime, timedelta, timezone

from .config import APP_NAME, load_config
from .db import Database
from .indexer import index_all, index_customer, root_online
from .security import hash_password, password_policy_error


def cmd_init(_args) -> int:
    cfg = load_config()
    Database(cfg.db_path)
    print(f"{APP_NAME}: database ready at {cfg.db_path}")
    return 0


def cmd_make_cert(args) -> int:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    cfg = load_config()
    if cfg.tls_cert.exists() and not args.force:
        print(f"Certificate already exists at {cfg.tls_cert}; use --force to replace.")
        return 1
    key = ec.generate_private_key(ec.SECP256R1())
    names = [x509.DNSName(args.hostname), x509.DNSName("localhost")]
    for ip in args.ip or []:
        names.append(x509.IPAddress(ipaddress.ip_address(ip)))
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, cfg.vendor_name or APP_NAME),
        x509.NameAttribute(NameOID.COMMON_NAME, args.hostname),
    ])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=int(args.days)))
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cfg.tls_key.parent.mkdir(parents=True, exist_ok=True)
    cfg.tls_key.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cfg.tls_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    print(f"Self-signed certificate written: {cfg.tls_cert}")
    print("Replace cert.pem/key.pem with a CA-issued pair when available; the app reads them at start.")
    return 0


def _read_password(cfg) -> str:
    while True:
        pw = getpass.getpass("Password: ")
        err = password_policy_error(pw, cfg)
        if err:
            print(err)
            continue
        if pw != getpass.getpass("Repeat password: "):
            print("Passwords do not match.")
            continue
        return pw


def cmd_create_superadmin(args) -> int:
    cfg = load_config()
    db = Database(cfg.db_path)
    pw = _read_password(cfg)
    with db.conn() as c:
        try:
            c.execute(
                "INSERT INTO users(customer_id, username, password_hash, role, display_name, must_change_password) "
                "VALUES (NULL, ?, ?, 'superadmin', ?, 0)",
                (args.username, hash_password(pw), args.display_name or args.username),
            )
        except Exception as e:  # noqa: BLE001
            print(f"Could not create user: {e}")
            return 1
        c.execute("INSERT INTO audit_log(username, action, detail) VALUES (?, 'cli.superadmin.create', ?)",
                  ("console", args.username))
    print(f"Superadmin '{args.username}' created.")
    return 0


def _user_row(c, username: str):
    row = c.execute("SELECT id, username, role FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        print(f"No such user: {username}")
    return row


def cmd_reset_mfa(args) -> int:
    """Lost phone: forget the authenticator; the user scans a new QR code at next sign-in."""
    from .mfa import reset_user_mfa
    cfg = load_config()
    db = Database(cfg.db_path)
    with db.conn() as c:
        row = _user_row(c, args.username)
        if row is None:
            return 1
        reset_user_mfa(c, row["id"])
        c.execute("INSERT INTO audit_log(username, user_id, action, detail) VALUES ('console', ?, 'cli.mfa.reset', ?)",
                  (row["id"], row["username"]))
    print(f"Authenticator for '{row['username']}' removed; they will enrol again at next sign-in.")
    return 0


def cmd_set_password(args) -> int:
    """Console password reset for any account, including superadmins."""
    cfg = load_config()
    db = Database(cfg.db_path)
    with db.conn() as c:
        if _user_row(c, args.username) is None:
            return 1
    pw = _read_password(cfg)
    with db.conn() as c:
        row = _user_row(c, args.username)
        c.execute("UPDATE users SET password_hash=?, must_change_password=?, failed_attempts=0, locked_until=NULL "
                  "WHERE id=?", (hash_password(pw), int(args.must_change), row["id"]))
        c.execute("DELETE FROM sessions WHERE user_id = ?", (row["id"],))
        c.execute("INSERT INTO audit_log(username, user_id, action, detail) VALUES ('console', ?, 'cli.password.set', ?)",
                  (row["id"], row["username"]))
    print(f"Password for '{row['username']}' updated; existing sessions signed out.")
    return 0


def cmd_backup(args) -> int:
    """Consistent online copy of the database plus the secrets it cannot live without:
    mfa.key (without it every user must re-enrol) and the TLS pair. Old backups beyond
    --keep days are removed from the destination."""
    import shutil
    import sqlite3 as _sq
    from pathlib import Path
    cfg = load_config()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = Path(args.dest) / f"televault-{stamp}"
    dest.mkdir(parents=True, exist_ok=False)
    src = _sq.connect(str(cfg.db_path))
    dst = _sq.connect(str(dest / "televault.sqlite3"))
    with dst:
        src.backup(dst)
    src.close(); dst.close()
    for f in (cfg.data_dir / "mfa.key", cfg.tls_cert, cfg.tls_key):
        if f.exists():
            shutil.copy2(f, dest / f.name)
    cutoff = datetime.now() - timedelta(days=args.keep)
    for old in Path(args.dest).glob("televault-*"):
        if old.is_dir() and old != dest and datetime.fromtimestamp(old.stat().st_mtime) < cutoff:
            shutil.rmtree(old, ignore_errors=True)
    print(f"Backup written: {dest}")
    return 0


def cmd_grant_queue(args) -> int:
    """Used only by scripts/grant-worker.ps1 (SYSTEM). 'take' claims pending requests and prints
    them as JSON; 'finish' records the outcome and writes it to the audit log."""
    import json
    from . import audit, grants
    cfg = load_config()
    audit.configure(cfg.audit_to_eventlog)
    db = Database(cfg.db_path)
    with db.conn() as c:
        if args.action == "take":
            print(json.dumps(grants.take_pending(c)))
            return 0
        row = c.execute("SELECT customer_id, path FROM access_grants WHERE id = ?", (args.id,)).fetchone()
        if row is None:
            print("No such request.")
            return 1
        ok = args.status == "done"
        grants.finish(c, args.id, ok, args.message or "")
        audit.log(c, "system.access.granted" if ok else "system.access.failed", username="grant-worker",
                  customer_id=row["customer_id"], detail=f"{row['path']} {args.message or ''}".strip())
    return 0


def cmd_mcp_token(args) -> int:
    """Console token management for the local MCP endpoint (the admin UI does the same)."""
    from .mcp_server import create_token
    cfg = load_config()
    db = Database(cfg.db_path)
    with db.conn() as c:
        if args.action == "create":
            tid, token = create_token(c, args.name, args.scope, "console")
            c.execute("INSERT INTO audit_log(username, action, detail) VALUES ('console', 'cli.mcp_token.create', ?)",
                      (f"#{tid} {args.name} scope={args.scope}",))
            url = f"http://127.0.0.1:{cfg.mcp_port}/mcp"
            print(f"Token #{tid} ({args.scope}) - shown once, store it now:\n{token}\n")
            print(f'claude mcp add --transport http televault {url} --header "Authorization: Bearer {token}"')
        elif args.action == "revoke":
            c.execute("UPDATE mcp_tokens SET revoked_at = strftime('%Y-%m-%dT%H:%M:%SZ','now') WHERE id = ?", (args.id,))
            print(f"Token #{args.id} revoked.")
        else:
            for r in c.execute("SELECT * FROM mcp_tokens ORDER BY id"):
                print(f"#{r['id']:<3} {r['name']:<24} {r['scope']:<8} created {r['created_at']} by {r['created_by']:<12} "
                      f"last used {r['last_used_at'] or '-':<20} {'REVOKED' if r['revoked_at'] else 'active'}")
    return 0


def cmd_remove_customer(args) -> int:
    """Remove a customer from TeleVault (e.g. demo data): its users, departments, sessions and
    index rows go with it. Recording FILES are never touched, and the audit log is kept.
    Requires --confirm <slug> so it cannot run by accident."""
    cfg = load_config()
    db = Database(cfg.db_path)
    with db.conn() as c:
        cust = c.execute("SELECT * FROM customers WHERE slug = ?", (args.slug,)).fetchone()
        if cust is None:
            print(f"No customer '{args.slug}' - nothing to do.")
            return 0
        users = [r["username"] for r in c.execute("SELECT username FROM users WHERE customer_id = ?", (cust["id"],))]
        n_rec = c.execute("SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (cust["id"],)).fetchone()[0]
        depts = [r["name"] for r in c.execute("SELECT name FROM departments WHERE customer_id = ?", (cust["id"],))]
        print(f"Customer {cust['slug']} ({cust['name']}) -> {cust['root_path']}")
        print(f"  users: {', '.join(users) or '-'}\n  departments: {', '.join(depts) or '-'}\n  index rows: {n_rec}")
        if args.confirm != args.slug:
            print(f"Dry run. To remove it, add:  --confirm {args.slug}")
            return 1
        # sessions/user_departments/departments/recordings/index_runs/access_grants cascade
        c.execute("DELETE FROM customers WHERE id = ?", (cust["id"],))
        from . import audit
        audit.configure(cfg.audit_to_eventlog)  # also mirror to the Windows Event Log
        audit.log(c, "cli.customer.remove", username="console", customer_id=cust["id"],
                  detail=f"{cust['slug']} root={cust['root_path']} users={users} depts={depts} index_rows={n_rec}")
    print(f"Removed customer '{args.slug}' ({len(users)} users, {len(depts)} departments, {n_rec} index rows). Files untouched.")
    return 0


def cmd_list_users(_args) -> int:
    cfg = load_config()
    db = Database(cfg.db_path)
    with db.conn() as c:
        for r in c.execute("SELECT u.*, c.slug FROM users u LEFT JOIN customers c ON c.id=u.customer_id ORDER BY u.id"):
            print(f"#{r['id']:<3} {r['username']:<24} {r['role']:<15} {r['slug'] or '-':<14} "
                  f"{'active' if r['active'] else 'disabled':<9} MFA {'yes' if r['mfa_enabled'] else 'not set up'}")
    return 0


def cmd_add_customer(args) -> int:
    cfg = load_config()
    db = Database(cfg.db_path)
    with db.conn() as c:
        try:
            cur = c.execute("INSERT INTO customers(slug, name, root_path) VALUES (?,?,?)",
                            (args.slug, args.name, args.root_path))
        except Exception as e:  # noqa: BLE001
            print(f"Could not add customer: {e}")
            return 1
        cid = cur.lastrowid
    state = "online" if root_online(args.root_path) else "OFFLINE (will index when the drive appears)"
    print(f"Customer {args.slug} (#{cid}) -> {args.root_path}  [{state}]")
    if args.index and root_online(args.root_path):
        print(index_customer(db, cfg, cid))
    return 0


def cmd_list_customers(_args) -> int:
    cfg = load_config()
    db = Database(cfg.db_path)
    with db.conn() as c:
        for r in c.execute("SELECT c.*, (SELECT COUNT(*) FROM recordings r WHERE r.customer_id=c.id) n FROM customers c ORDER BY id"):
            print(f"#{r['id']:<3} {r['slug']:<16} {r['name']:<30} {r['root_path']:<20} "
                  f"{'on ' if root_online(r['root_path']) else 'OFF'} {r['n']} files {'enabled' if r['enabled'] else 'disabled'}")
    return 0


def cmd_reindex(args) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    db = Database(cfg.db_path)
    if args.slug:
        with db.conn() as c:
            row = c.execute("SELECT id FROM customers WHERE slug = ?", (args.slug,)).fetchone()
        if row is None:
            print("No such customer.")
            return 1
        print(index_customer(db, cfg, row["id"]))
    else:
        for r in index_all(db, cfg):
            print(r)
    return 0


def cmd_serve(_args) -> int:
    from .main import run
    run()
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="televault", description=f"{APP_NAME} console")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("init").set_defaults(fn=cmd_init)

    mc = sub.add_parser("make-cert")
    mc.add_argument("--hostname", default="televault.local")
    mc.add_argument("--ip", action="append", help="IP SAN; repeatable")
    mc.add_argument("--days", default="1095")
    mc.add_argument("--force", action="store_true")
    mc.set_defaults(fn=cmd_make_cert)

    cs = sub.add_parser("create-superadmin")
    cs.add_argument("username")
    cs.add_argument("--display-name", default="")
    cs.set_defaults(fn=cmd_create_superadmin)

    rm = sub.add_parser("reset-mfa", help="remove a user's authenticator (lost phone)")
    rm.add_argument("username")
    rm.set_defaults(fn=cmd_reset_mfa)

    sp = sub.add_parser("set-password", help="set a user's password from the console")
    sp.add_argument("username")
    sp.add_argument("--must-change", action="store_true", help="force a change at next sign-in")
    sp.set_defaults(fn=cmd_set_password)

    sub.add_parser("list-users").set_defaults(fn=cmd_list_users)

    rc = sub.add_parser("remove-customer", help="remove a customer (demo data) and its users; files untouched")
    rc.add_argument("slug")
    rc.add_argument("--confirm", default="", help="repeat the slug to actually remove it")
    rc.set_defaults(fn=cmd_remove_customer)

    mt = sub.add_parser("mcp-token", help="create / list / revoke tokens for the local MCP endpoint")
    mt.add_argument("action", choices=["create", "list", "revoke"])
    mt.add_argument("--name", default="console")
    mt.add_argument("--scope", choices=["read", "operate"], default="read")
    mt.add_argument("--id", type=int)
    mt.set_defaults(fn=cmd_mcp_token)

    gq = sub.add_parser("grant-queue", help="(grant worker) take/finish folder access requests")
    gq.add_argument("action", choices=["take", "finish"])
    gq.add_argument("--id", type=int)
    gq.add_argument("--status", choices=["done", "error"])
    gq.add_argument("--message", default="")
    gq.set_defaults(fn=cmd_grant_queue)

    bk = sub.add_parser("backup", help="back up database + mfa.key + TLS pair")
    bk.add_argument("dest", help="backup folder, e.g. C:\\TeleVaultBackups")
    bk.add_argument("--keep", type=int, default=14, help="days of backups to keep")
    bk.set_defaults(fn=cmd_backup)

    ac = sub.add_parser("add-customer")
    ac.add_argument("slug")
    ac.add_argument("name")
    ac.add_argument("root_path")
    ac.add_argument("--index", action="store_true", help="index immediately")
    ac.set_defaults(fn=cmd_add_customer)

    sub.add_parser("list-customers").set_defaults(fn=cmd_list_customers)

    ri = sub.add_parser("reindex")
    ri.add_argument("slug", nargs="?")
    ri.set_defaults(fn=cmd_reindex)

    sub.add_parser("serve").set_defaults(fn=cmd_serve)

    args = ap.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
