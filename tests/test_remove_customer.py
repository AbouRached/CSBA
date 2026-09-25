"""cli remove-customer: dry run by default; with --confirm removes customer, users, depts, index rows."""
from __future__ import annotations

from televault import cli


def _count(env, sql, *a):
    with env["db"].conn() as c:
        return c.execute(sql, a).fetchone()[0]


def test_dry_run_changes_nothing(env, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda: env["cfg"])
    assert cli.main(["remove-customer", "alpha"]) == 1
    assert _count(env, "SELECT COUNT(*) FROM customers WHERE slug='alpha'") == 1


def test_confirmed_removal_cascades_and_keeps_files(env, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda: env["cfg"])
    files_before = sorted(p.name for p in env["drive_a"].rglob("*.wav"))
    assert cli.main(["remove-customer", "alpha", "--confirm", "alpha"]) == 0
    assert _count(env, "SELECT COUNT(*) FROM customers WHERE slug='alpha'") == 0
    assert _count(env, "SELECT COUNT(*) FROM users WHERE customer_id=1") == 0
    assert _count(env, "SELECT COUNT(*) FROM departments WHERE customer_id=1") == 0
    assert _count(env, "SELECT COUNT(*) FROM recordings WHERE customer_id=1") == 0
    assert _count(env, "SELECT COUNT(*) FROM users WHERE username IN ('root','beta_admin')") == 2  # others untouched
    assert _count(env, "SELECT COUNT(*) FROM audit_log WHERE action='cli.customer.remove'") == 1
    assert sorted(p.name for p in env["drive_a"].rglob("*.wav")) == files_before


def test_wrong_confirm_is_dry_run(env, monkeypatch):
    monkeypatch.setattr(cli, "load_config", lambda: env["cfg"])
    assert cli.main(["remove-customer", "alpha", "--confirm", "beta"]) == 1
    assert _count(env, "SELECT COUNT(*) FROM customers WHERE slug='alpha'") == 1
