"""ADR-0001 gates: staff-network superadmins, absolute session caps, step-up for sensitive actions."""
from __future__ import annotations

from conftest import HDR, OUTSIDE, client_from, login, login_password_only, mfa_code


# ---------------------------------------------------------------- staff network

def test_superadmin_cannot_sign_in_from_outside(env):
    c = client_from(env["app"], OUTSIDE)
    r = login_password_only(c, "root")
    assert r.status_code == 403 and "Staff accounts" in r.json()["detail"]
    with env["db"].conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='login.staff_blocked'").fetchone()[0] == 1


def test_superadmin_session_refused_when_used_from_outside(env):
    inside = env["client"]
    login(inside, "root")
    assert inside.get("/api/admin/customers").status_code == 200
    stolen = client_from(env["app"], OUTSIDE, cookies=inside.cookies)
    assert stolen.get("/api/admin/customers").status_code == 403
    assert stolen.get("/api/recordings").status_code == 403


def test_customers_are_not_network_restricted(env):
    c = client_from(env["app"], OUTSIDE)
    login(c, "alpha_admin")
    assert c.get("/api/recordings").status_code == 200


def test_tunnel_traffic_is_never_treated_as_local_console(env):
    env["cfg"].trust_cloudflare_header = True
    local = client_from(env["app"], ("127.0.0.1", 50000))
    r = local.post("/api/auth/login", json={"username": "root", "password": "Correct-Horse-Battery-9"},
                   headers={**HDR, "CF-Connecting-IP": "203.0.113.9", "CF-Ray": "abc"})
    assert r.status_code == 403
    # Same PC, no tunnel headers = the console on the Archive PC itself.
    assert login_password_only(local, "root").status_code == 200


# ---------------------------------------------------------------- session caps

def _age_sessions(env, hours: int):
    with env["db"].conn() as conn:
        conn.execute("UPDATE sessions SET created_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', ?)", (f"-{hours} hours",))


def test_superadmin_session_absolute_cap(env):
    c = env["client"]
    login(c, "root")
    _age_sessions(env, 9)  # cap is 8 h for superadmins, even though the idle timer is fresh
    assert c.get("/api/auth/me").status_code == 401


def test_customer_session_absolute_cap(env):
    c = env["client"]
    login(c, "alpha_admin")
    _age_sessions(env, 9)
    assert c.get("/api/auth/me").status_code == 200
    _age_sessions(env, 169)
    assert c.get("/api/auth/me").status_code == 401


# ---------------------------------------------------------------- step-up

def _stale_mfa(env):
    with env["db"].conn() as conn:
        conn.execute("UPDATE sessions SET mfa_verified_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-11 minutes')")


def test_sensitive_action_needs_fresh_code(env):
    c = env["client"]
    login(c, "alpha_admin")
    _stale_mfa(env)
    body = {"username": "new.user", "role": "department", "department_ids": [10]}
    r = c.post("/api/admin/users", json=body, headers=HDR)
    assert r.status_code == 403 and r.json()["detail"] == "step_up_required"
    # read-only admin views are not interrupted
    assert c.get("/api/admin/users").status_code == 200
    assert c.post("/api/auth/mfa/verify", json={"code": mfa_code(c, "alpha_admin")}, headers=HDR).status_code == 200
    assert c.post("/api/admin/users", json=body, headers=HDR).status_code == 200


def test_customer_root_change_needs_fresh_code(env):
    c = env["client"]
    login(c, "root")
    _stale_mfa(env)
    r = c.put("/api/admin/customers/1", json={"slug": "alpha", "name": "Alpha", "root_path": str(env["drive_a"])},
              headers=HDR)
    assert r.status_code == 403 and r.json()["detail"] == "step_up_required"


def test_backup_command(env, tmp_path, monkeypatch):
    from televault import cli
    monkeypatch.setattr(cli, "load_config", lambda: env["cfg"])
    (env["cfg"].data_dir / "mfa.key").write_bytes(b"k")
    assert cli.main(["backup", str(tmp_path / "bk")]) == 0
    out = next((tmp_path / "bk").glob("televault-*"))
    assert (out / "televault.sqlite3").stat().st_size > 0 and (out / "mfa.key").exists()
