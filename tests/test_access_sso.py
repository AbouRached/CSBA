"""Phase 3: Cloudflare Access proves the email; the in-app Staff access list decides who is staff."""
from __future__ import annotations

import time
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from conftest import HDR, OUTSIDE, client_from, login, login_password_only
from televault import access

TEAM = "example.cloudflareaccess.com"
AUD = "a" * 64


@pytest.fixture()
def sso(env, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    monkeypatch.setattr(access, "_client", lambda team: SimpleNamespace(
        get_signing_key_from_jwt=lambda tok: SimpleNamespace(key=key.public_key())))
    env["cfg"].access_team_domain, env["cfg"].access_aud = TEAM, AUD

    def token(email="alice@operator.example", aud=AUD, signer=key, exp=3600):
        now = int(time.time())
        return jwt.encode({"email": email, "aud": [aud], "iss": f"https://{TEAM}", "iat": now, "exp": now + exp},
                          signer, algorithm="RS256")
    return token


def allow(env, *patterns):
    with env["db"].conn() as c:
        for p in patterns:
            c.execute("INSERT INTO staff_access(pattern) VALUES (?)", (access.normalize_pattern(p),))


def outside(env, tok):
    return client_from(env["app"], OUTSIDE, cookies={"CF_Authorization": tok})


def test_listed_address_any_domain(env, sso):
    allow(env, "someone@gmail.com")
    c = outside(env, sso(email="Someone@Gmail.com"))
    login(c, "root")
    assert c.get("/api/admin/customers").status_code == 200


def test_whole_domain_entry(env, sso):
    allow(env, "partner.example")
    assert login_password_only(outside(env, sso(email="anyone@partner.example")), "root").status_code == 200
    assert login_password_only(outside(env, sso(email="anyone@evil-partner.example")), "root").status_code == 403


def test_verified_but_not_listed_gets_nothing(env, sso):
    allow(env, "@partner.example")
    assert login_password_only(outside(env, sso()), "root").status_code == 403  # operator.example not listed


@pytest.mark.parametrize("bad", ["wrong_aud", "expired", "forged"])
def test_bad_tokens_do_not_open_the_gate(env, sso, bad):
    allow(env, "alice@operator.example")
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tok = {"wrong_aud": lambda: sso(aud="b" * 64), "expired": lambda: sso(exp=-60),
           "forged": lambda: sso(signer=other)}[bad]()
    assert login_password_only(outside(env, tok), "root").status_code == 403


def test_sso_disabled_without_aud(env, sso):
    allow(env, "alice@operator.example")
    env["cfg"].access_aud = ""
    assert login_password_only(outside(env, sso()), "root").status_code == 403


def test_staff_login_route_audits(env, sso):
    allow(env, "alice@operator.example")
    r = outside(env, sso()).get("/api/auth/staff-login", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    outside(env, sso(email="x@y.com")).get("/api/auth/staff-login", follow_redirects=False)
    with env["db"].conn() as conn:
        acts = [r[0] for r in conn.execute("SELECT action FROM audit_log WHERE action LIKE 'staff.sso.%' ORDER BY id")]
    assert acts == ["staff.sso.ok", "staff.sso.not_listed"]


def test_pattern_normalisation():
    n = access.normalize_pattern
    assert n(" Ops@Partner.Example ") == "ops@partner.example"
    assert n("partner.example") == n("@partner.example") == n("*@partner.example") == "@partner.example"
    assert n("not an email") is None and n("@") is None and n("a@b") is None


def test_manage_list_in_app(env):
    c = env["client"]
    login(c, "root")
    r = c.post("/api/admin/staff-access", json={"pattern": "Partner@Example.org", "note": "contractor"}, headers=HDR)
    assert r.status_code == 200 and r.json()["pattern"] == "partner@example.org"
    assert c.post("/api/admin/staff-access", json={"pattern": "partner@example.org"}, headers=HDR).status_code == 409
    assert c.post("/api/admin/staff-access", json={"pattern": "nonsense"}, headers=HDR).status_code == 400
    items = c.get("/api/admin/staff-access").json()
    assert [i["pattern"] for i in items] == ["partner@example.org"]
    assert c.delete(f"/api/admin/staff-access/{items[0]['id']}", headers=HDR).status_code == 200
    assert c.get("/api/admin/staff-access").json() == []


def test_list_is_superadmin_only_and_needs_step_up(env):
    c = env["client"]
    login(c, "alpha_admin")
    assert c.get("/api/admin/staff-access").status_code == 403
    root = client_from(env["app"], ("10.50.9.9", 50000))
    login(root, "root")
    with env["db"].conn() as conn:
        conn.execute("UPDATE sessions SET mfa_verified_at = strftime('%Y-%m-%dT%H:%M:%SZ','now','-11 minutes')")
    r = root.post("/api/admin/staff-access", json={"pattern": "@partner.example"}, headers=HDR)
    assert r.status_code == 403 and r.json()["detail"] == "step_up_required"


def test_seed_from_config(env):
    env["cfg"].staff_emails = ["Alice.Admin@Operator.Example"]
    with env["db"].conn() as c:
        access.seed_from_config(c, env["cfg"])
        access.seed_from_config(c, env["cfg"])  # idempotent
        assert [r[0] for r in c.execute("SELECT pattern FROM staff_access")] == ["alice.admin@operator.example"]
