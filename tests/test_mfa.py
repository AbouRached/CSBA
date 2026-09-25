"""Mandatory TOTP second factor."""
from __future__ import annotations

import time

from conftest import HDR, PW, login, login_password_only, mfa_code
from televault.mfa import _hotp, match_step, new_secret, otpauth_uri, totp_now


def test_totp_rfc6238_vector():
    # RFC 6238 appendix B, SHA1, secret "12345678901234567890", T=59 -> 94287082 (8 digits) -> last 6.
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert _hotp(secret, 59 // 30) == "287082"


def test_match_step_window_and_format():
    s = new_secret()
    now = time.time()
    assert match_step(s, totp_now(s, now), now) is not None
    assert match_step(s, totp_now(s, now - 30), now) is not None      # one step of drift ok
    assert match_step(s, totp_now(s, now - 120), now) is None         # too old
    assert match_step(s, "12345", now) is None
    code = totp_now(s, now)
    assert match_step(s, f"{code[:3]} {code[3:]}", now) is not None   # spaces tolerated


def test_otpauth_uri_for_authenticator():
    uri = otpauth_uri("ABCDEF", "alice")
    assert uri.startswith("otpauth://totp/") and "issuer=TeleVault" in uri and "secret=ABCDEF" in uri


def test_password_alone_gives_no_access(env):
    c = env["client"]
    r = login_password_only(c, "alpha_admin")
    assert r.status_code == 200 and r.json()["mfa_ok"] is False
    assert c.get("/api/recordings").status_code == 403
    assert c.get("/api/admin/users").status_code == 403
    assert c.post("/api/auth/change-password", json={"current_password": PW, "new_password": "Another-Pass-123"},
                  headers=HDR).status_code == 403
    assert c.get("/api/auth/me").json()["mfa_ok"] is False


def test_enrol_then_verify_every_login(env):
    c = env["client"]
    login_password_only(c, "alpha_admin")
    s = c.post("/api/auth/mfa/setup", headers=HDR).json()
    assert s["qr"].startswith("data:image/svg+xml") and len(s["secret"].replace(" ", "")) == 32
    # reloading the setup page keeps the same pending secret
    assert c.post("/api/auth/mfa/setup", headers=HDR).json()["secret"] == s["secret"]
    assert c.post("/api/auth/mfa/verify", json={"code": mfa_code(c, "alpha_admin")}, headers=HDR).json()["enrolled"]
    assert c.get("/api/recordings").status_code == 200
    # once enrolled, setup is refused (a stolen password cannot replace the authenticator)
    assert c.post("/api/auth/mfa/setup", headers=HDR).status_code == 409
    c.post("/api/auth/logout", headers=HDR)
    r = login_password_only(c, "alpha_admin")
    assert r.json()["mfa_enrolled"] is True
    assert c.get("/api/recordings").status_code == 403
    assert c.post("/api/auth/mfa/verify", json={"code": mfa_code(c, "alpha_admin")}, headers=HDR).status_code == 200
    assert c.get("/api/recordings").status_code == 200


def test_code_cannot_be_replayed(env):
    c = env["client"]
    login(c, "alpha_admin")
    code = mfa_code(c, "alpha_admin", reset_replay=False)
    c.post("/api/auth/logout", headers=HDR)
    login_password_only(c, "alpha_admin")
    assert c.post("/api/auth/mfa/verify", json={"code": code}, headers=HDR).status_code == 400


def test_wrong_codes_kill_session(env):
    c = env["client"]
    login(c, "alpha_admin")
    c.post("/api/auth/logout", headers=HDR)
    login_password_only(c, "alpha_admin")
    codes = [c.post("/api/auth/mfa/verify", json={"code": "000000"}, headers=HDR).status_code for _ in range(5)]
    assert codes[:4] == [400] * 4 and codes[4] == 401
    assert c.get("/api/auth/me").status_code == 401


def test_admin_reset_mfa(env):
    c = env["client"]
    login(c, "alpha_support")
    c.post("/api/auth/logout", headers=HDR)
    login(c, "alpha_admin")
    users = {u["username"]: u for u in c.get("/api/admin/users").json()}
    assert users["alpha_support"]["mfa_enabled"] is True
    assert c.post(f"/api/admin/users/{users['alpha_support']['id']}/reset-mfa", headers=HDR).status_code == 200
    # a customer admin cannot reset another customer admin or a superadmin
    assert c.post("/api/admin/users/100/reset-mfa", headers=HDR).status_code == 404
    c.post("/api/auth/logout", headers=HDR)
    assert login_password_only(c, "alpha_support").json()["mfa_enrolled"] is False


def test_password_change_keeps_mfa_on_rotated_session(env):
    c = env["client"]
    login(c, "alpha_admin")
    r = c.post("/api/auth/change-password", json={"current_password": PW, "new_password": "Brand-New-Pass-77"},
               headers=HDR)
    assert r.status_code == 200
    assert c.get("/api/recordings").status_code == 200


def test_mfa_secret_encrypted_at_rest(env):
    c = env["client"]
    login_password_only(c, "alpha_admin")
    secret = c.post("/api/auth/mfa/setup", headers=HDR).json()["secret"].replace(" ", "")
    with env["db"].conn() as conn:
        stored = conn.execute("SELECT mfa_secret FROM users WHERE username='alpha_admin'").fetchone()[0]
    assert secret not in stored
