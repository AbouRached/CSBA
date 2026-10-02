"""Read-only SFTP feed: rolling window, one customer, allowed addresses, no writes, audited."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta

import asyncssh
import pytest

from conftest import HDR, login
from televault import sftp as tvsftp
from televault.security import hash_password

RECENT = "2026/08/20/out-3281883752-436-20260820-115255-1787215975.372897.wav"
RECENT2 = "2026/08/20/q-131-01644655-20260820-082243-1787203363.370306.wav"
OLD = "2026/08/19/external-436-70000001-20260819-090000-1787100000.100000.wav"
EMPTY = "2026/08/20/external-884-70072421-20260820-092444-1787207084.370825.wav"
BETA = "2026/09/01/in-9999-11111111-20260901-100000-1790000000.1.wav"
CLIENT_KEY = asyncssh.generate_private_key("ssh-ed25519")
PASSWORD = "feed-password-for-tests-1"


def _setup(env, ips=("127.0.0.1",), active=True, days=30):
    """Alpha account; RECENT/RECENT2/EMPTY dated yesterday, everything else stays old."""
    yday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S")
    with env["db"].conn() as c:
        c.execute("UPDATE recordings SET rec_ts = ? WHERE rel_path IN (?,?,?)", (yday, RECENT, RECENT2, EMPTY))
        c.execute("UPDATE recordings SET rec_ts = ? WHERE customer_id = 2", (yday,))
        c.execute("UPDATE recordings SET rec_ts = '2020-01-01T00:00:00' WHERE rec_type = 'unknown'")  # undated, old
        c.execute("INSERT INTO sftp_accounts(id, username, customer_id, window_days, allowed_ips_json, public_keys, "
                  "password_hash, active) VALUES (1, 'ai-feed', 1, ?, ?, ?, ?, ?)",
                  (days, json.dumps(list(ips)), CLIENT_KEY.export_public_key().decode(), hash_password(PASSWORD),
                   int(active)))
    env["cfg"].sftp_host, env["cfg"].sftp_port = "127.0.0.1", 0


def _run(env, body):
    async def main():
        server = await tvsftp.start(env["cfg"], env["db"])
        port = server.sockets[0].getsockname()[1]
        try:
            return await body(port)
        finally:
            server.close()
            await server.wait_closed()
    return asyncio.run(main())


def _connect(port, **kw):
    opts = dict(username="ai-feed", known_hosts=None, client_keys=[CLIENT_KEY], password=None)
    opts.update(kw)
    return asyncssh.connect("127.0.0.1", port, **opts)


def _audit(env, prefix):
    with env["db"].conn() as c:
        return [tuple(r) for r in c.execute("SELECT action, username, customer_id, detail FROM audit_log "
                                            "WHERE action LIKE ? ORDER BY id", (prefix + "%",))]


def test_key_login_sees_only_recent_non_empty_files_of_its_customer(env):
    _setup(env)

    async def body(port):
        async with _connect(port) as conn, conn.start_sftp_client() as s:
            assert await s.listdir("/") == [".", "..", "2026"]
            names = sorted(await s.listdir("/2026/08/20"))
            data = await (await s.open("/" + RECENT, "rb")).read()
            for gone in (OLD, EMPTY, BETA, "loose/notes.wav"):
                assert not await s.exists("/" + gone), gone
            # '..' can never climb out of the virtual root
            assert await s.realpath("/../../..") == "/"
            assert not await s.exists("/../../Windows/win.ini")
            return names, data

    names, data = _run(env, body)
    assert names == [".", "..", RECENT.split("/")[-1], RECENT2.split("/")[-1]]
    assert data == (env["drive_a"] / RECENT).read_bytes()
    assert _audit(env, "sftp.") == [("sftp.login", "sftp:ai-feed", 1, ""),
                                    ("sftp.download", "sftp:ai-feed", 1, RECENT)]


def test_everything_that_writes_is_refused(env):
    _setup(env)

    async def body(port):
        async with _connect(port) as conn, conn.start_sftp_client() as s:
            for op in (lambda: s.open("/x.wav", "wb"), lambda: s.open("/" + RECENT, "r+b"),
                       lambda: s.remove("/" + RECENT), lambda: s.rename("/" + RECENT, "/y.wav"),
                       lambda: s.mkdir("/new"), lambda: s.rmdir("/2026"),
                       lambda: s.chmod("/" + RECENT, 0o777), lambda: s.symlink("/" + RECENT, "/link")):
                with pytest.raises(asyncssh.SFTPError):
                    await op()
            # no shell / exec either
            with pytest.raises((asyncssh.ChannelOpenError, asyncssh.ProcessError, asyncssh.Error)):
                r = await conn.run("whoami", check=True)
                assert False, r
    _run(env, body)
    assert (env["drive_a"] / RECENT).exists()


def test_password_login_and_failures_are_audited(env):
    _setup(env)

    async def body(port):
        with pytest.raises(asyncssh.PermissionDenied):
            async with _connect(port, client_keys=None, password="wrong-password-xx"):
                pass
        async with _connect(port, client_keys=None, password=PASSWORD) as conn, conn.start_sftp_client() as s:
            return await s.listdir("/2026/08")
    assert _run(env, body) == [".", "..", "20"]
    acts = [a for a, *_ in _audit(env, "sftp.")]
    assert "sftp.login.fail" in acts and acts[-1] == "sftp.login"


def test_address_not_allowed_is_dropped(env):
    _setup(env, ips=("198.51.100.7/32",))

    async def body(port):
        with pytest.raises((OSError, asyncssh.Error)):
            async with _connect(port):
                pass
    _run(env, body)
    assert _audit(env, "sftp.login") == []


def test_disabled_mid_session_cannot_open_files(env):
    _setup(env)

    async def body(port):
        async with _connect(port) as conn, conn.start_sftp_client() as s:
            with env["db"].conn() as c:
                c.execute("UPDATE sftp_accounts SET active = 0")
            with pytest.raises(asyncssh.SFTPError):
                await s.open("/" + RECENT, "rb")
        with pytest.raises((asyncssh.PermissionDenied, OSError, asyncssh.Error)):
            async with _connect(port):
                pass
    _run(env, body)


# ---------------------------------------------------------------- admin API

def test_admin_api_superadmin_only_and_validated(env):
    a = env["client"]; login(a, "alpha_admin")
    assert a.get("/api/admin/sftp").status_code == 403
    c = env["client"]; login(c, "root")
    base = {"username": "ai-feed", "customer_id": 1, "window_days": 30, "allowed_ips": ["198.51.100.7"]}
    assert c.post("/api/admin/sftp", json=base, headers=HDR).status_code == 400            # no key, no password
    assert c.post("/api/admin/sftp", json={**base, "generate_password": True, "allowed_ips": ["0.0.0.0/0"]},
                  headers=HDR).status_code == 400
    assert c.post("/api/admin/sftp", json={**base, "public_keys": "ssh-ed25519 garbage"}, headers=HDR).status_code == 400
    assert c.post("/api/admin/sftp", json={**base, "generate_password": True, "allowed_ips": []},
                  headers=HDR).status_code == 400
    key = CLIENT_KEY.export_public_key().decode()
    r = c.post("/api/admin/sftp", json={**base, "public_keys": key, "generate_password": True}, headers=HDR)
    assert r.status_code == 200 and len(r.json()["password"]) >= 20
    listing = c.get("/api/admin/sftp").json()
    acct = listing["accounts"][0]
    assert listing["host_fingerprint"].startswith("SHA256:") and "password_hash" not in acct
    assert acct["has_password"] and acct["allowed_ips"] == ["198.51.100.7/32"]
    assert acct["key_fingerprints"] == [CLIENT_KEY.get_fingerprint()]
    upd = {**base, "public_keys": key, "remove_password": True, "window_days": 7}
    assert c.put(f"/api/admin/sftp/{r.json()['id']}", json=upd, headers=HDR).status_code == 200
    assert c.get("/api/admin/sftp").json()["accounts"][0]["has_password"] is False
    assert c.delete(f"/api/admin/sftp/{r.json()['id']}", headers=HDR).status_code == 200
    assert [x[0] for x in _audit(env, "admin.sftp.")] == ["admin.sftp.create", "admin.sftp.update", "admin.sftp.delete"]
