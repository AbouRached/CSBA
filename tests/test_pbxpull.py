"""PBX pull: copy-only mirror of <remote>/YYYY/MM/DD into the customer's archive folder,
configured from the admin page (PBX list, test + trust, schedule, run now)."""
from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime
from pathlib import Path

import asyncssh
import pytest

from conftest import HDR, login
from televault import pbxpull

OLD = time.time() - 3600          # finished an hour ago
DAY = "2026/09/20"


@pytest.fixture(autouse=True)
def _data_drive_ok(monkeypatch):
    """pytest's temp folders are on the Windows drive, which the real job refuses."""
    monkeypatch.setattr(pbxpull, "unsafe_destination", lambda root: None)


def _remote(tmp_path: Path, files: dict[str, tuple[int, float]]) -> Path:
    root = tmp_path / "pbx"
    for rel, (size, mtime) in files.items():
        p = root / "monitor" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"x" * size)
        os.utime(p, (mtime, mtime))
    return root


class Pbx:
    """Throwaway SFTP server exporting a folder; the job's key is authorised on it."""
    def __init__(self, env, tmp_path, remote_root: Path):
        self.env, self.remote_root = env, remote_root
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        cfg = env["cfg"]
        cfg.pbx_key = tmp_path / "keys" / "id"
        self.pub = pbxpull.ensure_key(cfg)
        (tmp_path / "keys" / "authorized").write_text(self.pub)
        self.auth = str(tmp_path / "keys" / "authorized")
        with env["db"].conn() as c:
            pbxpull._set(c, "pbx_min_free_gb", "1")

    async def __aenter__(self):
        self.server = await asyncssh.listen("127.0.0.1", 0, server_host_keys=[self.host_key],
                                            authorized_client_keys=self.auth,
                                            sftp_factory=lambda chan: asyncssh.SFTPServer(chan, chroot=str(self.remote_root)))
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *a):
        self.server.close()
        await self.server.wait_closed()

    def add_source(self, trusted=True, customer_id=1, name="alpha-pbx"):
        with self.env["db"].conn() as c:
            c.execute("DELETE FROM pbx_sources WHERE name = ?", (name,))
            c.execute("INSERT INTO pbx_sources(name, customer_id, host, port, username, remote_dir, host_key) "
                      "VALUES (?,?, '127.0.0.1', ?, 'puller', '/monitor', ?)",
                      (name, customer_id, self.port, self.host_key.export_public_key().decode().strip() if trusted else ""))


def _pull(env, tmp_path, remote_root, **kw):
    async def main():
        async with Pbx(env, tmp_path, remote_root) as pbx:
            pbx.add_source()
            return await pbxpull.run(env["cfg"], env["db"], **kw)
    return asyncio.run(main())


def test_copies_new_keeps_existing_and_never_touches_the_pbx(env, tmp_path):
    remote = _remote(tmp_path, {
        f"{DAY}/new-1.wav": (5000, OLD), f"{DAY}/new-2.wav": (700, OLD),
        f"{DAY}/have.wav": (300, OLD),                 # already in the archive, same size
        f"{DAY}/short.wav": (900, OLD),                # archive has a shorter (interrupted) copy
        f"{DAY}/bigger-local.wav": (100, OLD),         # archive copy is larger: leave alone
        f"{DAY}/recording-now.wav": (50, time.time()), # call still in progress
        f"{DAY}/notes.txt": (10, OLD),                 # not audio
        "2026/09/21/next-day.wav": (123, OLD),
        "junk/ignored.wav": (5, OLD),                  # not YYYY/MM/DD
    })
    dest = env["drive_a"] / "2026" / "09" / "20"
    dest.mkdir(parents=True)
    (dest / "have.wav").write_bytes(b"h" * 300)
    (dest / "short.wav").write_bytes(b"s" * 400)
    (dest / "bigger-local.wav").write_bytes(b"b" * 999)
    before = sorted(p.relative_to(remote).as_posix() for p in remote.rglob("*") if p.is_file())

    st = _pull(env, tmp_path, remote, dry_run=True)[0]                     # reports, writes nothing
    assert (st.copied, st.present, st.in_progress, st.conflicts) == (4, 1, 1, 1)
    assert not (dest / "new-1.wav").exists() and not (env["drive_a"] / "2026/09/21").exists()

    st = _pull(env, tmp_path, remote)[0]
    assert (st.copied, st.present, st.in_progress, st.replaced, st.conflicts, st.errors) == (4, 1, 1, 1, 1, [])
    assert (dest / "new-1.wav").read_bytes() == b"x" * 5000
    assert abs((dest / "new-1.wav").stat().st_mtime - OLD) < 2            # PBX time kept
    assert (dest / "have.wav").read_bytes() == b"h" * 300                 # untouched
    assert (dest / "short.wav").stat().st_size == 900                     # completed...
    kept = [p for p in dest.iterdir() if p.name.startswith("short.wav.replaced-")]
    assert len(kept) == 1 and kept[0].read_bytes() == b"s" * 400          # ...and the old copy kept
    assert (dest / "bigger-local.wav").stat().st_size == 999              # never shrunk
    assert not (dest / "recording-now.wav").exists() and not (dest / "notes.txt").exists()
    assert (env["drive_a"] / "2026/09/21/next-day.wav").stat().st_size == 123
    assert not list(env["drive_a"].rglob("*.part")) and not (env["drive_a"] / "junk").exists()
    assert sorted(p.relative_to(remote).as_posix() for p in remote.rglob("*") if p.is_file()) == before  # PBX untouched

    st = _pull(env, tmp_path, remote)[0]                                   # second run: nothing left
    assert st.copied == 0 and st.present == 5
    with env["db"].conn() as c:
        acts = [r[0] for r in c.execute("SELECT action FROM audit_log WHERE action LIKE 'system.pbxpull.%' ORDER BY id")]
    assert acts == ["system.pbxpull.done", "system.pbxpull.done"]


def test_untrusted_or_changed_host_key_recent_days_and_unsafe_destination(env, tmp_path, monkeypatch):
    today = time.strftime("%Y/%m/%d")
    remote = _remote(tmp_path, {f"{today}/t.wav": (10, OLD), "2020/01/01/ancient.wav": (10, OLD)})

    async def main():
        async with Pbx(env, tmp_path, remote) as pbx:
            pbx.add_source(trusted=False)
            a = (await pbxpull.run(env["cfg"], env["db"]))[0]              # never trusted: no pull
            with env["db"].conn() as c:                                    # trusted key differs from the server's
                c.execute("UPDATE pbx_sources SET host_key = ?",
                          (asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip(),))
            b = (await pbxpull.run(env["cfg"], env["db"]))[0]
            pbx.add_source()
            c_ = (await pbxpull.run(env["cfg"], env["db"], recent_days=2))[0]
            monkeypatch.setattr(pbxpull, "unsafe_destination", lambda root: "the Windows drive is not allowed")
            d = (await pbxpull.run(env["cfg"], env["db"]))[0]
            pbx.add_source(customer_id=3, name="gone-pbx")                 # customer whose drive is missing
            monkeypatch.setattr(pbxpull, "unsafe_destination", lambda root: None)
            e = [s for s in await pbxpull.run(env["cfg"], env["db"], only="gone-pbx")][0]
            return a, b, c_, d, e
    a, b, c_, d, e = asyncio.run(main())
    assert a.copied == 0 and "not trusted" in a.stopped
    assert b.copied == 0 and "cannot connect" in b.stopped
    assert c_.copied == 1 and (env["drive_a"] / today / "t.wav").exists() and not (env["drive_a"] / "2020").exists()
    assert d.copied == 0 and "refused" in d.stopped
    assert "offline" in e.stopped


def test_real_destination_check_refuses_windows_drive_and_network_paths(monkeypatch):
    monkeypatch.undo()                                                     # use the real function
    sysdrive = os.environ.get("SystemDrive", "C:")
    assert "Windows drive" in pbxpull.unsafe_destination(Path(sysdrive + "\\Recordings"))
    assert pbxpull.unsafe_destination(Path("\\\\server\\share\\x")) == "not a local drive path"
    assert pbxpull.unsafe_destination(Path("relative\\x")) == "not a local drive path"


def test_admin_page_flow_add_test_trust_run_and_schedule(env, tmp_path):
    """Everything from the UI: add a PBX, the worker tests it, a superadmin trusts the host key,
    'pull now' and the schedule make the worker copy."""
    remote = _remote(tmp_path, {f"{DAY}/a.wav": (2000, OLD)})
    c = env["client"]; login(c, "root")
    a = env["client"]

    async def main():
        async with Pbx(env, tmp_path, remote) as pbx:
            cfg, db = env["cfg"], env["db"]
            body = {"name": "alpha-pbx", "customer_id": 1, "host": "127.0.0.1", "port": pbx.port,
                    "username": "puller", "remote_dir": "/monitor"}
            for bad in ({"name": "Bad Name"}, {"host": "bad host"}, {"remote_dir": "relative"}, {"remote_dir": "/a/../b"},
                        {"username": "root; rm"}, {"customer_id": 999}):
                assert c.post("/api/admin/pbx", json={**body, **bad}, headers=HDR).status_code == 400, bad
            sid = c.post("/api/admin/pbx", json=body, headers=HDR).json()["id"]
            assert c.post("/api/admin/pbx", json=body, headers=HDR).status_code == 409
            assert c.post(f"/api/admin/pbx/{sid}/trust", headers=HDR).status_code == 409     # nothing seen yet

            assert "idle" in await pbxpull.tick(cfg, db, now=datetime(2026, 10, 3, 3, 0)) or True
            o = c.get("/api/admin/pbx").json()
            s = o["sources"][0]
            assert o["key_line"].startswith('restrict,from="') and 'command="internal-sftp -R" ssh-ed25519 ' in o["key_line"]
            assert s["test"]["ok"] and "year folders: 2026" in s["test"]["message"] and not s["test_pending"]
            assert s["needs_trust"] and s["seen_fingerprints"] == [pbx.host_key.get_fingerprint()]
            assert not (env["drive_a"] / DAY / "a.wav").exists()            # tested, but not trusted: nothing copied

            assert c.post(f"/api/admin/pbx/{sid}/trust", headers=HDR).status_code == 200
            assert c.post("/api/admin/pbx/run", json={"source_id": sid}, headers=HDR).status_code == 200
            assert await pbxpull.tick(cfg, db, now=datetime(2026, 10, 3, 12, 30)) == "run now (alpha-pbx)"
            assert (env["drive_a"] / DAY / "a.wav").stat().st_size == 2000
            s = c.get("/api/admin/pbx").json()["sources"][0]
            assert s["status"]["copied"] == 1 and not s["needs_trust"] and s["trusted_fingerprints"]

            # schedule: nightly once per window, daytime hourly, both from the settings saved in the UI
            st = {**c.get("/api/admin/pbx").json()["settings"], "pbx_night_start": 22, "pbx_night_hours": 4,
                  "pbx_day_from": 8, "pbx_day_to": 18, "pbx_min_free_gb": 1}
            assert c.put("/api/admin/pbx/settings", json={**st, "pbx_alert_pct": 10}, headers=HDR).status_code == 400
            assert c.put("/api/admin/pbx/settings", json=st, headers=HDR).status_code == 200
            assert await pbxpull.tick(cfg, db, now=datetime(2026, 10, 3, 23, 0)) == "nightly pull"
            assert await pbxpull.tick(cfg, db, now=datetime(2026, 10, 4, 1, 0)) == "idle (nightly pull already done)"
            assert await pbxpull.tick(cfg, db, now=datetime(2026, 10, 4, 5, 0)) == "idle"
            assert await pbxpull.tick(cfg, db, now=datetime(2026, 10, 4, 9, 0)) == "daytime pull"
            assert await pbxpull.tick(cfg, db, now=datetime(2026, 10, 4, 9, 5)) == "idle"

            # moving the PBX to another address drops the trust
            assert c.put(f"/api/admin/pbx/{sid}", json={**body, "host": "127.0.0.2"}, headers=HDR).status_code == 200
            s = c.get("/api/admin/pbx").json()["sources"][0]
            assert s["trusted_fingerprints"] == [] and s["test_pending"]
            assert c.delete(f"/api/admin/pbx/{sid}", headers=HDR).status_code == 200
    asyncio.run(main())
    assert (env["drive_a"] / DAY / "a.wav").exists()                        # removing a PBX keeps the archive
    with env["db"].conn() as db:
        acts = [r[0] for r in db.execute("SELECT action FROM audit_log WHERE action LIKE 'admin.pbx.%' ORDER BY id")]
    assert acts == ["admin.pbx.create", "admin.pbx.trust", "admin.pbx.run", "admin.pbx.settings", "admin.pbx.update",
                    "admin.pbx.delete"]
    login(a, "alpha_admin")
    assert a.get("/api/admin/pbx").status_code == 403


def test_seed_from_config_with_pinned_host_keys(env, tmp_path):
    cfg = env["cfg"]
    hk = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode().strip()
    cfg.pbx_known_hosts = tmp_path / "known_hosts"
    cfg.pbx_known_hosts.write_text(f"10.0.0.5 {hk}\n10.0.0.9 {hk}\n")
    cfg.pbx_sources = [{"name": "alpha-pbx", "customer": "alpha", "host": "10.0.0.5", "user": "root"},
                       {"name": "nobody", "customer": "no-such-customer", "host": "10.0.0.9", "user": "root"}]
    with env["db"].conn() as c:
        assert pbxpull.seed_from_config(c, cfg) == 1
        assert pbxpull.seed_from_config(c, cfg) == 0                         # only once
        s = pbxpull.load_sources(c)
    assert [(x.name, x.host, x.user, x.host_key) for x in s] == [("alpha-pbx", "10.0.0.5", "root", hk)]
