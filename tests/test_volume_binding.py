"""A customer is bound to the disk its folder is on; a different disk at that path is refused."""
from __future__ import annotations

from conftest import HDR, login
from televault import admin, indexer, recordings


def _serial(env, cid=1):
    with env["db"].conn() as c:
        return c.execute("SELECT volume_serial FROM customers WHERE id = ?", (cid,)).fetchone()[0]


def _count(env, cid=1):
    with env["db"].conn() as c:
        return c.execute("SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (cid,)).fetchone()[0]


def _fake_disk(monkeypatch, serial):
    for mod in (indexer, admin):
        monkeypatch.setattr(mod, "volume_serial", lambda path, s=serial: s)


def test_first_index_binds_then_other_disk_is_refused(env, monkeypatch):
    _fake_disk(monkeypatch, "AAAA1111")
    with env["db"].conn() as c:
        c.execute("UPDATE customers SET volume_serial = NULL")
    assert indexer.index_customer(env["db"], env["cfg"], 1)["status"] == "ok"
    assert _serial(env) == "AAAA1111"
    before = _count(env)

    _fake_disk(monkeypatch, "BBBB2222")   # letters swapped: another customer's disk is now here
    r = indexer.index_customer(env["db"], env["cfg"], 1)
    assert r["status"] == "wrong_drive" and _count(env) == before   # nothing indexed or removed
    with env["db"].conn() as c:
        assert c.execute("SELECT COUNT(*) FROM audit_log WHERE action='system.drive.mismatch'").fetchone()[0] == 1


def test_wrong_disk_blocks_playback_and_shows_in_admin(env, monkeypatch):
    with env["db"].conn() as c:
        c.execute("UPDATE customers SET volume_serial = 'AAAA1111' WHERE id = 1")
        rid = c.execute("SELECT id FROM recordings WHERE customer_id = 1 AND empty = 0 LIMIT 1").fetchone()[0]
    _fake_disk(monkeypatch, "BBBB2222")
    monkeypatch.setattr(recordings, "drive_state", lambda root, s: indexer.drive_state(root, s))
    c = env["client"]; login(c, "alpha_admin")
    r = c.get(f"/api/recordings/{rid}/stream")
    assert r.status_code == 503 and "not available" in r.json()["detail"]
    root = env["client"]; login(root, "root")
    cust = next(x for x in root.get("/api/admin/customers").json() if x["id"] == 1)
    assert cust["drive_state"] == "wrong_drive" and cust["online"] is False and cust["current_serial"] == "BBBB2222"


def test_rebind_is_explicit_and_audited(env, monkeypatch):
    with env["db"].conn() as c:
        c.execute("UPDATE customers SET volume_serial = 'AAAA1111' WHERE id = 1")
    _fake_disk(monkeypatch, "CCCC3333")
    c = env["client"]; login(c, "root")
    # an ordinary edit (rename) must NOT silently accept the other disk
    c.put("/api/admin/customers/1", json={"slug": "alpha", "name": "Alpha renamed", "root_path": str(env["drive_a"])},
          headers=HDR)
    assert _serial(env) == "AAAA1111"
    r = c.post("/api/admin/customers/1/rebind-drive", headers=HDR)
    assert r.status_code == 200 and _serial(env) == "CCCC3333"
    with env["db"].conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM audit_log WHERE action='admin.customer.rebind_drive'").fetchone()[0] == 1
    a = env["client"]; login(a, "alpha_admin")
    assert a.post("/api/admin/customers/1/rebind-drive", headers=HDR).status_code == 403


def test_real_volume_serial_on_windows(env):
    import os
    s = indexer.volume_serial(str(env["drive_a"]))
    if os.name == "nt":
        assert s and len(s) == 8
