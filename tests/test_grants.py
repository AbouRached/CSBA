"""Granting the service account read-only folder access from the admin UI (queue + worker CLI)."""
from __future__ import annotations

import json

from conftest import HDR, login
from televault import cli, grants


def _grants(env):
    with env["db"].conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM access_grants ORDER BY id")]


def test_new_customer_queues_grant(env, tmp_path):
    c = env["client"]; login(c, "root")
    d = tmp_path / "driveNew"; d.mkdir()
    assert c.post("/api/admin/customers", json={"slug": "newco", "name": "NewCo", "root_path": str(d)},
                  headers=HDR).status_code == 200
    g = _grants(env)
    assert len(g) == 1 and g[0]["path"] == str(d) and g[0]["status"] == "pending" and g[0]["requested_by"] == "root"


def test_root_change_queues_grant_same_root_does_not(env, tmp_path):
    c = env["client"]; login(c, "root")
    body = {"slug": "alpha", "name": "Alpha", "root_path": str(env["drive_a"])}
    c.put("/api/admin/customers/1", json=body, headers=HDR)
    assert _grants(env) == []
    d = tmp_path / "driveMoved"; d.mkdir()
    c.put("/api/admin/customers/1", json={**body, "root_path": str(d)}, headers=HDR)
    assert [g["path"] for g in _grants(env)] == [str(d)]


def test_grant_button_dedupes_and_reports_status(env):
    c = env["client"]; login(c, "root")
    r1 = c.post("/api/admin/customers/1/grant-access", headers=HDR).json()
    r2 = c.post("/api/admin/customers/1/grant-access", headers=HDR).json()
    assert r1["queued"] is True and r2["queued"] is False and len(_grants(env)) == 1
    cust = next(x for x in c.get("/api/admin/customers").json() if x["id"] == 1)
    assert cust["access"]["readable"] is True and cust["access"]["grant"]["status"] == "pending"


def test_grant_is_superadmin_only(env):
    c = env["client"]; login(c, "alpha_admin")
    assert c.post("/api/admin/customers/1/grant-access", headers=HDR).status_code == 403
    assert "access" not in c.get("/api/admin/customers").json()[0]


def test_worker_cli_take_and_finish(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_config", lambda: env["cfg"])
    with env["db"].conn() as c:
        gid = grants.queue_grant(c, 1, str(env["drive_a"]), "root")
    assert cli.main(["grant-queue", "take"]) == 0
    taken = json.loads(capsys.readouterr().out)
    assert [t["id"] for t in taken] == [gid]
    assert cli.main(["grant-queue", "take"]) == 0 and json.loads(capsys.readouterr().out) == []  # claimed once
    assert cli.main(["grant-queue", "finish", "--id", str(gid), "--status", "error", "--message", "Refused: x"]) == 0
    g = _grants(env)[0]
    assert g["status"] == "error" and g["message"] == "Refused: x" and g["finished_at"]
    with env["db"].conn() as c:
        assert c.execute("SELECT COUNT(*) FROM audit_log WHERE action='system.access.failed'").fetchone()[0] == 1
    # a new request is possible once the previous one finished
    with env["db"].conn() as c:
        assert grants.queue_grant(c, 1, str(env["drive_a"]), "root") is not None


def test_stale_running_request_is_retaken(env):
    with env["db"].conn() as c:
        gid = grants.queue_grant(c, 1, str(env["drive_a"]), "root")
        grants.take_pending(c)
        assert grants.take_pending(c) == []
        c.execute("UPDATE access_grants SET started_at = '2000-01-01T00:00:00Z' WHERE id = ?", (gid,))
        assert [t["id"] for t in grants.take_pending(c)] == [gid]
