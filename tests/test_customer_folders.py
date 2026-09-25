"""Customer root folders: overlap protection and the superadmin-only folder picker."""
from __future__ import annotations

from conftest import HDR, login


def _root(c):
    return login(c, "root")


def test_overlapping_roots_rejected(env):
    c = env["client"]; _root(c)
    a = str(env["drive_a"])
    for path in (a, a + "\\2026", str(env["drive_a"].parent)):
        r = c.post("/api/admin/customers", json={"slug": "dup", "name": "Dup", "root_path": path}, headers=HDR)
        assert r.status_code == 409, path
    # Case differences do not sneak past on Windows.
    r = c.put("/api/admin/customers/2", json={"slug": "beta", "name": "Beta", "root_path": a.upper()}, headers=HDR)
    assert r.status_code == 409


def test_relative_root_rejected(env):
    c = env["client"]; _root(c)
    r = c.post("/api/admin/customers", json={"slug": "rel", "name": "Rel", "root_path": "recordings"}, headers=HDR)
    assert r.status_code == 400


def test_customer_can_keep_own_root_and_move_to_free_folder(env, tmp_path):
    c = env["client"]; _root(c)
    assert c.put("/api/admin/customers/1", json={"slug": "alpha", "name": "Alpha 2", "root_path": str(env["drive_a"])},
                 headers=HDR).status_code == 200
    free = tmp_path / "driveC"; free.mkdir()
    assert c.put("/api/admin/customers/1", json={"slug": "alpha", "name": "Alpha", "root_path": str(free)},
                 headers=HDR).status_code == 200


def test_browse_lists_folders_only_and_marks_owners(env):
    c = env["client"]; _root(c)
    r = c.get("/api/admin/fs/browse", params={"path": str(env["drive_a"].parent)})
    assert r.status_code == 200
    body = r.json()
    names = {d["name"]: d for d in body["dirs"]}
    assert {"driveA", "driveB"} <= set(names)
    assert names["driveA"]["assigned_to"][0]["slug"] == "alpha"
    assert body["overlaps"]  # the parent contains customer folders
    r = c.get("/api/admin/fs/browse", params={"path": str(env["drive_a"] / "loose")})
    assert r.json()["audio_files_here"] == 1 and r.json()["dirs"] == []


def test_browse_rejects_unc_relative_and_missing(env):
    c = env["client"]; _root(c)
    assert c.get("/api/admin/fs/browse", params={"path": r"\\evil-host\share"}).status_code == 400
    assert c.get("/api/admin/fs/browse", params={"path": "relative"}).status_code == 400
    assert c.get("/api/admin/fs/browse", params={"path": str(env["drive_a"] / "nope")}).status_code == 404


def test_drives_listed(env):
    c = env["client"]; _root(c)
    r = c.get("/api/admin/fs/drives")
    assert r.status_code == 200 and len(r.json()) >= 1


def test_picker_is_superadmin_only(env):
    c = env["client"]; login(c, "alpha_admin")
    assert c.get("/api/admin/fs/drives").status_code == 403
    assert c.get("/api/admin/fs/browse", params={"path": str(env["drive_a"])}).status_code == 403
