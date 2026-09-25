import io
import zipfile

from conftest import HDR, PW, login


def test_csrf_header_required(env):
    c = env["client"]
    r = c.post("/api/auth/login", json={"username": "root", "password": PW})
    assert r.status_code == 403


def test_login_lockout_after_failures(env):
    c = env["client"]
    for _ in range(3):
        assert login(c, "alpha_admin", "wrong-password-xx").status_code == 401
    assert login(c, "alpha_admin").status_code == 423
    with env["db"].conn() as db:
        n = db.execute("SELECT COUNT(*) FROM audit_log WHERE action='login.fail'").fetchone()[0]
    assert n == 3


def test_unknown_user_is_generic_401(env):
    assert login(env["client"], "nobody").status_code == 401


def test_forced_password_change_blocks_recordings(env):
    c = env["client"]
    assert login(c, "fresh").status_code == 200
    assert c.get("/api/recordings").status_code == 403
    r = c.post("/api/auth/change-password", json={"current_password": PW, "new_password": "short"}, headers=HDR)
    assert r.status_code == 400
    r = c.post("/api/auth/change-password", json={"current_password": PW, "new_password": "New-Strong-Pass-2026"}, headers=HDR)
    assert r.status_code == 200
    assert c.get("/api/recordings").status_code == 200
    # old password no longer works
    c.post("/api/auth/logout", headers=HDR)
    assert login(c, "fresh").status_code == 401
    assert login(c, "fresh", "New-Strong-Pass-2026").status_code == 200


def test_static_files_not_cached_by_shared_caches(env):
    r = env["client"].get("/static/app.js")
    assert r.status_code == 200 and r.headers["cache-control"] == "private, no-cache"


def test_security_headers_present(env):
    r = env["client"].get("/")
    assert r.status_code == 200
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"


def test_department_scope_via_api_and_hidden_empties(env):
    c = env["client"]
    assert login(c, "alpha_support").status_code == 200
    d = c.get("/api/recordings").json()
    assert d["total"] == 4
    d = c.get("/api/recordings?include_empty=true&ext=436").json()
    assert d["total"] == 2
    # cannot reach Beta's recording by id
    with env["db"].conn() as db:
        beta_id = db.execute("SELECT id FROM recordings WHERE customer_id=2 LIMIT 1").fetchone()[0]
        own_id = db.execute("SELECT id FROM recordings WHERE filename LIKE 'q-126-%'").fetchone()[0]
        other_id = db.execute("SELECT id FROM recordings WHERE filename LIKE 'q-131-%'").fetchone()[0]
    assert c.get(f"/api/recordings/{beta_id}/stream").status_code == 404
    assert c.get(f"/api/recordings/{other_id}/download").status_code == 404
    assert c.get(f"/api/recordings/{own_id}/download").status_code == 200


def test_customer_admin_pagination_and_empties(env):
    c = env["client"]
    login(c, "alpha_admin")
    d = c.get("/api/recordings").json()
    assert d["total"] == 8 and len(d["items"]) == 4 and d["page_size"] == 4
    d2 = c.get("/api/recordings?page=2").json()
    assert len(d2["items"]) == 4 and {x["id"] for x in d["items"]}.isdisjoint({x["id"] for x in d2["items"]})
    assert c.get("/api/recordings?include_empty=true").json()["total"] == 9
    assert c.get("/api/recordings?type=unknown&include_empty=true").json()["total"] == 1


def test_range_streaming(env):
    c = env["client"]
    login(c, "alpha_admin")
    rid = c.get("/api/recordings?ext=851").json()["items"][0]["id"]
    full = c.get(f"/api/recordings/{rid}/stream")
    assert full.status_code == 200 and full.headers["accept-ranges"] == "bytes"
    assert full.headers["content-type"].startswith("audio/wav")
    part = c.get(f"/api/recordings/{rid}/stream", headers={"Range": "bytes=44-143"})
    assert part.status_code == 206 and len(part.content) == 100
    assert part.headers["content-range"].startswith("bytes 44-143/")
    assert part.content == full.content[44:144]
    bad = c.get(f"/api/recordings/{rid}/stream", headers={"Range": "bytes=999999-"})
    assert bad.status_code == 416
    dl = c.get(f"/api/recordings/{rid}/download")
    assert dl.headers["content-disposition"].startswith("attachment;")
    # a browser opens a stream with bytes=0- : that is one play; later seeks are not
    assert c.get(f"/api/recordings/{rid}/stream", headers={"Range": "bytes=0-"}).status_code == 206
    with env["db"].conn() as db:
        acts = [r[0] for r in db.execute("SELECT action FROM audit_log WHERE action LIKE 'recording.%'")]
    assert acts.count("recording.play") == 2 and acts.count("recording.download") == 1


def test_no_mutating_verbs_on_recordings(env):
    c = env["client"]
    login(c, "root")
    rid = c.get("/api/recordings?customer_id=1").json()["items"][0]["id"]
    for method in ("delete", "put", "patch"):
        r = getattr(c, method)(f"/api/recordings/{rid}", headers=HDR)
        assert r.status_code in (404, 405), method
        r = getattr(c, method)(f"/api/recordings/{rid}/download", headers=HDR)
        assert r.status_code in (404, 405), method
    assert (env["drive_a"] / "2026/08/20").exists()


def test_zip_selected_and_limits(env):
    c = env["client"]
    login(c, "alpha_admin")
    ids = [x["id"] for x in c.get("/api/recordings").json()["items"]][:3]
    r = c.post("/api/recordings/zip", json={"ids": ids}, headers=HDR)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    zf = zipfile.ZipFile(io.BytesIO(r.content))
    names = zf.namelist()
    assert len(names) == 3 and all(len(n.split("/")) == 2 for n in names)  # <date>/<filename>
    r = c.post("/api/recordings/zip", json={"filters": {"include_empty": True}}, headers=HDR)
    assert r.status_code == 413
    r = c.post("/api/recordings/zip", json={"filters": {"ext": "851"}}, headers=HDR)
    assert r.status_code == 200
    # tmp dir cleaned
    assert not list(env["cfg"].tmp_dir.glob("tv-*.zip"))


def test_zip_cannot_include_other_customer(env):
    c = env["client"]
    login(c, "alpha_admin")
    with env["db"].conn() as db:
        beta_id = db.execute("SELECT id FROM recordings WHERE customer_id=2 LIMIT 1").fetchone()[0]
        own = db.execute("SELECT id FROM recordings WHERE customer_id=1 AND empty=0 LIMIT 1").fetchone()[0]
    r = c.post("/api/recordings/zip", json={"ids": [beta_id, own]}, headers=HDR)
    assert r.status_code == 200
    assert len(zipfile.ZipFile(io.BytesIO(r.content)).namelist()) == 1


def test_offline_drive(env):
    c = env["client"]
    login(c, "root")
    s = c.get("/api/recordings/summary?customer_id=3").json()
    assert s["drive"]["online"] is False and s["count"] == 0
    assert s["last_index"]["status"] == "offline"


def test_admin_isolation(env):
    c = env["client"]
    login(c, "alpha_admin")
    assert c.post("/api/admin/customers", json={"slug": "x", "name": "X", "root_path": "Z:\\"}, headers=HDR).status_code == 403
    assert c.post("/api/admin/departments", json={"customer_id": 2, "name": "Hack", "extensions": ["1"]}, headers=HDR).status_code == 403
    r = c.post("/api/admin/departments", json={"customer_id": 1, "name": "Sales", "extensions": ["851", "bad ext"]}, headers=HDR)
    assert r.status_code == 400
    r = c.post("/api/admin/departments", json={"customer_id": 1, "name": "Sales", "extensions": ["851"]}, headers=HDR)
    dept = r.json()["id"]
    r = c.post("/api/admin/users", json={"username": "sales1", "role": "department", "department_ids": [dept]}, headers=HDR)
    assert r.status_code == 200 and len(r.json()["initial_password"]) >= 12
    assert c.post("/api/admin/users", json={"username": "adm2", "role": "customer_admin"}, headers=HDR).status_code == 403
    # cross-customer department attach is refused
    with env["db"].conn() as db:
        db.execute("INSERT INTO departments(id, customer_id, name) VALUES (50, 2, 'BetaDept')")
    assert c.post("/api/admin/users", json={"username": "sales2", "role": "department", "department_ids": [50]}, headers=HDR).status_code == 403
    # the new user sees only ext 851
    c.post("/api/auth/logout", headers=HDR)
    login(c, "sales1", r.json()["initial_password"])
    c.post("/api/auth/change-password", json={"current_password": r.json()["initial_password"], "new_password": "Another-Strong-Pw-1"}, headers=HDR)
    assert c.get("/api/recordings").json()["total"] == 1


def test_department_user_cannot_use_admin(env):
    c = env["client"]
    login(c, "alpha_support")
    assert c.get("/api/admin/users").status_code == 403
    assert c.get("/api/admin/audit").status_code == 403


def test_disabling_user_kills_session(env):
    c = env["client"]
    login(c, "root")
    r = c.put("/api/admin/users/102", json={"username": "alpha_support", "role": "department", "customer_id": 1, "department_ids": [10], "active": False}, headers=HDR)
    assert r.status_code == 200
    assert login(c, "alpha_support").status_code == 401
