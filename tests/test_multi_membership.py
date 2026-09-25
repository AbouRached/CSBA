"""Superadmins created from the UI; users spanning several customers and departments."""
from __future__ import annotations

from conftest import HDR, login

BETA_436 = "external-436-22222222-20260901-100100-1790000060.2.wav"   # Beta, ext 436
ALPHA_436 = "out-3281883752-436-20260820-115255-1787215975.372897.wav"  # Alpha, ext 436
BETA_DID = "in-9999-11111111-20260901-100000-1790000000.1.wav"


def _names(c, **params):
    out, page = [], 1
    while True:
        r = c.get("/api/recordings", params={"include_empty": "true", "page": page, **params}).json()
        out += [x["filename"] for x in r["items"]]
        if page * r["page_size"] >= r["total"]:
            return set(out)
        page += 1


def _beta_dept(env, dept_id=60, **rules):
    import json
    with env["db"].conn() as c:
        c.execute("INSERT INTO departments(id, customer_id, name, extensions_json, queues_json, dids_json) VALUES (?,2,?,?,?,?)",
                  (dept_id, rules.get("name", "BetaReception"), json.dumps(rules.get("ext", [])), "[]",
                   json.dumps(rules.get("did", ["9999"]))))
    return dept_id


# ---------------------------------------------------------------- departments across customers

def test_department_rules_stay_inside_their_customer(env):
    """User in Alpha 'Support' (ext 436) and Beta 'Reception' (DID 9999): ext 436 must NOT
    leak Beta's ext-436 recording, and Beta's DID rule must not open anything of Alpha's."""
    root = env["client"]; login(root, "root")
    beta = _beta_dept(env)
    r = root.post("/api/admin/users", json={"username": "multi.dept", "role": "department",
                                            "department_ids": [10, beta]}, headers=HDR)
    assert r.status_code == 200
    u = env["app"]  # fresh client for the new user
    from conftest import client_from, OFFICE
    c = client_from(u, OFFICE)
    login(c, "multi.dept", r.json()["initial_password"])
    c.post("/api/auth/change-password", json={"current_password": r.json()["initial_password"],
                                              "new_password": "Another-Long-Pass-99"}, headers=HDR)
    names = _names(c)
    assert ALPHA_436 in names and BETA_DID in names
    assert BETA_436 not in names          # 436 is an Alpha Support extension, not a Beta one
    me = c.get("/api/auth/me").json()
    assert {x["slug"] for x in me["customers"]} == {"alpha", "beta"} and me["customer"] is None
    # narrowing to one customer works, and to a foreign one gives nothing
    assert _names(c, customer_id=2) == {BETA_DID}
    with env["db"].conn() as db:
        db.execute("INSERT INTO customers(id, slug, name, root_path) VALUES (9, 'gamma', 'Gamma', 'Z:\\\\nope')")
    assert _names(c, customer_id=9) == _names(c)  # not theirs -> falls back to their own customers only


def test_customer_admin_of_two_customers(env):
    root = env["client"]; login(root, "root")
    r = root.post("/api/admin/users", json={"username": "group.admin", "role": "customer_admin",
                                            "customer_ids": [1, 2]}, headers=HDR)
    assert r.status_code == 200
    from conftest import client_from, OFFICE
    c = client_from(env["app"], OFFICE)
    pw = r.json()["initial_password"]
    login(c, "group.admin", pw)
    c.post("/api/auth/change-password", json={"current_password": pw, "new_password": "Another-Long-Pass-99"}, headers=HDR)
    names = _names(c)
    assert ALPHA_436 in names and BETA_436 in names
    assert {x["slug"] for x in c.get("/api/admin/customers").json()} == {"alpha", "beta"}
    # can create departments for either of its customers, not for others
    assert c.post("/api/admin/departments", json={"customer_id": 2, "name": "B2", "extensions": ["1"]}, headers=HDR).status_code == 200
    assert c.post("/api/admin/departments", json={"customer_id": 3, "name": "X", "extensions": ["1"]}, headers=HDR).status_code == 403


def test_customer_admin_cannot_touch_users_spanning_other_customers(env):
    root = env["client"]; login(root, "root")
    beta = _beta_dept(env)
    uid = root.post("/api/admin/users", json={"username": "spans", "role": "department",
                                              "department_ids": [10, beta]}, headers=HDR).json()["id"]
    a = env["client"]; login(a, "alpha_admin")
    users = {u["username"]: u for u in a.get("/api/admin/users").json()}
    assert users["spans"]["manageable"] is False and users["alpha_support"]["manageable"] is True
    body = {"username": "spans", "role": "department", "department_ids": [10]}
    assert a.put(f"/api/admin/users/{uid}", json=body, headers=HDR).status_code == 403
    assert a.post(f"/api/admin/users/{uid}/reset-password", headers=HDR).status_code == 403
    # and cannot give its own user a Beta department
    body = {"username": "alpha_support", "role": "department", "department_ids": [10, beta]}
    assert a.put("/api/admin/users/102", json=body, headers=HDR).status_code == 403


# ---------------------------------------------------------------- superadmins from the UI

def test_superadmin_creates_and_manages_superadmins(env):
    c = env["client"]; login(c, "root")
    r = c.post("/api/admin/users", json={"username": "second.admin", "role": "superadmin"}, headers=HDR)
    assert r.status_code == 200
    uid = r.json()["id"]
    users = {u["username"]: u for u in c.get("/api/admin/users").json()}
    assert users["second.admin"]["role"] == "superadmin" and users["root"]["is_self"] is True
    assert c.post(f"/api/admin/users/{uid}/reset-mfa", headers=HDR).status_code == 200
    assert c.post(f"/api/admin/users/{uid}/reset-password", headers=HDR).status_code == 200
    with env["db"].conn() as db:
        assert db.execute("SELECT must_change_password FROM users WHERE id = ?", (uid,)).fetchone()[0] == 1
        assert db.execute("SELECT COUNT(*) FROM audit_log WHERE action='admin.user.create' AND detail LIKE 'second.admin role=superadmin%'").fetchone()[0] == 1


def test_superadmin_self_and_last_protection(env):
    c = env["client"]; login(c, "root")
    me = {"username": "root", "role": "superadmin", "active": False}
    assert c.put("/api/admin/users/100", json=me, headers=HDR).status_code == 409          # can't disable self
    assert c.put("/api/admin/users/100", json={**me, "active": True, "role": "department",
                                                "department_ids": [10]}, headers=HDR).status_code == 409  # can't demote self
    assert c.post("/api/admin/users/100/reset-mfa", headers=HDR).status_code == 409       # not on own account
    uid = c.post("/api/admin/users", json={"username": "second.admin", "role": "superadmin"}, headers=HDR).json()["id"]
    assert c.put(f"/api/admin/users/{uid}", json={"username": "second.admin", "role": "superadmin", "active": False},
                 headers=HDR).status_code == 200                                           # root still active
    # now make root the only active one and try to disable the last via the other account
    with env["db"].conn() as db:
        db.execute("UPDATE users SET active = 1 WHERE id = ?", (uid,))
        db.execute("UPDATE users SET active = 0 WHERE id = 100")
    from conftest import client_from, OFFICE
    s = client_from(env["app"], OFFICE)
    with env["db"].conn() as db:
        from televault.security import hash_password
        db.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                   (hash_password("Correct-Horse-Battery-9"), uid))
    login(s, "second.admin")
    r = s.put(f"/api/admin/users/{uid}", json={"username": "second.admin", "role": "superadmin", "active": False}, headers=HDR)
    assert r.status_code == 409


def test_only_superadmins_create_superadmins(env):
    a = env["client"]; login(a, "alpha_admin")
    assert a.post("/api/admin/users", json={"username": "sneaky", "role": "superadmin"}, headers=HDR).status_code == 403
    users = a.get("/api/admin/users").json()
    assert all(u["role"] != "superadmin" for u in users)
