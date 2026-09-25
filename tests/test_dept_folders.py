"""Departments scoped by folder on the customer drive (in addition to extension/queue/DID)."""
from __future__ import annotations

import json

from conftest import HDR, login, make_wav
from televault.indexer import index_customer
from televault.scope import DeptRule, department_predicate


def _set_folders(env, dept_id, folders, clear_numbers=False):
    with env["db"].conn() as c:
        c.execute("UPDATE departments SET folders_json = ? WHERE id = ?", (json.dumps(folders), dept_id))
        if clear_numbers:
            c.execute("UPDATE departments SET extensions_json='[]', queues_json='[]', dids_json='[]' WHERE id = ?",
                      (dept_id,))


def _visible(c):
    """Every filename the user can see (walks all pages; the test page size is small)."""
    names, page = [], 1
    while True:
        r = c.get("/api/recordings", params={"include_empty": "true", "page": page}).json()
        names += [x["filename"] for x in r["items"]]
        if page * r["page_size"] >= r["total"]:
            return sorted(names)
        page += 1


def test_folder_only_department_sees_whole_subtree(env):
    _set_folders(env, 10, ["2026/08/19"], clear_numbers=True)
    c = env["client"]; login(c, "alpha_support")
    assert _visible(c) == ["external-436-70000001-20260819-090000-1787100000.100000.wav"]


def test_folder_rule_is_added_to_number_rules(env):
    c = env["client"]; login(c, "alpha_support")
    before = set(_visible(c))
    _set_folders(env, 10, ["loose"])
    after = set(_visible(c))
    assert after == before | {"notes.wav"}


def test_folder_prefix_does_not_match_sibling_names(env):
    # "loose" must not match "loose-other/..."
    make_wav(env["drive_a"] / "loose-other" / "x.wav", 100)
    index_customer(env["db"], env["cfg"], 1)
    _set_folders(env, 10, ["loose"], clear_numbers=True)
    c = env["client"]; login(c, "alpha_support")
    assert _visible(c) == ["notes.wav"]


def test_like_wildcards_in_folder_names_are_literal():
    pred, params = department_predicate([DeptRule([], [], [], ["a_b%c"])])
    assert "ESCAPE" in pred and params == ["a\\_b\\%c/%"]


def test_api_saves_and_validates_folders(env):
    c = env["client"]; login(c, "alpha_admin")
    body = {"customer_id": 1, "name": "Support", "extensions": ["436"], "queues": [], "dids": [],
            "folders": ["\\2026\\08\\", "2026/08", " loose/ "]}
    assert c.put("/api/admin/departments/10", json=body, headers=HDR).status_code == 200
    d = next(x for x in c.get("/api/admin/departments").json() if x["id"] == 10)
    assert d["folders"] == ["2026/08", "loose"]
    for bad in ["../other", "C:/Windows", "a/../../b"]:
        r = c.put("/api/admin/departments/10", json={**body, "folders": [bad]}, headers=HDR)
        assert r.status_code == 400, bad


def test_customer_folder_browser_is_scoped(env):
    c = env["client"]; login(c, "alpha_admin")
    r = c.get("/api/admin/customers/1/folders").json()
    assert {d["name"] for d in r["dirs"]} == {"2026", "loose"} and r["parent"] is None
    r = c.get("/api/admin/customers/1/folders", params={"path": "2026/08"}).json()
    assert {d["path"] for d in r["dirs"]} == {"2026/08/19", "2026/08/20"} and r["parent"] == "2026"
    assert c.get("/api/admin/customers/1/folders", params={"path": "../driveB"}).status_code == 400
    assert c.get("/api/admin/customers/2/folders").status_code == 403  # another customer
