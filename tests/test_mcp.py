"""Local MCP endpoint: protocol, auth, scopes, audit and the troubleshooting tools."""
from __future__ import annotations

import json

import pytest
from starlette.testclient import TestClient

from conftest import HDR, login
from televault.mcp_server import create_token

LOCAL = ("127.0.0.1", 50000)


@pytest.fixture()
def mcp(env):
    app = env["app"].state.mcp_app
    client = TestClient(app, base_url="http://127.0.0.1:8765", client=LOCAL)
    with env["db"].conn() as c:
        _, read = create_token(c, "test-read", "read", "pytest")
        _, op = create_token(c, "test-op", "operate", "pytest")

    def call(method, params=None, token=read, id_=1):
        r = client.post("/mcp", json={"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}},
                        headers={"Authorization": f"Bearer {token}"})
        return r

    def tool(name, args=None, token=read):
        r = call("tools/call", {"name": name, "arguments": args or {}}, token)
        res = r.json()["result"]
        text = res["content"][0]["text"]
        return res["isError"], (text if res["isError"] else json.loads(text))

    return {"client": client, "call": call, "tool": tool, "read": read, "op": op}


def test_initialize_and_list(mcp):
    r = mcp["call"]("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}})
    res = r.json()["result"]
    assert res["protocolVersion"] == "2025-06-18" and res["serverInfo"]["name"] == "televault" and "tools" in res["capabilities"]
    # notification -> 202, no body
    n = mcp["client"].post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                           headers={"Authorization": f"Bearer {mcp['read']}"})
    assert n.status_code == 202
    names_read = {t["name"] for t in mcp["call"]("tools/list").json()["result"]["tools"]}
    names_op = {t["name"] for t in mcp["call"]("tools/list", token=mcp["op"]).json()["result"]["tools"]}
    assert {"health", "explain_access", "tail_log", "recording_stats"} <= names_read
    assert "reindex" not in names_read and {"reindex", "unlock_user"} <= names_op


def test_unknown_version_falls_back(mcp):
    res = mcp["call"]("initialize", {"protocolVersion": "1999-01-01"}).json()["result"]
    assert res["protocolVersion"] == "2025-06-18"


def test_auth_required_and_revocation(env, mcp):
    c = mcp["client"]
    body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
    assert c.post("/mcp", json=body).status_code == 401
    assert c.post("/mcp", json=body, headers={"Authorization": "Bearer tv_nope"}).status_code == 401
    assert mcp["call"]("ping").status_code == 200
    with env["db"].conn() as conn:
        conn.execute("UPDATE mcp_tokens SET revoked_at = 'x' WHERE name = 'test-read'")
    assert mcp["call"]("ping").status_code == 401


def test_local_only(env, mcp):
    app = env["app"].state.mcp_app
    remote = TestClient(app, base_url="http://127.0.0.1:8765", client=("10.50.5.5", 1))
    assert remote.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                       headers={"Authorization": f"Bearer {mcp['read']}"}).status_code == 403
    rebind = TestClient(app, base_url="http://evil.example:8765", client=LOCAL)  # DNS-rebinding Host
    assert rebind.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                       headers={"Authorization": f"Bearer {mcp['read']}"}).status_code == 403
    assert mcp["client"].get("/mcp", headers={"Authorization": f"Bearer {mcp['read']}"}).status_code == 405


def test_health_and_customers(mcp):
    err, h = mcp["tool"]("health")
    assert not err and {c["slug"] for c in h["customers"]} == {"alpha", "beta", "gone"}
    alpha = next(c for c in h["customers"] if c["slug"] == "alpha")
    assert alpha["online"] and alpha["recordings"] == 9
    err, cs = mcp["tool"]("list_customers")
    assert not err and next(c for c in cs if c["slug"] == "gone")["online"] is False


def test_explain_access_matches_real_scope(env, mcp):
    # alpha_support is in Support (ext 436, 548; queue 126)
    err, yes = mcp["tool"]("explain_access", {"username": "alpha_support",
                                              "recording": "out-3281883752-436-20260820-115255-1787215975.372897.wav"})
    assert not err and yes["visible"] is True
    assert any("party 436" in m for d in yes["why"] if isinstance(d, dict) for m in d["matches"])
    err, no = mcp["tool"]("explain_access", {"username": "alpha_support",
                                             "recording": "in-3282-27972203-20260820-092903-1787207343.370894.wav"})
    assert not err and no["visible"] is False
    err, other = mcp["tool"]("explain_access", {"username": "beta_admin",
                                                "recording": "in-3282-27972203-20260820-092903-1787207343.370894.wav"})
    assert other["visible"] is False and "not one of the user's customers" in other["why"][0]
    # cross-check with the web API as that user
    c = env["client"]; login(c, "alpha_support")
    names = {x["filename"] for x in c.get("/api/recordings", params={"q": "out-3281883752"}).json()["items"]}
    assert "out-3281883752-436-20260820-115255-1787215975.372897.wav" in names


def test_parse_and_stats_and_folders(mcp):
    err, p = mcp["tool"]("parse_filename", {"filename": "q-126-437-20260820-102616-1787210776.371575.wav", "customer": "alpha"})
    assert not err and p["parsed"]["rec_type"] == "q" and "Support" in p["departments_by_number"]
    err, s = mcp["tool"]("recording_stats", {"customer": "alpha"})
    assert not err and s["total"] == 9 and s["by_type"]["q"] == 2 and {"folder": "2026", "recordings": 8} in s["top_folders"]
    err, f = mcp["tool"]("list_folders", {"customer": "alpha", "path": "2026/08"})
    assert not err and f["folders"] == ["19", "20"]
    err, msg = mcp["tool"]("list_folders", {"customer": "alpha", "path": "../driveB"})
    assert err and "inside" in msg


def test_operate_scope_and_audit(env, mcp):
    err, msg = mcp["tool"]("unlock_user", {"username": "alpha_admin"})
    assert err and "operate scope" in msg
    with env["db"].conn() as c:
        c.execute("UPDATE users SET locked_until = '2999-01-01T00:00:00Z', failed_attempts = 3 WHERE username = 'alpha_admin'")
    err, res = mcp["tool"]("unlock_user", {"username": "alpha_admin"}, token=mcp["op"])
    assert not err and res["failed_attempts_cleared"] == 3
    err, r = mcp["tool"]("reindex", {"customer": "alpha"}, token=mcp["op"])
    assert not err and r["status"] == "ok"
    with env["db"].conn() as c:
        acts = [r[0] for r in c.execute("SELECT detail FROM audit_log WHERE action = 'mcp.tool' ORDER BY id")]
        users = {r[0] for r in c.execute("SELECT username FROM audit_log WHERE action = 'mcp.tool'")}
    assert [a.split()[0] for a in acts] == ["unlock_user", "unlock_user", "reindex"]
    assert users == {"mcp:test-read", "mcp:test-op"}


def test_unknown_tool_and_method(mcp):
    assert mcp["call"]("tools/call", {"name": "delete_everything"}).json()["error"]["code"] == -32602
    assert mcp["call"]("resources/list").json()["error"]["code"] == -32601


def test_token_admin_api(env):
    c = env["client"]; login(c, "root")
    r = c.post("/api/admin/mcp-tokens", json={"name": "laptop", "scope": "read"}, headers=HDR).json()
    assert r["token"].startswith("tv_") and "claude mcp add --transport http televault" in r["claude_command"]
    lst = c.get("/api/admin/mcp-tokens").json()["tokens"]
    assert lst[0]["name"] == "laptop" and "token" not in lst[0] and "token_hash" not in lst[0]
    assert c.delete(f"/api/admin/mcp-tokens/{r['id']}", headers=HDR).status_code == 200
    a = env["client"]; login(a, "alpha_admin")
    assert a.get("/api/admin/mcp-tokens").status_code == 403
