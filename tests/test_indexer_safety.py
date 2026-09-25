"""The indexer must never forget recordings just because it could not read a folder."""
from __future__ import annotations

import os

from televault import indexer


def _count(env, cid=1):
    with env["db"].conn() as c:
        return c.execute("SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (cid,)).fetchone()[0]


def test_unreadable_root_keeps_index(env, monkeypatch):
    before = _count(env)
    assert before > 0
    real = os.scandir

    def denied(path=".", *a, **k):
        if os.path.abspath(path) == os.path.abspath(env["drive_a"]):
            raise PermissionError(5, "Access is denied")
        return real(path, *a, **k)

    monkeypatch.setattr(indexer.os, "scandir", denied)
    r = indexer.index_customer(env["db"], env["cfg"], 1)
    assert r["status"] == "error" and "cannot read root" in r["message"]
    assert _count(env) == before


def test_unreadable_subfolder_removes_nothing(env, monkeypatch):
    before = _count(env)
    real_walk = os.walk

    def walk_with_error(top, onerror=None, **kw):
        for dirpath, dirnames, filenames in real_walk(top, onerror=onerror, **kw):
            if dirpath.endswith("20"):  # pretend 2026/08/20 is unreadable
                onerror(PermissionError(5, "Access is denied", dirpath))
                dirnames[:] = []
                continue
            yield dirpath, dirnames, filenames

    monkeypatch.setattr(indexer.os, "walk", walk_with_error)
    r = indexer.index_customer(env["db"], env["cfg"], 1)
    assert r["status"] == "ok" and r["removed"] == 0
    assert _count(env) == before
    with env["db"].conn() as c:
        assert c.execute("SELECT status FROM index_runs ORDER BY id DESC LIMIT 1").fetchone()[0] == "partial"


def test_file_really_gone_is_still_removed(env):
    before = _count(env)
    (env["drive_a"] / "2026/08/19/external-436-70000001-20260819-090000-1787100000.100000.wav").unlink()
    r = indexer.index_customer(env["db"], env["cfg"], 1)
    assert r["removed"] == 1 and _count(env) == before - 1
