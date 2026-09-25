"""The indexer must not hold the database write lock while it walks a (large) drive."""
from __future__ import annotations

import sqlite3

from televault import indexer


def test_other_writers_are_not_blocked_during_walk(env, monkeypatch):
    real_walk = indexer._walk_audio
    results = []

    def walk_and_try_to_write(root, exts, errors=None):
        for i, item in enumerate(real_walk(root, exts, errors)):
            yield item
            if i == 6:  # mid-walk, after 3 committed batches: another process (web, CLI) writes
                other = sqlite3.connect(str(env["db"].db_path), timeout=0.5)
                try:
                    other.execute("INSERT INTO audit_log(action, detail) VALUES ('test.write', 'during walk')")
                    other.commit()
                    results.append("ok")
                except sqlite3.OperationalError as e:
                    results.append(str(e))
                finally:
                    other.close()

    monkeypatch.setattr(indexer, "_walk_audio", walk_and_try_to_write)
    monkeypatch.setattr(indexer, "BATCH", 2)  # several walk batches are written before the probe
    with env["db"].conn() as c:               # and there is real work to do, not a no-op rescan
        c.execute("DELETE FROM recordings WHERE customer_id = 1")
    r = indexer.index_customer(env["db"], env["cfg"], 1)
    assert r["status"] == "ok" and r["added"] == 9 and results == ["ok"]


def test_unchanged_rescan_writes_nothing(env):
    r = indexer.index_customer(env["db"], env["cfg"], 1)  # fixture already indexed once
    assert (r["added"], r["updated"], r["removed"]) == (0, 0, 0) and r["seen"] == 9


def test_changed_file_is_updated(env):
    f = env["drive_a"] / "2026/08/20/q-126-437-20260820-102616-1787210776.371575.wav"
    f.write_bytes(f.read_bytes() + b"\0" * 100)
    r = indexer.index_customer(env["db"], env["cfg"], 1)
    assert r["updated"] == 1 and r["added"] == 0


def test_large_batches(env, monkeypatch):
    monkeypatch.setattr(indexer, "BATCH", 2)  # force many small transactions
    with env["db"].conn() as c:
        c.execute("DELETE FROM recordings WHERE customer_id = 1")
    r = indexer.index_customer(env["db"], env["cfg"], 1)
    assert r["added"] == 9
    with env["db"].conn() as c:
        assert c.execute("SELECT COUNT(*) FROM recordings WHERE customer_id = 1").fetchone()[0] == 9
