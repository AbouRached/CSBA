"""Walks each customer's drive and keeps the `recordings` table in step with it.

Rules:
- Read-only. The indexer never touches a file on disk.
- A customer whose root is not reachable (drive unplugged) is skipped and its existing
  rows are left alone, so history stays browsable and nothing is "forgotten".
- Rows for files that vanished from an *online* root are removed from the index only.
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from pathlib import Path

from .config import Config
from .db import Database
from .parser import fallback_from_mtime, parse_filename
from .security import iso, now_utc

log = logging.getLogger("televault.indexer")


def root_online(root: str) -> bool:
    try:
        p = Path(root)
        return p.exists() and p.is_dir()
    except OSError:
        return False


def _walk_audio(root: Path, exts: set[str], errors: list | None = None):
    """Yield (rel_path, filename, size, mtime) for every audio file under root.
    Folders that cannot be read are appended to `errors` (and logged)."""
    def onerror(e: OSError) -> None:
        log.warning("walk: %s", e)
        if errors is not None:
            errors.append(e)

    for dirpath, dirnames, filenames in os.walk(root, onerror=onerror):
        # never descend into the recycle bin or system dirs
        dirnames[:] = [d for d in dirnames if not d.startswith("$") and d.lower() != "system volume information"]
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in exts:
                continue
            full = os.path.join(dirpath, fn)
            try:
                st = os.stat(full)
            except OSError:
                continue
            rel = os.path.relpath(full, root).replace("\\", "/")
            yield rel, fn, st.st_size, st.st_mtime


def index_customer(db: Database, cfg: Config, customer_id: int) -> dict:
    with db.conn() as c:
        cust = c.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
    if cust is None:
        return {"status": "error", "message": "no such customer"}
    root = cust["root_path"]
    started = iso(now_utc())
    with db.conn() as c:
        run_id = c.execute(
            "INSERT INTO index_runs(customer_id, started_at) VALUES (?,?)", (customer_id, started)
        ).lastrowid

    if not root_online(root):
        msg = f"root offline: {root}"
        log.warning("customer %s: %s", cust["slug"], msg)
        with db.conn() as c:
            c.execute(
                "UPDATE index_runs SET finished_at=?, status='offline', message=? WHERE id=?",
                (iso(now_utc()), msg, run_id),
            )
        return {"status": "offline", "message": msg}

    # A root that exists but cannot be listed (service account lacks rights) is an error,
    # not an empty drive: leave the index exactly as it is.
    try:
        with os.scandir(root):
            pass
    except OSError as e:
        msg = f"cannot read root: {e.strerror or e} ({root})"
        log.error("customer %s: %s", cust["slug"], msg)
        with db.conn() as c:
            c.execute("UPDATE index_runs SET finished_at=?, status='error', message=? WHERE id=?",
                      (iso(now_utc()), msg[:500], run_id))
        return {"status": "error", "message": msg}

    # Per-run marker: the timestamp alone is per-second, so two runs in the same second could
    # not tell old rows from new. The zero-padded run id sorts after it (and after any older
    # marker without one), so "seen_at < marker" means exactly "not seen in this run".
    seen_marker = f"{started}#{run_id:012d}"
    exts = set(cfg.audio_extensions)
    added = 0
    seen = 0
    walk_errors: list[OSError] = []
    batch: list[tuple] = []

    def flush(conn: sqlite3.Connection):
        nonlocal added
        if not batch:
            return
        cur = conn.executemany(
            """INSERT INTO recordings(customer_id, rel_path, filename, rec_type, target, party,
                                      rec_ts, uniqueid, size, mtime, empty, seen_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(customer_id, rel_path) DO UPDATE SET
                   filename=excluded.filename, rec_type=excluded.rec_type, target=excluded.target,
                   party=excluded.party, rec_ts=excluded.rec_ts, uniqueid=excluded.uniqueid,
                   size=excluded.size, mtime=excluded.mtime, empty=excluded.empty,
                   seen_at=excluded.seen_at""",
            # parsed fields are refreshed too, so a parser improvement (e.g. a newly known
            # recording type) corrects rows that were indexed earlier as 'unknown'
            batch,
        )
        added += max(0, cur.rowcount)
        batch.clear()

    try:
        with db.conn() as c:
            before = c.execute(
                "SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (customer_id,)
            ).fetchone()[0]
            for rel, fn, size, mtime in _walk_audio(Path(root), exts, walk_errors):
                seen += 1
                parsed = parse_filename(fn) or fallback_from_mtime(mtime)
                batch.append(
                    (
                        customer_id, rel, fn, parsed.rec_type, parsed.target, parsed.party,
                        parsed.rec_ts, parsed.uniqueid, size, mtime,
                        1 if size <= cfg.empty_file_bytes else 0, seen_marker,
                    )
                )
                if len(batch) >= 1000:
                    flush(c)
            flush(c)
            if walk_errors:
                # Some folders were unreadable: "not seen" may just mean "could not look".
                removed = 0
                log.warning("customer %s: %d unreadable folder(s); keeping unseen rows", cust["slug"], len(walk_errors))
            else:
                removed = c.execute(
                    "DELETE FROM recordings WHERE customer_id = ? AND seen_at < ?",
                    (customer_id, seen_marker),
                ).rowcount
            after = c.execute(
                "SELECT COUNT(*) FROM recordings WHERE customer_id = ?", (customer_id,)
            ).fetchone()[0]
            new_rows = max(0, after - before + removed)
            c.execute(
                """UPDATE index_runs SET finished_at=?, status=?, files_seen=?, files_added=?,
                                         files_removed=?, message=? WHERE id=?""",
                (iso(now_utc()), "partial" if walk_errors else "ok", seen, new_rows, removed,
                 f"{len(walk_errors)} unreadable folder(s)" if walk_errors else "", run_id),
            )
        log.info("customer %s: seen=%d new=%d removed=%d", cust["slug"], seen, new_rows, removed)
        return {"status": "ok", "seen": seen, "added": new_rows, "removed": removed}
    except Exception as e:  # noqa: BLE001
        log.exception("index failed for %s", cust["slug"])
        with db.conn() as c:
            c.execute(
                "UPDATE index_runs SET finished_at=?, status='error', message=? WHERE id=?",
                (iso(now_utc()), str(e)[:500], run_id),
            )
        return {"status": "error", "message": str(e)}


def index_all(db: Database, cfg: Config) -> list[dict]:
    with db.conn() as c:
        ids = [r["id"] for r in c.execute("SELECT id FROM customers WHERE enabled = 1 ORDER BY id")]
    return [index_customer(db, cfg, cid) for cid in ids]


class IndexerThread(threading.Thread):
    """Runs index_all every cfg.index_interval_minutes; `trigger()` runs it now."""

    def __init__(self, db: Database, cfg: Config):
        super().__init__(name="televault-indexer", daemon=True)
        self.db = db
        self.cfg = cfg
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._busy = threading.Lock()
        self.last_run: str | None = None

    def trigger(self) -> None:
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    @property
    def running(self) -> bool:
        return self._busy.locked()

    def run(self) -> None:
        time.sleep(2)
        while not self._stop.is_set():
            with self._busy:
                try:
                    index_all(self.db, self.cfg)
                except Exception:  # noqa: BLE001
                    log.exception("index_all crashed")
                self.last_run = iso(now_utc())
            self._wake.wait(self.cfg.index_interval_minutes * 60)
            self._wake.clear()
