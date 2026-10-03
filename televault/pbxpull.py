"""Pull new call recordings from the PBXs onto each customer's archive drive. COPY ONLY.

Everything is configured on the admin page "PBX pull" (superadmins): the PBX list, the
connection test and host-key trust, the schedule, the thresholds and "run now". The web app
only stores wishes in the database; the work is done by `pbx-pull tick`, run every few minutes
by the SYSTEM task "TeleVault PBX Pull" (the web app's service account can neither read the
SSH key nor write to the archive drives).

- Nothing is ever deleted or changed on a PBX: the job's SSH key is installed there as
  read-only SFTP (`restrict,from=...,command="internal-sftp -R"`), so even this code could not.
- A PBX is pulled only after its host key was seen by a connection test and TRUSTED by a
  superadmin (step-up); a changed host key stops the pull until it is trusted again.
- Because the list comes from the web app, the SYSTEM job re-checks every destination itself:
  the customer's folder must be on a local fixed/removable drive that is not the Windows drive,
  with no junction or link on the path, and be the right disk (volume serial). Only audio files,
  with plain file names, are written, only under YYYY\\MM\\DD.
- Nothing already in the archive is overwritten, except a local file that is SMALLER than the
  PBX's copy (copied while the call was still running): the short copy is kept beside it as
  `<name>.replaced-<date>` and the complete file takes its place.
- A file is taken only once it has not changed for a while (calls in progress), downloaded to
  `<name>.part`, size-checked, then renamed; the PBX's modification time is kept.
- Each run reads how full the PBX's recording disk is (SFTP statvfs) for the admin page;
  crossing the alert level writes a warning to the audit log (and the Windows Event Log).
- One run at a time (lock file); each run is summarised in the audit log.
"""
from __future__ import annotations

import asyncio
import ctypes
import json
import logging
import os
import re
import shutil
import stat as _stat
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import asyncssh

from . import audit
from .config import Config
from .db import Database
from .indexer import drive_state

log = logging.getLogger("televault.pbxpull")

_Y, _MD = re.compile(r"^\d{4}$"), re.compile(r"^\d{2}$")
_BAD_NAME = re.compile(r'[\\/:*?"<>|\x00-\x1f]')
LOCK_STALE_SECONDS = 24 * 3600
KEY_COMMENT = "televault-pbx-pull"

# Settings editable on the admin page: key -> (default, min, max)
SETTINGS = {
    "pbx_night_start": (20, 0, 23),        # hour the nightly full pull starts
    "pbx_night_hours": (10, 1, 23),        # ...and for how long it may run
    "pbx_day_enabled": (1, 0, 1),          # hourly light pull during the day
    "pbx_day_from": (7, 0, 23),
    "pbx_day_to": (19, 0, 23),
    "pbx_recent_days": (2, 1, 14),         # the daytime pull only looks at this many newest days
    "pbx_alert_pct": (80, 50, 99),         # warn when a PBX's recording disk is this full
    "pbx_min_age_minutes": (15, 2, 240),   # a file must be unchanged this long (calls still recording)
    "pbx_parallel": (4, 1, 8),             # simultaneous downloads per PBX
    "pbx_min_free_gb": (20, 1, 2000),      # stop pulling to a drive below this free space
}


def get_settings(c) -> dict[str, int]:
    kv = {r[0]: r[1] for r in c.execute("SELECT key, value FROM settings WHERE key LIKE 'pbx_%'")}
    out = {}
    for k, (default, lo, hi) in SETTINGS.items():
        try:
            out[k] = min(hi, max(lo, int(kv.get(k, default))))
        except ValueError:
            out[k] = default
    return out


def _set(c, key: str, value: str, by: str = "pbx-pull") -> None:
    c.execute("INSERT INTO settings(key, value, updated_by) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET "
              "value = excluded.value, updated_by = excluded.updated_by, "
              "updated_at = strftime('%Y-%m-%dT%H:%M:%SZ','now')", (key, value, by))


def _get(c, key: str, default: str = "") -> str:
    r = c.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return r[0] if r else default


def _utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Source:
    id: int
    name: str
    customer_id: int
    host: str
    user: str
    port: int = 22
    remote_dir: str = "/var/spool/asterisk/monitor"
    enabled: bool = True
    host_key: str = ""        # trusted public host key(s), one "type base64" per line


@dataclass
class Stats:
    source: str
    days: int = 0
    copied: int = 0
    bytes: int = 0
    present: int = 0          # already in the archive with the same size
    in_progress: int = 0      # too fresh, taken next run
    replaced: int = 0         # short local copy replaced by the complete file
    conflicts: int = 0        # local copy is LARGER than the PBX's - left alone
    errors: list[str] = field(default_factory=list)
    stopped: str = ""         # why the run ended early, if it did
    disk_used_pct: float | None = None   # PBX recording disk
    disk_free_gb: float | None = None
    disk_total_gb: float | None = None

    def line(self) -> str:
        s = (f"{self.source}: copied {self.copied} files ({self.bytes / 1e9:.2f} GB), {self.present} already there, "
             f"{self.in_progress} still recording, {self.replaced} completed, {self.conflicts} conflicts, "
             f"{len(self.errors)} errors, {self.days} day folders")
        if self.disk_used_pct is not None:
            s += f"; PBX disk {self.disk_used_pct:.0f}% used ({self.disk_free_gb:.0f} GB free)"
        return s + (f" - stopped: {self.stopped}" if self.stopped else "")

    @property
    def bad(self) -> bool:
        return bool(self.errors) or bool(self.stopped and "time limit" not in self.stopped)


def load_sources(c) -> list[Source]:
    return [Source(id=r["id"], name=r["name"], customer_id=r["customer_id"], host=r["host"], user=r["username"],
                   port=r["port"], remote_dir=r["remote_dir"].rstrip("/") or "/", enabled=bool(r["enabled"]),
                   host_key=r["host_key"] or "")
            for r in c.execute("SELECT * FROM pbx_sources ORDER BY name")]


# ---------------------------------------------------------------- destination safety (SYSTEM writes here)

def unsafe_destination(root: Path) -> str | None:
    """Why the job must not write under `root`, or None. The path comes from the web app's
    database, so it is not trusted: local data drive only, never the Windows drive, no links."""
    s = str(root)
    if s.startswith("\\\\") or not re.match(r"^[A-Za-z]:\\", s):
        return "not a local drive path"
    if os.name == "nt":
        if ctypes.windll.kernel32.GetDriveTypeW(s[:3]) not in (2, 3):     # removable, fixed
            return "not a fixed or removable drive"
        if s[:2].lower() == os.environ.get("SystemDrive", "C:").lower():
            return "the Windows drive is not allowed"
    p = Path(s)
    while len(str(p)) > 3:
        try:
            if p.is_symlink() or (getattr(p.lstat(), "st_file_attributes", 0) & 0x400):   # reparse point
                return f"path goes through a junction or link ({p})"
        except OSError as e:
            return f"cannot check {p}: {e}"
        p = p.parent
    return None


def _local_sizes(folder: Path) -> dict[str, int]:
    try:
        with os.scandir(folder) as it:
            return {e.name: e.stat().st_size for e in it if e.is_file()}
    except FileNotFoundError:
        return {}


async def _dirs(sftp: asyncssh.SFTPClient, path: str, pattern: re.Pattern) -> list[str]:
    names = []
    async for e in sftp.scandir(path):
        if pattern.match(e.filename) and e.attrs.permissions is not None and _stat.S_ISDIR(e.attrs.permissions):
            names.append(e.filename)
    return sorted(names)


async def _pull_file(sftp, remote: str, dest: Path, size: int, mtime: int, st: Stats) -> None:
    part = dest.with_name(dest.name + ".part")
    try:
        await sftp.get(remote, str(part))
        got = part.stat().st_size
        if got != size:
            raise OSError(f"size {got} != {size} on the PBX")
        if dest.exists():   # only reached for a shorter local copy: keep it, never destroy archive data
            dest.rename(dest.with_name(f"{dest.name}.replaced-{datetime.now():%Y%m%d%H%M%S}"))
            st.replaced += 1
        os.replace(part, dest)
        os.utime(dest, (mtime, mtime))
        st.copied += 1
        st.bytes += size
    except (OSError, asyncssh.Error) as e:
        st.errors.append(f"{remote}: {e}")
        log.warning("%s: %s: %s", st.source, remote, e)
        try:
            part.unlink()
        except OSError:
            pass


def _trusted(host_key: str) -> tuple[list, list, list]:
    keys = [asyncssh.import_public_key(line.strip()) for line in host_key.splitlines() if line.strip()]
    return (keys, [], [])


async def _connect(cfg: Config, src: Source, known_hosts):
    return await asyncssh.connect(src.host, port=src.port, username=src.user, client_keys=[str(cfg.pbx_key)],
                                  known_hosts=known_hosts, agent_path=None, password=None,
                                  connect_timeout=20, keepalive_interval=30)


async def _disk(sftp, path: str, st: Stats) -> None:
    try:
        v = await sftp.statvfs(path)
        total, avail = v.frsize * v.blocks, v.frsize * v.bavail
        if total:
            st.disk_total_gb, st.disk_free_gb = total / 1e9, avail / 1e9
            st.disk_used_pct = 100.0 * (1 - avail / total)
    except (asyncssh.Error, AttributeError, OSError) as e:   # old servers lack statvfs
        log.info("%s: disk usage not available: %s", st.source, e)


async def pull_source(cfg: Config, db: Database, src: Source, opts: dict[str, int], *, dry_run: bool = False,
                      deadline: float | None = None, only_day: str | None = None,
                      recent_days: int | None = None) -> Stats:
    st = Stats(src.name)
    with db.conn() as c:
        cust = c.execute("SELECT id, root_path, volume_serial FROM customers WHERE id = ?", (src.customer_id,)).fetchone()
    if cust is None:
        st.stopped = "its customer no longer exists"
        return st
    if not src.host_key.strip():
        st.stopped = "host key not trusted yet - run Test, then Trust, on the PBX pull page"
        return st
    root = Path(cust["root_path"])
    why = unsafe_destination(root)
    if why:
        st.stopped = f"destination {root} refused: {why}"
        return st
    state = drive_state(str(root), cust["volume_serial"])
    if state != "online":
        st.stopped = f"archive drive {root} is {state.replace('_', ' ')}"
        return st
    exts = {e.lower() for e in cfg.audio_extensions}
    min_free = opts["pbx_min_free_gb"] * 1024 ** 3
    sem = asyncio.Semaphore(opts["pbx_parallel"])
    # daytime runs only look at the newest day folders (light on the PBX); the nightly run takes all
    oldest = (datetime.now() - timedelta(days=recent_days - 1)).strftime("%Y/%m/%d") if recent_days else None

    try:
        conn = await _connect(cfg, src, _trusted(src.host_key))
    except (OSError, asyncssh.Error, ValueError) as e:
        st.stopped = f"cannot connect to {src.host}: {e}"
        return st
    async with conn, conn.start_sftp_client() as sftp:
        await _disk(sftp, src.remote_dir, st)
        try:
            years = await _dirs(sftp, src.remote_dir, _Y)
        except asyncssh.SFTPError as e:
            st.stopped = f"cannot list {src.remote_dir}: {e}"
            return st
        for y in years:                                   # oldest first: old months are archived first
            for m in await _dirs(sftp, f"{src.remote_dir}/{y}", _MD):
                for d in await _dirs(sftp, f"{src.remote_dir}/{y}/{m}", _MD):
                    if only_day and f"{y}/{m}/{d}" != only_day:
                        continue
                    if oldest and f"{y}/{m}/{d}" < oldest:
                        continue
                    if deadline and time.time() > deadline:
                        st.stopped = "time limit reached, continues next run"
                        return st
                    if shutil.disk_usage(root).free < min_free:
                        st.stopped = f"less than {opts['pbx_min_free_gb']} GB free on {root.anchor}"
                        return st
                    rdir, ldir = f"{src.remote_dir}/{y}/{m}/{d}", root / y / m / d
                    have = _local_sizes(ldir)
                    fresh = time.time() - opts["pbx_min_age_minutes"] * 60
                    todo = []
                    async for e in sftp.scandir(rdir):
                        a = e.attrs
                        if a.permissions is None or not _stat.S_ISREG(a.permissions):
                            continue
                        name = e.filename
                        if _BAD_NAME.search(name) or name in (".", "..") or name.endswith((" ", ".")):
                            continue                      # never let a server choose a path
                        if os.path.splitext(name)[1].lower() not in exts:
                            continue
                        size, local = int(a.size or 0), have.get(name)
                        if local == size:
                            st.present += 1
                        elif (a.mtime or 0) > fresh:
                            st.in_progress += 1
                        elif local is not None and local > size:
                            st.conflicts += 1
                            log.warning("%s: %s/%s is larger in the archive (%d) than on the PBX (%d) - left alone",
                                        src.name, rdir, name, local, size)
                        else:
                            todo.append((name, size, int(a.mtime or 0)))
                    st.days += 1
                    if dry_run:
                        st.copied += len(todo)
                        st.bytes += sum(s for _, s, _ in todo)
                        continue
                    if not todo:
                        continue
                    ldir.mkdir(parents=True, exist_ok=True)

                    async def one(name: str, size: int, mtime: int) -> None:
                        async with sem:
                            await _pull_file(sftp, f"{rdir}/{name}", ldir / name, size, mtime, st)
                    await asyncio.gather(*(one(*t) for t in todo))
                    log.info("%s %s/%s/%s: %d files", src.name, y, m, d, len(todo))
                    if len(st.errors) > 50:
                        st.stopped = "too many errors"
                        return st
    return st


def _save_status(c, st: Stats, src: Source, alert_pct: int) -> None:
    """Last run + PBX disk for the admin page; a warning when the disk crosses the alert level."""
    old = c.execute("SELECT status_json FROM pbx_sources WHERE id = ?", (src.id,)).fetchone()
    was_high = bool(old and old[0] and json.loads(old[0]).get("disk_high"))
    high = st.disk_used_pct is not None and st.disk_used_pct >= alert_pct
    c.execute("UPDATE pbx_sources SET status_json = ? WHERE id = ?", (json.dumps({
        "at": _utc(), "summary": st.line(), "copied": st.copied, "bytes": st.bytes, "errors": len(st.errors),
        "stopped": st.stopped, "disk_used_pct": st.disk_used_pct, "disk_free_gb": st.disk_free_gb,
        "disk_total_gb": st.disk_total_gb, "disk_high": high}), src.id))
    if high and not was_high:
        audit.log(c, "system.pbx.disk_high", username="pbx-pull", customer_id=src.customer_id,
                  detail=f"{st.source}: PBX recording disk {st.disk_used_pct:.0f}% used, "
                         f"{st.disk_free_gb:.0f} GB free (alert level {alert_pct}%)")
    elif was_high and not high and st.disk_used_pct is not None:
        audit.log(c, "system.pbx.disk_ok", username="pbx-pull", customer_id=src.customer_id,
                  detail=f"{st.source}: back to {st.disk_used_pct:.0f}% used")


def _lock(cfg: Config) -> Path | None:
    p = cfg.data_dir / "pbxpull.lock"
    try:
        if p.exists() and time.time() - p.stat().st_mtime > LOCK_STALE_SECONDS:
            p.unlink()
        fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return p
    except FileExistsError:
        return None


async def run(cfg: Config, db: Database, *, only: str | None = None, dry_run: bool = False,
              max_hours: float | None = None, only_day: str | None = None,
              recent_days: int | None = None) -> list[Stats]:
    lock = None if dry_run else _lock(cfg)
    if not dry_run and lock is None:
        log.warning("another pull is still running (data/pbxpull.lock) - nothing done")
        return []
    deadline = time.time() + max_hours * 3600 if max_hours else None
    results = []
    try:
        with db.conn() as c:
            srcs, opts = load_sources(c), get_settings(c)
        for src in srcs:
            if not src.enabled or (only and src.name != only):
                continue
            st = await pull_source(cfg, db, src, opts, dry_run=dry_run, deadline=deadline, only_day=only_day,
                                   recent_days=recent_days)
            results.append(st)
            log.info("%s%s", "[dry run] " if dry_run else "", st.line())
            if not dry_run:
                with db.conn() as c:
                    audit.log(c, "system.pbxpull.error" if st.bad else "system.pbxpull.done", username="pbx-pull",
                              customer_id=src.customer_id,
                              detail=st.line() + (" | " + "; ".join(st.errors[:3]) if st.errors else ""))
                    _save_status(c, st, src, opts["pbx_alert_pct"])
    finally:
        if lock:
            lock.unlink(missing_ok=True)
    return results


# ---------------------------------------------------------------- key, connection test, scheduler tick

def ensure_key(cfg: Config) -> str:
    """Create the job's SSH key on first use; returns the public key ('ssh-ed25519 AAAA... comment')."""
    cfg.pbx_key.parent.mkdir(parents=True, exist_ok=True)
    if not cfg.pbx_key.exists():
        k = asyncssh.generate_private_key("ssh-ed25519", comment=KEY_COMMENT)
        k.write_private_key(str(cfg.pbx_key))
    k = asyncssh.read_private_key(str(cfg.pbx_key))
    pub = k.export_public_key().decode().strip()
    return pub if len(pub.split()) > 2 else f"{pub} {KEY_COMMENT}"


async def test_source(cfg: Config, src: Source) -> dict:
    """Connect WITHOUT trusting any host key yet, report what was seen. Reads only."""
    out: dict = {"at": _utc(), "ok": False, "message": "", "host_key": "", "fingerprint": ""}
    try:
        conn = await _connect(cfg, src, None)
    except asyncssh.PermissionDenied:
        out["message"] = "The PBX refused the key - add TeleVault's key line to this user's ~/.ssh/authorized_keys on the PBX."
        return out
    except (OSError, asyncssh.Error) as e:
        out["message"] = f"Cannot connect: {e}"
        return out
    async with conn:
        hk = conn.get_server_host_key()
        if hk is not None:
            out["host_key"] = hk.export_public_key().decode().strip()
            out["fingerprint"] = hk.get_fingerprint()
        try:
            async with conn.start_sftp_client() as sftp:
                years = await _dirs(sftp, src.remote_dir, _Y)
                st = Stats(src.name)
                await _disk(sftp, src.remote_dir, st)
                out["ok"] = True
                out["message"] = (f"Connected. {src.remote_dir} has year folders: {', '.join(years) or 'none'}"
                                  + (f"; disk {st.disk_used_pct:.0f}% used, {st.disk_free_gb:.0f} GB free"
                                     if st.disk_used_pct is not None else ""))
        except (asyncssh.Error, OSError) as e:
            out["message"] = f"Signed in, but cannot read {src.remote_dir}: {e}"
    return out


def seed_from_config(c, cfg: Config) -> int:
    """First tick only: carry config.json's pbx_sources (and their pinned host keys) into the
    list managed on the admin page."""
    if _get(c, "pbx_seeded") or c.execute("SELECT COUNT(*) FROM pbx_sources").fetchone()[0]:
        _set(c, "pbx_seeded", "1")
        return 0
    pinned: dict[str, list[str]] = {}
    if cfg.pbx_known_hosts.exists():
        for line in cfg.pbx_known_hosts.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 3 and not line.startswith("#"):
                pinned.setdefault(parts[0], []).append(" ".join(parts[1:3]))
    n = 0
    for raw in cfg.pbx_sources:
        cust = c.execute("SELECT id FROM customers WHERE slug = ?", (str(raw.get("customer", "")),)).fetchone()
        if cust is None:
            continue
        host, port = str(raw["host"]), int(raw.get("port", 22))
        keys = pinned.get(host, []) + pinned.get(f"[{host}]:{port}", [])
        c.execute("INSERT OR IGNORE INTO pbx_sources(name, customer_id, host, port, username, remote_dir, enabled, "
                  "host_key, created_by) VALUES (?,?,?,?,?,?,?,?, 'config.json')",
                  (str(raw["name"]), cust["id"], host, port, str(raw["user"]),
                   str(raw.get("remote_dir", "/var/spool/asterisk/monitor")), int(bool(raw.get("enabled", True))),
                   "\n".join(keys)))
        n += 1
    _set(c, "pbx_seeded", "1")
    return n


async def tick(cfg: Config, db: Database, now: datetime | None = None) -> str:
    """Run every few minutes by the SYSTEM task: publish the public key, do requested connection
    tests, then whatever the schedule (or a 'run now') asks for. Returns what it did."""
    now = now or datetime.now()
    pub = ensure_key(cfg)
    with db.conn() as c:
        _set(c, "pbx_public_key", pub)
        _set(c, "pbx_tick_at", _utc())
        seeded = seed_from_config(c, cfg)
        if seeded:
            audit.log(c, "system.pbxpull.seeded", username="pbx-pull", detail=f"{seeded} PBX from config.json")
        pending = [s for s in load_sources(c)
                   if c.execute("SELECT test_requested FROM pbx_sources WHERE id = ?", (s.id,)).fetchone()[0]]
    for src in pending:
        res = await test_source(cfg, src)
        with db.conn() as c:
            c.execute("UPDATE pbx_sources SET test_requested = 0, test_json = ?, host_key_seen = ? WHERE id = ?",
                      (json.dumps({k: res[k] for k in ("at", "ok", "message", "fingerprint")}), res["host_key"], src.id))
            audit.log(c, "system.pbx.test" if res["ok"] else "system.pbx.test.fail", username="pbx-pull",
                      customer_id=src.customer_id, detail=f"{src.name} ({src.host}): {res['message']}")

    with db.conn() as c:
        opts = get_settings(c)
        requested = _get(c, "pbx_run_requested")
        if requested:
            _set(c, "pbx_run_requested", "")
    if requested:
        await run(cfg, db, only=None if requested == "all" else requested)
        return f"run now ({requested})"

    # nightly full pull: once per window
    start = now.replace(hour=opts["pbx_night_start"], minute=0, second=0, microsecond=0)
    if now < start:
        start -= timedelta(days=1)
    end = start + timedelta(hours=opts["pbx_night_hours"])
    with db.conn() as c:
        last_night, last_day = _get(c, "pbx_last_night"), float(_get(c, "pbx_last_day_run", "0") or 0)
    if start <= now < end:
        if last_night != start.strftime("%Y-%m-%d"):
            with db.conn() as c:
                _set(c, "pbx_last_night", start.strftime("%Y-%m-%d"))
            await run(cfg, db, max_hours=max(0.1, (end - now).total_seconds() / 3600))
            return "nightly pull"
        return "idle (nightly pull already done)"
    # daytime: hourly, newest days only
    lo, hi = opts["pbx_day_from"], opts["pbx_day_to"]
    in_day = (lo <= now.hour <= hi) if lo <= hi else (now.hour >= lo or now.hour <= hi)
    if opts["pbx_day_enabled"] and in_day and time.time() - last_day >= 55 * 60:
        with db.conn() as c:
            _set(c, "pbx_last_day_run", str(time.time()))
        await run(cfg, db, recent_days=opts["pbx_recent_days"], max_hours=0.8)
        return "daytime pull"
    return "idle"
