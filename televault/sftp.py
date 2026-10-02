"""Read-only SFTP feed: an external system (e.g. an AI / analytics vendor) pulls a rolling
window of ONE customer's recordings.

Gates (ADR-0001 item 18):
- Off unless config `sftp_port` is set. Own port; the Windows firewall rule and the router
  forward are limited to the vendor's addresses (scripts/install-sftp.ps1).
- Accounts are managed by superadmins in the admin UI (step-up code). Each is pinned to one
  customer and a window in days of call time, counted back from that customer's LATEST
  recording (drives are often filled in batches, so "today" would leave the window empty);
  it is not a TeleVault user and has no OS account.
- Every connection must come from the account's allowed IPs (checked here too, not only by the
  firewall). SSH key preferred, or a generated password (Argon2id). Repeated failures from an
  address are refused for a while; addresses on no account's list are dropped at connect.
- The client sees a VIRTUAL tree built from the index: <rel_path> of in-window, non-empty
  recordings only. Nothing on disk is listed directly; writes, renames, deletes, links and
  attribute changes are refused; a file outside the window simply does not exist. Opening a
  file re-checks the window, the customer's drive (volume serial) and path containment.
- Every login and every file opened is audited (and mirrored to the Windows Event Log).
- No shell, exec, SCP, port/agent/X11 forwarding.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import posixpath
import re
import stat as _stat
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

import asyncssh
from asyncssh import (FILEXFER_TYPE_DIRECTORY, FILEXFER_TYPE_REGULAR, FXF_APPEND, FXF_CREAT, FXF_TRUNC,
                      FXF_WRITE, SFTPAttrs, SFTPFailure, SFTPName, SFTPNoSuchFile, SFTPOpUnsupported,
                      SFTPPermissionDenied)

from . import audit
from .config import Config
from .db import Database
from .indexer import drive_state
from .security import verify_password

log = logging.getLogger("televault.sftp")

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,31}$")
CACHE_SECONDS = 300          # the virtual tree is rebuilt at most this often
FAIL_LIMIT, FAIL_WINDOW = 10, 600
DIR_MODE, FILE_MODE = _stat.S_IFDIR | 0o555, _stat.S_IFREG | 0o444
READ_ONLY = "This feed is read-only."


# ---------------------------------------------------------------- helpers shared with the admin API

def parse_keys(text: str) -> list[asyncssh.SSHKey]:
    """authorized_keys-style text (one public key per line) -> keys; raises ValueError."""
    keys = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            keys.append(asyncssh.import_public_key(line))
        except (asyncssh.KeyImportError, ValueError) as e:
            raise ValueError(f"Not a valid SSH public key: {line[:40]}...") from e
    return keys


def key_fingerprints(text: str) -> list[str]:
    try:
        return [k.get_fingerprint() for k in parse_keys(text)]
    except ValueError:
        return []


def parse_networks(items: list[str]) -> list[str]:
    """Allowed source addresses; at least one, none wider than /16 (IPv4) or /48 (IPv6)."""
    out = []
    for raw in items:
        raw = raw.strip()
        if not raw:
            continue
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            raise ValueError(f"Not an IP address or network: {raw}")
        if net.prefixlen < (16 if net.version == 4 else 48):
            raise ValueError(f"{raw} is too wide - list the vendor's own addresses.")
        out.append(str(net))
    if not out:
        raise ValueError("List at least one address the vendor connects from.")
    return sorted(set(out))


def _in(ip: str, nets: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.version == 6 and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return any(addr in ipaddress.ip_network(n) for n in nets)


def host_key(cfg: Config) -> asyncssh.SSHKey:
    p = cfg.data_dir / "sftp_host_ed25519"
    if not p.exists():
        asyncssh.generate_private_key("ssh-ed25519").write_private_key(str(p))
    return asyncssh.read_private_key(str(p))


def host_fingerprint(cfg: Config) -> str:
    return host_key(cfg).get_fingerprint()


_TS = "%Y-%m-%dT%H:%M:%S"


def window(conn, customer_id: int, days: int) -> tuple[str, str]:
    """(start, latest): the window covers `days` of call time ending at the customer's newest
    recording. Only names that carry a date anchor it (undated files are indexed with their
    file time, which can be anything), and nothing dated in the future does."""
    latest = conn.execute(
        "SELECT MAX(rec_ts) FROM recordings WHERE customer_id = ? AND empty = 0 "
        "AND rec_type != 'unknown' AND rec_ts <= ?",
        (customer_id, datetime.now().strftime(_TS))).fetchone()[0]
    anchor = datetime.fromisoformat(latest) if latest else datetime.now()
    return (anchor - timedelta(days=days)).strftime(_TS), anchor.strftime(_TS)


_IN_WINDOW = "r.customer_id = ? AND r.empty = 0 AND r.rec_ts >= ?"


# ---------------------------------------------------------------- virtual tree

@dataclass
class Entry:
    rec_id: int | None       # None = directory
    size: int = 0
    mtime: int = 0


class Tree:
    def __init__(self, rows, built: float):
        self.built = built
        self.dirs: dict[str, dict[str, Entry]] = {"": {}}
        for rec_id, rel, size, mtime in rows:
            parts = [x for x in str(rel).replace("\\", "/").split("/") if x]
            parent, mtime = "", int(mtime or 0)
            for part in parts[:-1]:
                kids = self.dirs.setdefault(parent, {})
                d = kids.setdefault(part, Entry(None, 0, mtime))
                d.mtime = max(d.mtime, mtime)
                parent = f"{parent}/{part}" if parent else part
                self.dirs.setdefault(parent, {})
            if parts:
                self.dirs.setdefault(parent, {})[parts[-1]] = Entry(rec_id, int(size or 0), mtime)

    def lookup(self, path: str) -> Entry | None:
        if path == "":
            return Entry(None, 0, int(self.built))
        parent, _, name = path.rpartition("/")
        return self.dirs.get(parent, {}).get(name)


def _norm(path: bytes) -> str:
    """Client path -> key in the virtual tree ('' = root). '..' can never climb above root."""
    try:
        s = path.decode("utf-8")
    except UnicodeDecodeError:
        raise SFTPNoSuchFile("No such file")
    if "\x00" in s:
        raise SFTPNoSuchFile("No such file")
    return posixpath.normpath(posixpath.join("/", s.replace("\\", "/"))).lstrip("/")


class _Handle:
    def __init__(self, f, entry: Entry):
        self.f, self.entry, self.lock = f, entry, threading.Lock()

    def pread(self, offset: int, size: int) -> bytes:
        with self.lock:
            self.f.seek(offset)
            return self.f.read(size)


# ---------------------------------------------------------------- feed (accounts, cache, limits)

class Feed:
    def __init__(self, cfg: Config, db: Database):
        self.cfg, self.db = cfg, db
        self._trees: dict[tuple[int, int], Tree] = {}
        self._fails: dict[str, deque] = {}

    # failures per source address
    def blocked(self, ip: str) -> bool:
        q = self._fails.get(ip)
        if not q:
            return False
        while q and q[0] < time.time() - FAIL_WINDOW:
            q.popleft()
        return len(q) >= FAIL_LIMIT

    def fail(self, ip: str) -> None:
        self._fails.setdefault(ip, deque()).append(time.time())

    def known_address(self, ip: str) -> bool:
        with self.db.conn() as c:
            rows = c.execute("SELECT allowed_ips_json FROM sftp_accounts WHERE active = 1").fetchall()
        return any(_in(ip, json.loads(r[0] or "[]")) for r in rows)

    def account(self, username: str) -> dict | None:
        with self.db.conn() as c:
            r = c.execute("SELECT * FROM sftp_accounts WHERE username = ? AND active = 1",
                          (username.lower(),)).fetchone()
        return dict(r) if r else None

    def audit(self, action: str, acct: dict | None, username: str, ip: str, detail: str = "") -> None:
        with self.db.conn() as c:
            audit.log(c, action, username=f"sftp:{username}", ip=ip, detail=detail,
                      customer_id=acct["customer_id"] if acct else None)
            if action == "sftp.login" and acct:
                c.execute("UPDATE sftp_accounts SET last_login_at = strftime('%Y-%m-%dT%H:%M:%SZ','now'), "
                          "last_ip = ? WHERE id = ?", (ip, acct["id"]))

    async def tree(self, customer_id: int, days: int) -> Tree:
        key = (customer_id, days)
        t = self._trees.get(key)
        if t is None or time.time() - t.built > CACHE_SECONDS:
            t = await asyncio.to_thread(self._build, customer_id, days)
            self._trees[key] = t
        return t

    def _build(self, customer_id: int, days: int) -> Tree:
        with self.db.conn() as c:
            rows = c.execute(f"SELECT r.id, r.rel_path, r.size, r.mtime FROM recordings r WHERE {_IN_WINDOW}",
                             (customer_id, window(c, customer_id, days)[0])).fetchall()
        return Tree(rows, time.time())

    def open_recording(self, acct: dict, entry: Entry, vpath: str, ip: str) -> _Handle:
        with self.db.conn() as c:
            # re-read the account: disabling it or narrowing it takes effect on open sessions too
            now = c.execute("SELECT customer_id, window_days FROM sftp_accounts WHERE id = ? AND active = 1",
                            (acct["id"],)).fetchone()
            if now is None or now["customer_id"] != acct["customer_id"]:
                raise SFTPPermissionDenied("Account disabled")
            row = c.execute(
                "SELECT r.rel_path, c.root_path, c.volume_serial FROM recordings r "
                f"JOIN customers c ON c.id = r.customer_id WHERE r.id = ? AND {_IN_WINDOW}",
                (entry.rec_id, acct["customer_id"],
                 window(c, acct["customer_id"], min(now["window_days"], acct["window_days"]))[0])).fetchone()
            if row is None:
                raise SFTPNoSuchFile("No such file")
            root = Path(row["root_path"]).resolve()
            if drive_state(str(root), row["volume_serial"]) != "online":
                raise SFTPFailure("Storage is temporarily unavailable, try again later.")
            full = (root / row["rel_path"]).resolve()
            try:
                full.relative_to(root)
            except ValueError:
                raise SFTPNoSuchFile("No such file")
            try:
                f = open(full, "rb")
            except OSError:
                raise SFTPNoSuchFile("File is missing from the drive")
            audit.log(c, "sftp.download", username=f"sftp:{acct['username']}", customer_id=acct["customer_id"],
                      ip=ip, detail=row["rel_path"])
        return _Handle(f, entry)


# ---------------------------------------------------------------- SSH side

class _SSHServer(asyncssh.SSHServer):
    def __init__(self, feed: Feed):
        self.feed = feed
        self.conn: asyncssh.SSHServerConnection | None = None
        self.ip = ""
        self.acct: dict | None = None

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.conn = conn
        peer = conn.get_extra_info("peername")
        self.ip = str(peer[0]) if peer else ""
        if self.feed.blocked(self.ip) or not self.feed.known_address(self.ip):
            log.info("sftp: dropped connection from %s", self.ip)
            conn.abort()

    def begin_auth(self, username: str) -> bool:
        acct = self.feed.account(username)
        if acct and _in(self.ip, json.loads(acct["allowed_ips_json"] or "[]")):
            self.acct = acct
        else:
            self.acct = None
            self.feed.fail(self.ip)
            self.feed.audit("sftp.blocked", acct, username, self.ip,
                            "address not allowed for this account" if acct else "unknown or disabled account")
        return True   # always ask for credentials: no hint whether the name exists

    def public_key_auth_supported(self) -> bool:
        return True

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        if not self.acct:
            return False
        try:
            return any(k.public_data == key.public_data for k in parse_keys(self.acct["public_keys"]))
        except ValueError:
            return False

    def password_auth_supported(self) -> bool:
        return True

    async def validate_password(self, username: str, password: str) -> bool:
        a = self.acct
        ok = bool(a and a["password_hash"]) and await asyncio.to_thread(verify_password, a["password_hash"], password)
        if not ok:
            self.feed.fail(self.ip)
            if a:
                self.feed.audit("sftp.login.fail", a, username, self.ip, "wrong password")
        return ok

    def auth_completed(self) -> None:
        a = self.acct
        assert a is not None and self.conn is not None
        self.conn.set_extra_info(tv_account=a, tv_ip=self.ip)
        self.feed.audit("sftp.login", a, a["username"], self.ip)


class _ReadOnlySFTP(asyncssh.SFTPServer):
    def __init__(self, chan, feed: Feed):
        super().__init__(chan)
        conn = chan.get_connection()
        self.feed = feed
        self.acct: dict = conn.get_extra_info("tv_account")
        self.ip: str = conn.get_extra_info("tv_ip") or ""

    async def _tree(self) -> Tree:
        return await self.feed.tree(self.acct["customer_id"], self.acct["window_days"])

    async def _entry(self, path: bytes) -> tuple[str, Entry]:
        p = _norm(path)
        e = (await self._tree()).lookup(p)
        if e is None:
            raise SFTPNoSuchFile("No such file")
        return p, e

    @staticmethod
    def _attrs(e: Entry) -> SFTPAttrs:
        if e.rec_id is None:
            return SFTPAttrs(type=FILEXFER_TYPE_DIRECTORY, permissions=DIR_MODE, atime=e.mtime, mtime=e.mtime)
        return SFTPAttrs(type=FILEXFER_TYPE_REGULAR, size=e.size, permissions=FILE_MODE, atime=e.mtime, mtime=e.mtime)

    def format_user(self, uid):
        return "televault"

    def format_group(self, gid):
        return "televault"

    def map_path(self, path: bytes) -> bytes:   # safety net: nothing may reach the real file system
        raise SFTPPermissionDenied(READ_ONLY)

    def reverse_map_path(self, path: bytes) -> bytes:
        return path

    async def realpath(self, path: bytes) -> bytes:
        return ("/" + _norm(path)).encode("utf-8")

    async def stat(self, path: bytes) -> SFTPAttrs:
        return self._attrs((await self._entry(path))[1])

    async def lstat(self, path: bytes) -> SFTPAttrs:
        return await self.stat(path)

    async def scandir(self, path: bytes):
        p, e = await self._entry(path)
        if e.rec_id is not None:
            raise SFTPFailure("Not a directory")
        tree = await self._tree()
        yield SFTPName(b".", attrs=self._attrs(e))
        yield SFTPName(b"..", attrs=self._attrs(Entry(None, 0, e.mtime)))
        for name, child in sorted(tree.dirs.get(p, {}).items()):
            yield SFTPName(name.encode("utf-8"), attrs=self._attrs(child))

    async def open(self, path: bytes, pflags: int, attrs: SFTPAttrs) -> _Handle:
        if pflags & (FXF_WRITE | FXF_APPEND | FXF_CREAT | FXF_TRUNC):
            raise SFTPPermissionDenied(READ_ONLY)
        p, e = await self._entry(path)
        if e.rec_id is None:
            raise SFTPFailure("Is a directory")
        return await asyncio.to_thread(self.feed.open_recording, self.acct, e, p, self.ip)

    def open56(self, *args, **kwargs):
        raise SFTPOpUnsupported("SFTP version 3 only")

    async def read(self, file_obj: _Handle, offset: int, size: int) -> bytes:
        return await asyncio.to_thread(file_obj.pread, offset, min(size, 1 << 20))

    async def close(self, file_obj: _Handle) -> None:
        await asyncio.to_thread(file_obj.f.close)

    async def fstat(self, file_obj: _Handle) -> SFTPAttrs:
        return self._attrs(file_obj.entry)

    # Everything that would change anything is refused.
    def _deny(self, *args, **kwargs):
        raise SFTPPermissionDenied(READ_ONLY)

    write = setstat = lsetstat = fsetstat = remove = mkdir = rmdir = rename = posix_rename = _deny
    symlink = link = _deny

    def readlink(self, path: bytes):
        raise SFTPNoSuchFile("Not a link")

    def _unsupported(self, *args, **kwargs):
        raise SFTPOpUnsupported("Not supported")

    statvfs = fstatvfs = lock = unlock = fsync = _unsupported


async def start(cfg: Config, db: Database):
    """Start the SFTP listener (called from main.run when sftp_port is set)."""
    feed = Feed(cfg, db)
    server = await asyncssh.listen(
        cfg.sftp_host, cfg.sftp_port,
        server_factory=lambda: _SSHServer(feed),
        server_host_keys=[host_key(cfg)],
        sftp_factory=lambda chan: _ReadOnlySFTP(chan, feed),
        allow_scp=False, agent_forwarding=False, x11_forwarding=False,
        login_timeout=30, keepalive_interval=60,
    )
    log.info("SFTP feed on %s:%d (host key %s)", cfg.sftp_host, cfg.sftp_port, host_fingerprint(cfg))
    return server
