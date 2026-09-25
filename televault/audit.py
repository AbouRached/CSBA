"""Append-only audit log. Nothing in the application ever deletes from audit_log.

Every event is also mirrored to the Windows Application event log (source "TeleVault"),
so the trail survives someone with access to the database, and can be collected off-box
by whatever SIEM / event forwarding you use (ADR-0001). Failures to mirror never block
the request.
"""
from __future__ import annotations

import logging
import os
import sqlite3

log_ = logging.getLogger("televault.audit")

_eventlog_enabled = False
_WARN_MARKERS = (".fail", "blocked", "locked", "ratelimited", "reset", "reused", "mismatch")

EVENTLOG_SOURCE = "TeleVault"
EVENT_INFO, EVENT_WARNING = 0x0004, 0x0002
EVENT_ID_INFO, EVENT_ID_WARNING = 1000, 2000


def configure(eventlog: bool) -> None:
    global _eventlog_enabled
    _eventlog_enabled = eventlog and os.name == "nt"


def _to_eventlog(action: str, text: str) -> None:
    try:
        import ctypes
        from ctypes import wintypes
        advapi = ctypes.windll.advapi32
        advapi.RegisterEventSourceW.restype = wintypes.HANDLE
        h = advapi.RegisterEventSourceW(None, EVENTLOG_SOURCE)
        if not h:
            return
        try:
            warn = any(m in action for m in _WARN_MARKERS)
            strings = (ctypes.c_wchar_p * 1)(text)
            advapi.ReportEventW(wintypes.HANDLE(h), EVENT_WARNING if warn else EVENT_INFO, 0,
                                EVENT_ID_WARNING if warn else EVENT_ID_INFO, None, 1, 0, strings, None)
        finally:
            advapi.DeregisterEventSource(wintypes.HANDLE(h))
    except Exception:  # noqa: BLE001
        log_.debug("event log write failed", exc_info=True)


def log(
    conn: sqlite3.Connection,
    action: str,
    *,
    user_id: int | None = None,
    username: str = "",
    customer_id: int | None = None,
    ip: str = "",
    detail: str = "",
) -> None:
    conn.execute(
        "INSERT INTO audit_log(user_id, username, customer_id, ip, action, detail) VALUES (?,?,?,?,?,?)",
        (user_id, username, customer_id, ip, action, detail[:2000]),
    )
    if _eventlog_enabled:
        _to_eventlog(action, f"action={action} user={username or '-'} user_id={user_id} "
                             f"customer_id={customer_id} ip={ip or '-'} detail={detail[:1000]}")
