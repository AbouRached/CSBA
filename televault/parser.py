"""Recording filename parser.

FreePBX `recordcheck` builds every filename as

    <type>-<target>-<party>-<YYYYMMDD>-<HHMMSS>-<uniqueid>.<ext>

Field   Meaning
type    external | in | out | q | internal | parked | conf
target  DID (in), queue number (q), dialled number (out), extension (external/internal)
party   the local extension, or the outside CID when there is no local user
uniqueid  epoch.sequence of the *recorded channel*

The timestamp is PBX-local time stamped at call setup. Both the date and the time are
kept exactly as written; no timezone conversion is attempted.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime

KNOWN_TYPES = {"external", "in", "out", "q", "internal", "parked", "conf"}

# type-target-party-YYYYMMDD-HHMMSS-uniqueid.ext
# target and party may themselves contain no hyphen in FreePBX output, but be tolerant:
# anchor on the date/time/uniqueid tail and split the head on the first two hyphens.
_TAIL = re.compile(
    r"^(?P<head>.+?)-(?P<date>\d{8})-(?P<time>\d{6})-(?P<uid>\d+\.\d+)(?:\.[A-Za-z0-9]+)?$"
)


@dataclass(frozen=True)
class ParsedName:
    rec_type: str
    target: str
    party: str
    rec_ts: str  # ISO 8601 without tz, e.g. 2026-08-20T09:29:03
    uniqueid: str
    parsed: bool


def parse_filename(name: str) -> ParsedName | None:
    """Return the parsed fields, or None when the name does not follow the schema."""
    m = _TAIL.match(name)
    if not m:
        return None
    head = m.group("head")
    parts = head.split("-", 2)
    if len(parts) != 3:
        return None
    rec_type, target, party = parts
    rec_type = rec_type.lower()
    if rec_type not in KNOWN_TYPES:
        return None
    try:
        ts = datetime.strptime(m.group("date") + m.group("time"), "%Y%m%d%H%M%S")
    except ValueError:
        return None
    return ParsedName(
        rec_type=rec_type,
        target=target,
        party=party,
        rec_ts=ts.strftime("%Y-%m-%dT%H:%M:%S"),
        uniqueid=m.group("uid"),
        parsed=True,
    )


def fallback_from_mtime(mtime: float) -> ParsedName:
    """For files that do not follow the schema: keep them, dated by modification time."""
    ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%dT%H:%M:%S")
    return ParsedName(rec_type="unknown", target="", party="", rec_ts=ts, uniqueid="", parsed=False)
