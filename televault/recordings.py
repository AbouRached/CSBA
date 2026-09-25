"""Browse, stream, download and zip recordings — read-only by construction.

There is no DELETE, PUT or PATCH here. Files are addressed by index id only and the
resolved path is re-checked against the customer root before it is opened.
"""
from __future__ import annotations

import os
import re
import sqlite3
import tempfile
import zipfile
from pathlib import Path
from typing import Iterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from . import audit
from .config import Config
from .deps import active_user, client_ip, get_cfg, get_conn
from .indexer import drive_state, root_online
from .scope import Principal, effective_customer_id, scope_sql

router = APIRouter(prefix="/api/recordings", tags=["recordings"])

MIME = {".wav": "audio/wav", ".mp3": "audio/mpeg", ".ogg": "audio/ogg", ".gsm": "audio/x-gsm"}
CHUNK = 256 * 1024
_DIGITS = re.compile(r"^[0-9*#+]{1,32}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


# ---------------------------------------------------------------- filters

class Filters(BaseModel):
    customer_id: int | None = None
    date_from: str | None = None
    date_to: str | None = None
    rec_type: str | None = None
    ext: str | None = None       # matches party, or target for internal
    number: str | None = None    # substring of target or party
    q: str | None = None         # substring of filename
    include_empty: bool = False


def _filter_sql(f: Filters) -> tuple[str, list]:
    clauses: list[str] = []
    params: list = []
    if f.date_from:
        if not _DATE.match(f.date_from):
            raise HTTPException(400, "date_from must be YYYY-MM-DD")
        clauses.append("r.rec_ts >= ?")
        params.append(f.date_from + "T00:00:00")
    if f.date_to:
        if not _DATE.match(f.date_to):
            raise HTTPException(400, "date_to must be YYYY-MM-DD")
        clauses.append("r.rec_ts <= ?")
        params.append(f.date_to + "T23:59:59")
    if f.rec_type:
        if not re.match(r"^[a-z]{1,10}$", f.rec_type):
            raise HTTPException(400, "bad type")
        clauses.append("r.rec_type = ?")
        params.append(f.rec_type)
    if f.ext:
        if not _DIGITS.match(f.ext):
            raise HTTPException(400, "bad extension")
        clauses.append("(r.party = ? OR (r.rec_type IN ('external','exten','internal') AND r.target = ?))")
        params.extend([f.ext, f.ext])
    if f.number:
        n = f.number.strip()
        if not _DIGITS.match(n):
            raise HTTPException(400, "bad number")
        clauses.append("(r.target LIKE ? OR r.party LIKE ?)")
        params.extend([f"%{n}%", f"%{n}%"])
    if f.q:
        s = f.q.strip()[:64].replace("%", "").replace("_", "")
        if s:
            clauses.append("r.filename LIKE ?")
            params.append(f"%{s}%")
    if not f.include_empty:
        clauses.append("r.empty = 0")
    return (" AND ".join(clauses) if clauses else "1"), params


def _where(conn: sqlite3.Connection, p: Principal, f: Filters) -> tuple[str, list]:
    cid = effective_customer_id(p, f.customer_id)
    s_sql, s_params = scope_sql(conn, p, cid)
    f_sql, f_params = _filter_sql(f)
    return f"{s_sql} AND {f_sql}", s_params + f_params


def _row_json(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "customer_id": r["customer_id"],
        "filename": r["filename"],
        "type": r["rec_type"],
        "target": r["target"],
        "party": r["party"],
        "ts": r["rec_ts"],
        "size": r["size"],
        "empty": bool(r["empty"]),
        "path": r["rel_path"],
    }


# ---------------------------------------------------------------- list

@router.get("")
def list_recordings(
    request: Request,
    customer_id: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    rec_type: str | None = Query(None, alias="type"),
    ext: str | None = None,
    number: str | None = None,
    q: str | None = None,
    include_empty: bool = False,
    page: int = Query(1, ge=1, le=100000),
    p: Principal = Depends(active_user),
    conn: sqlite3.Connection = Depends(get_conn),
    cfg: Config = Depends(get_cfg),
):
    f = Filters(customer_id=customer_id, date_from=date_from, date_to=date_to, rec_type=rec_type,
                ext=ext, number=number, q=q, include_empty=include_empty)
    where, params = _where(conn, p, f)
    total = conn.execute(f"SELECT COUNT(*), COALESCE(SUM(r.size),0) FROM recordings r WHERE {where}", params).fetchone()
    rows = conn.execute(
        f"SELECT * FROM recordings r WHERE {where} ORDER BY r.rec_ts DESC, r.id DESC LIMIT ? OFFSET ?",
        params + [cfg.page_size, (page - 1) * cfg.page_size],
    ).fetchall()
    return {
        "total": total[0],
        "total_bytes": total[1],
        "page": page,
        "page_size": cfg.page_size,
        "items": [_row_json(r) for r in rows],
    }


@router.get("/summary")
def summary(
    customer_id: int | None = None,
    p: Principal = Depends(active_user),
    conn: sqlite3.Connection = Depends(get_conn),
):
    """Counts per type and date range — powers the dashboard strip."""
    f = Filters(customer_id=customer_id, include_empty=True)
    where, params = _where(conn, p, f)
    by_type = conn.execute(
        f"SELECT r.rec_type, COUNT(*) n, SUM(r.empty) e FROM recordings r WHERE {where} GROUP BY r.rec_type",
        params,
    ).fetchall()
    rng = conn.execute(
        f"SELECT MIN(r.rec_ts), MAX(r.rec_ts), COUNT(*), COALESCE(SUM(r.size),0) FROM recordings r WHERE {where}",
        params,
    ).fetchone()
    cid = effective_customer_id(p, customer_id)
    drive = None
    if cid is not None:
        c = conn.execute("SELECT root_path, volume_serial FROM customers WHERE id = ?", (cid,)).fetchone()
        if c:
            state = drive_state(c["root_path"], c["volume_serial"])
            drive = {"root": c["root_path"], "online": state == "online", "state": state}
    last = None
    if cid is not None:
        lr = conn.execute(
            "SELECT started_at, finished_at, status, files_seen FROM index_runs WHERE customer_id = ? ORDER BY id DESC LIMIT 1",
            (cid,),
        ).fetchone()
        last = dict(lr) if lr else None
    return {
        "by_type": [{"type": r["rec_type"], "count": r["n"], "empty": r["e"] or 0} for r in by_type],
        "first": rng[0], "last": rng[1], "count": rng[2], "bytes": rng[3],
        "drive": drive, "last_index": last,
    }


# ---------------------------------------------------------------- file access

def _resolve(conn: sqlite3.Connection, p: Principal, rec_id: int) -> tuple[sqlite3.Row, Path]:
    s_sql, s_params = scope_sql(conn, p, None if p.is_superadmin else p.customer_id)
    row = conn.execute(
        f"SELECT r.*, c.root_path, c.volume_serial FROM recordings r JOIN customers c ON c.id = r.customer_id "
        f"WHERE r.id = ? AND {s_sql}",
        [rec_id] + s_params,
    ).fetchone()
    if row is None:
        raise HTTPException(404, "Recording not found.")
    root = Path(row["root_path"]).resolve()
    state = drive_state(str(root), row["volume_serial"])
    if state == "offline":
        raise HTTPException(503, "The storage drive for this customer is currently offline.")
    if state == "wrong_drive":
        # another disk is at this drive letter: never serve it as this customer's recording
        raise HTTPException(503, "The storage drive for this customer is not available. Please contact support.")
    full = (root / row["rel_path"]).resolve()
    # belt and braces: the resolved path must stay inside the customer root
    try:
        full.relative_to(root)
    except ValueError:
        raise HTTPException(404, "Recording not found.")
    if not full.is_file():
        raise HTTPException(404, "File is missing from the drive.")
    return row, full


def _iter_file(path: Path, start: int, end: int) -> Iterator[bytes]:
    with path.open("rb") as fh:
        fh.seek(start)
        remaining = end - start + 1
        while remaining > 0:
            chunk = fh.read(min(CHUNK, remaining))
            if not chunk:
                break
            remaining -= len(chunk)
            yield chunk


def _serve(request: Request, path: Path, filename: str, attachment: bool) -> StreamingResponse:
    size = path.stat().st_size
    mime = MIME.get(path.suffix.lower(), "application/octet-stream")
    headers = {
        "Accept-Ranges": "bytes",
        "Cache-Control": "private, no-store",
        "Content-Disposition": f'{"attachment" if attachment else "inline"}; filename="{filename}"',
    }
    rng = request.headers.get("range")
    start, end, status = 0, size - 1, 200
    if rng and rng.startswith("bytes=") and not attachment:
        m = re.match(r"bytes=(\d*)-(\d*)$", rng)
        if m:
            a, b = m.group(1), m.group(2)
            if a:
                start = int(a)
                end = int(b) if b else size - 1
            elif b:
                start = max(0, size - int(b))
            if start > end or start >= size:
                raise HTTPException(416, "Range not satisfiable", headers={"Content-Range": f"bytes */{size}"})
            end = min(end, size - 1)
            status = 206
            headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    headers["Content-Length"] = str(end - start + 1)
    if size == 0:
        return StreamingResponse(iter(()), status_code=200, media_type=mime, headers=headers)
    return StreamingResponse(_iter_file(path, start, end), status_code=status, media_type=mime, headers=headers)


@router.get("/{rec_id}/stream")
def stream(
    rec_id: int, request: Request,
    p: Principal = Depends(active_user), conn: sqlite3.Connection = Depends(get_conn),
):
    row, path = _resolve(conn, p, rec_id)
    # Browsers open a stream with "Range: bytes=0-" and then seek with later ranges.
    # Log the opening request only, so one play = one audit row.
    rng = request.headers.get("range", "")
    if not rng or rng.startswith("bytes=0-"):
        audit.log(conn, "recording.play", user_id=p.user_id, username=p.username,
                  customer_id=row["customer_id"], ip=client_ip(request), detail=row["rel_path"])
    return _serve(request, path, row["filename"], attachment=False)


@router.get("/{rec_id}/download")
def download(
    rec_id: int, request: Request,
    p: Principal = Depends(active_user), conn: sqlite3.Connection = Depends(get_conn),
):
    row, path = _resolve(conn, p, rec_id)
    audit.log(conn, "recording.download", user_id=p.user_id, username=p.username,
              customer_id=row["customer_id"], ip=client_ip(request), detail=row["rel_path"])
    return _serve(request, path, row["filename"], attachment=True)


# ---------------------------------------------------------------- zip

class ZipIn(BaseModel):
    ids: list[int] | None = Field(default=None, max_length=5000)
    filters: Filters | None = None


@router.post("/zip")
def zip_download(
    body: ZipIn, request: Request,
    p: Principal = Depends(active_user), conn: sqlite3.Connection = Depends(get_conn),
    cfg: Config = Depends(get_cfg),
):
    if body.ids:
        s_sql, s_params = scope_sql(conn, p, None if p.is_superadmin else p.customer_id)
        q = ",".join("?" * len(body.ids))
        rows = conn.execute(
            f"SELECT r.*, c.root_path, c.volume_serial FROM recordings r JOIN customers c ON c.id = r.customer_id "
            f"WHERE r.id IN ({q}) AND {s_sql} ORDER BY r.rec_ts",
            body.ids + s_params,
        ).fetchall()
    elif body.filters:
        where, params = _where(conn, p, body.filters)
        rows = conn.execute(
            f"SELECT r.*, c.root_path, c.volume_serial FROM recordings r JOIN customers c ON c.id = r.customer_id "
            f"WHERE {where} ORDER BY r.rec_ts LIMIT ?",
            params + [cfg.zip_max_files + 1],
        ).fetchall()
    else:
        raise HTTPException(400, "Provide ids or filters.")

    if not rows:
        raise HTTPException(404, "Nothing matched.")
    if len(rows) > cfg.zip_max_files:
        raise HTTPException(413, f"Too many files for one zip ({len(rows)} > {cfg.zip_max_files}). Narrow the filter.")
    total = sum(r["size"] for r in rows)
    if total > cfg.zip_max_bytes:
        raise HTTPException(413, f"Selection is {total/1e9:.1f} GB; the limit is {cfg.zip_max_bytes/1e9:.1f} GB.")

    roots = {r["customer_id"]: Path(r["root_path"]).resolve() for r in rows}
    serials = {r["customer_id"]: r["volume_serial"] for r in rows}
    for cid, root in roots.items():
        if drive_state(str(root), serials[cid]) != "online":
            raise HTTPException(503, "A required storage drive is not available.")

    tmp = tempfile.NamedTemporaryFile(prefix="tv-", suffix=".zip", dir=cfg.tmp_dir, delete=False)
    tmp_path = Path(tmp.name)
    tmp.close()
    missing = 0
    try:
        with zipfile.ZipFile(tmp_path, "w", compression=zipfile.ZIP_STORED, allowZip64=True) as zf:
            for r in rows:
                root = roots[r["customer_id"]]
                full = (root / r["rel_path"]).resolve()
                try:
                    full.relative_to(root)
                except ValueError:
                    continue
                if not full.is_file():
                    missing += 1
                    continue
                arc = r["rec_ts"][:10] + "/" + r["filename"]
                zf.write(full, arcname=arc)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise

    audit.log(conn, "recording.zip", user_id=p.user_id, username=p.username,
              customer_id=next(iter(roots)), ip=client_ip(request),
              detail=f"files={len(rows)-missing} bytes={total} missing={missing}")

    def _stream() -> Iterator[bytes]:
        try:
            with tmp_path.open("rb") as fh:
                while True:
                    chunk = fh.read(CHUNK)
                    if not chunk:
                        break
                    yield chunk
        finally:
            tmp_path.unlink(missing_ok=True)

    name = f"televault-{rows[0]['rec_ts'][:10]}_{rows[-1]['rec_ts'][:10]}.zip"
    return StreamingResponse(
        _stream(), media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}"',
                 "Content-Length": str(tmp_path.stat().st_size),
                 "Cache-Control": "private, no-store"},
    )
