"""TeleVault application factory.

Serves the API and the static single-page UI over HTTPS. Read-only toward the drives.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import access, admin, audit, auth, mfa, recordings
from .config import APP_NAME, Config, load_config
from .db import Database
from .indexer import IndexerThread
from .mcp_server import create_mcp_app
from .security import IpLimiter, csrf_ok

log = logging.getLogger("televault")
STATIC_DIR = Path(__file__).resolve().parent / "static"

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "media-src 'self'; connect-src 'self'; font-src 'self'; frame-ancestors 'none'; "
        "form-action 'self'; base-uri 'none'; object-src 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


def create_app(cfg: Config | None = None, start_indexer: bool = True) -> FastAPI:
    cfg = cfg or load_config()
    audit.configure(cfg.audit_to_eventlog)
    db = Database(cfg.db_path)
    with db.conn() as c:
        access.seed_from_config(c, cfg)
    indexer = IndexerThread(db, cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if start_indexer:
            indexer.start()
        log.info("%s started; data at %s", APP_NAME, cfg.data_dir)
        yield
        indexer.stop()

    app = FastAPI(title=APP_NAME, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.cfg = cfg
    app.state.db = db
    app.state.indexer = indexer
    app.state.ip_limiter = IpLimiter(cfg.ip_max_attempts, cfg.ip_window_minutes * 60)
    # Local MCP endpoint (served on its own 127.0.0.1 listener by run(); see mcp_server.py)
    app.state.mcp_app = create_mcp_app(cfg, db, indexer)

    @app.middleware("http")
    async def hardening(request: Request, call_next):
        if request.url.path.startswith("/api/") and not csrf_ok(request.method, request.headers):
            return JSONResponse({"detail": "Missing request header."}, status_code=403)
        try:
            response = await call_next(request)
        except Exception:  # noqa: BLE001
            rid = uuid.uuid4().hex[:12]
            log.exception("unhandled error rid=%s path=%s", rid, request.url.path)
            response = JSONResponse({"detail": f"Internal error (ref {rid})."}, status_code=500)
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if request.url.path.startswith("/static/"):
            # Never let Cloudflare (a shared cache) hold the UI: after a deploy it kept serving
            # the old app.js for hours. Browsers revalidate with the ETag (cheap 304).
            response.headers["Cache-Control"] = "private, no-cache"
        return response

    @app.exception_handler(HTTPException)
    async def http_exc(request: Request, exc: HTTPException):
        return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)

    app.include_router(auth.router)
    app.include_router(mfa.router)
    app.include_router(recordings.router)
    app.include_router(admin.router)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"ok": True, "app": APP_NAME}

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-store"})

    return app


def run() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = load_config()
    if not (cfg.tls_cert.exists() and cfg.tls_key.exists()):
        raise SystemExit(
            f"TLS certificate not found ({cfg.tls_cert}). Run:  py -3.12 -m televault.cli make-cert"
        )
    app = create_app(cfg)
    common = dict(proxy_headers=False, server_header=False, date_header=False, access_log=False)
    web = uvicorn.Server(uvicorn.Config(app, host=cfg.host, port=cfg.port, ssl_certfile=str(cfg.tls_cert),
                                       ssl_keyfile=str(cfg.tls_key), **common))
    servers = [web]
    if cfg.mcp_port:
        # Always loopback, plain HTTP: reachable only from this PC, never via the tunnel or LAN.
        mcp = uvicorn.Server(uvicorn.Config(app.state.mcp_app, host="127.0.0.1", port=cfg.mcp_port,
                                            lifespan="off", **common))
        mcp.install_signal_handlers = lambda: None  # the web server owns Ctrl+C handling
        servers.append(mcp)
        log.info("MCP endpoint on http://127.0.0.1:%d/mcp", cfg.mcp_port)

    async def serve_all():
        await asyncio.gather(*(s.serve() for s in servers))

    asyncio.run(serve_all())


if __name__ == "__main__":
    run()
