"""TeleVault configuration.

Everything operational lives in config.json next to the package (or at the path in
TELEVAULT_CONFIG). Nothing here is a secret except the TLS key path.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "TeleVault"
BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULTS = {
    "host": "0.0.0.0",
    "port": 8443,
    "data_dir": "data",
    "tls_cert": "data/cert.pem",
    "tls_key": "data/key.pem",
    "session_ttl_hours": 12,
    "index_interval_minutes": 15,
    "page_size": 50,
    "zip_max_files": 500,
    "zip_max_bytes": 2 * 1024 * 1024 * 1024,
    "login_max_failures": 5,
    "login_lock_minutes": 15,
    "ip_max_attempts": 20,
    "ip_window_minutes": 10,
    "min_password_length": 12,
    "audio_extensions": [".wav", ".mp3", ".gsm", ".ogg"],
    "empty_file_bytes": 44,
    "hide_empty_by_default": True,
    # Set true when cloudflared runs on this PC: CF-Connecting-IP is then honoured,
    # but only on connections from loopback (i.e. from the local tunnel connector).
    "trust_cloudflare_header": False,
    # Superadmin (operator staff) accounts only work from these networks. The local console
    # (loopback, not via the tunnel) always counts as staff network.
    "staff_networks": [],
    # Absolute session caps on top of the idle timeout (session_ttl_hours).
    "session_max_hours": 168,
    "superadmin_session_max_hours": 8,
    # Sensitive admin actions need an authenticator code entered within this many minutes.
    "step_up_minutes": 10,
    "audit_to_eventlog": True,
    # Cloudflare Access (Entra SSO) proof that lets a superadmin work away from the office.
    # Empty access_aud = feature off (staff networks only).
    "access_team_domain": "",
    "access_aud": "",
    # Seeds the Staff access list (admin UI) on first run; after that the list is managed there.
    "staff_emails": [],
    # Local account TeleVault runs as; the Customers page reports its access per folder.
    "service_account": "televault-svc",
    # Local MCP endpoint for troubleshooting/development tools (Claude Code etc.).
    # Always bound to 127.0.0.1; 0 disables it.
    "mcp_port": 8765,
    # Operator name shown in the authenticator app, MCP server title and TLS certificate.
    "vendor_name": "",
}


@dataclass
class Config:
    host: str
    port: int
    data_dir: Path
    tls_cert: Path
    tls_key: Path
    session_ttl_hours: int
    index_interval_minutes: int
    page_size: int
    zip_max_files: int
    zip_max_bytes: int
    login_max_failures: int
    login_lock_minutes: int
    ip_max_attempts: int
    ip_window_minutes: int
    min_password_length: int
    audio_extensions: list[str] = field(default_factory=list)
    empty_file_bytes: int = 44
    hide_empty_by_default: bool = True
    trust_cloudflare_header: bool = False
    staff_networks: list[str] = field(default_factory=list)
    session_max_hours: int = 168
    superadmin_session_max_hours: int = 8
    step_up_minutes: int = 10
    audit_to_eventlog: bool = True
    access_team_domain: str = ""
    access_aud: str = ""
    staff_emails: list[str] = field(default_factory=list)
    service_account: str = "televault-svc"
    mcp_port: int = 8765
    vendor_name: str = ""

    @property
    def db_path(self) -> Path:
        return self.data_dir / "televault.sqlite3"

    @property
    def tmp_dir(self) -> Path:
        return self.data_dir / "tmp"


def config_path() -> Path:
    env = os.environ.get("TELEVAULT_CONFIG")
    return Path(env) if env else BASE_DIR / "config.json"


def load_config() -> Config:
    raw = dict(DEFAULTS)
    p = config_path()
    if p.exists():
        with p.open("r", encoding="utf-8") as fh:
            raw.update(json.load(fh))

    def _p(v: str) -> Path:
        path = Path(v)
        return path if path.is_absolute() else BASE_DIR / path

    cfg = Config(
        host=raw["host"],
        port=int(raw["port"]),
        data_dir=_p(raw["data_dir"]),
        tls_cert=_p(raw["tls_cert"]),
        tls_key=_p(raw["tls_key"]),
        session_ttl_hours=int(raw["session_ttl_hours"]),
        index_interval_minutes=int(raw["index_interval_minutes"]),
        page_size=int(raw["page_size"]),
        zip_max_files=int(raw["zip_max_files"]),
        zip_max_bytes=int(raw["zip_max_bytes"]),
        login_max_failures=int(raw["login_max_failures"]),
        login_lock_minutes=int(raw["login_lock_minutes"]),
        ip_max_attempts=int(raw["ip_max_attempts"]),
        ip_window_minutes=int(raw["ip_window_minutes"]),
        min_password_length=int(raw["min_password_length"]),
        audio_extensions=[e.lower() for e in raw["audio_extensions"]],
        empty_file_bytes=int(raw["empty_file_bytes"]),
        hide_empty_by_default=bool(raw["hide_empty_by_default"]),
        trust_cloudflare_header=bool(raw["trust_cloudflare_header"]),
        staff_networks=[str(n) for n in raw["staff_networks"]],
        session_max_hours=int(raw["session_max_hours"]),
        superadmin_session_max_hours=int(raw["superadmin_session_max_hours"]),
        step_up_minutes=int(raw["step_up_minutes"]),
        audit_to_eventlog=bool(raw["audit_to_eventlog"]),
        access_team_domain=str(raw["access_team_domain"]).strip(),
        access_aud=str(raw["access_aud"]).strip(),
        staff_emails=[str(e).strip().lower() for e in raw["staff_emails"] if str(e).strip()],
        service_account=str(raw["service_account"]).strip(),
        mcp_port=int(raw["mcp_port"]),
        vendor_name=str(raw["vendor_name"]).strip(),
    )
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.tmp_dir.mkdir(parents=True, exist_ok=True)
    return cfg
