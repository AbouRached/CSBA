"""Test fixtures: a throwaway config, two customers on temp 'drives', users of every role."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from televault.config import Config, load_config, DEFAULTS
from televault.db import Database
from televault.indexer import index_all
from televault.main import create_app
from televault.security import hash_password

WAV_HEADER = b"RIFF" + (36).to_bytes(4, "little") + b"WAVEfmt " + (16).to_bytes(4, "little") + \
    (1).to_bytes(2, "little") + (1).to_bytes(2, "little") + (8000).to_bytes(4, "little") + \
    (16000).to_bytes(4, "little") + (2).to_bytes(2, "little") + (16).to_bytes(2, "little") + \
    b"data" + (0).to_bytes(4, "little")
assert len(WAV_HEADER) == 44


def make_wav(path: Path, samples: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    body = bytes(samples * 2)
    hdr = bytearray(WAV_HEADER)
    hdr[4:8] = (36 + len(body)).to_bytes(4, "little")
    hdr[40:44] = len(body).to_bytes(4, "little")
    path.write_bytes(bytes(hdr) + body)


FILES_A = [
    ("2026/08/20/in-3282-27972203-20260820-092903-1787207343.370894.wav", 4000),
    ("2026/08/20/out-3281883752-436-20260820-115255-1787215975.372897.wav", 4000),
    ("2026/08/20/q-131-01644655-20260820-082243-1787203363.370306.wav", 4000),
    ("2026/08/20/q-126-437-20260820-102616-1787210776.371575.wav", 4000),
    ("2026/08/20/external-851-01263358-20260820-105325-1787212405.371995.wav", 4000),
    ("2026/08/20/internal-548-525-20260820-093910-1787207950.370959.wav", 4000),
    ("2026/08/20/external-884-70072421-20260820-092444-1787207084.370825.wav", 0),   # empty
    ("2026/08/19/external-436-70000001-20260819-090000-1787100000.100000.wav", 4000),
    ("loose/notes.wav", 100),  # unparseable name
]
FILES_B = [
    ("2026/09/01/in-9999-11111111-20260901-100000-1790000000.1.wav", 4000),
    ("2026/09/01/external-436-22222222-20260901-100100-1790000060.2.wav", 4000),  # same ext number as A
]


@pytest.fixture()
def env(tmp_path: Path):
    data = tmp_path / "data"
    drive_a = tmp_path / "driveA"
    drive_b = tmp_path / "driveB"
    for rel, n in FILES_A:
        make_wav(drive_a / rel, n)
    for rel, n in FILES_B:
        make_wav(drive_b / rel, n)

    raw = dict(DEFAULTS)
    raw.update({"data_dir": str(data), "tls_cert": str(data / "c.pem"), "tls_key": str(data / "k.pem"),
                "zip_max_files": 5, "login_max_failures": 3, "ip_max_attempts": 50})
    cfg = Config(
        host="127.0.0.1", port=0, data_dir=data, tls_cert=data / "c.pem", tls_key=data / "k.pem",
        session_ttl_hours=1, index_interval_minutes=60, page_size=4, zip_max_files=5,
        zip_max_bytes=10_000_000, login_max_failures=3, login_lock_minutes=15, ip_max_attempts=50,
        ip_window_minutes=10, min_password_length=12, audio_extensions=[".wav"], empty_file_bytes=44,
        hide_empty_by_default=True, staff_networks=["10.50.0.0/16"], audit_to_eventlog=False,
    )
    data.mkdir(); (data / "tmp").mkdir()
    db = Database(cfg.db_path)
    with db.conn() as c:
        c.execute("INSERT INTO customers(id, slug, name, root_path) VALUES (1,'alpha','Alpha',?)", (str(drive_a),))
        c.execute("INSERT INTO customers(id, slug, name, root_path) VALUES (2,'beta','Beta',?)", (str(drive_b),))
        c.execute("INSERT INTO customers(id, slug, name, root_path) VALUES (3,'gone','Gone',?)", (str(tmp_path / "nope"),))
        c.execute("INSERT INTO departments(id, customer_id, name, extensions_json, queues_json, dids_json) "
                  "VALUES (10, 1, 'Support', ?, ?, ?)", (json.dumps(["436", "548"]), json.dumps(["126"]), json.dumps([])))
        c.execute("INSERT INTO departments(id, customer_id, name, extensions_json, queues_json, dids_json) "
                  "VALUES (11, 1, 'Reception', ?, ?, ?)", (json.dumps([]), json.dumps([]), json.dumps(["3282"])))
        pw = hash_password("Correct-Horse-Battery-9")
        c.execute("INSERT INTO users(id, customer_id, username, password_hash, role, must_change_password) "
                  "VALUES (100, NULL, 'root', ?, 'superadmin', 0)", (pw,))
        c.execute("INSERT INTO users(id, customer_id, username, password_hash, role, must_change_password) "
                  "VALUES (101, 1, 'alpha_admin', ?, 'customer_admin', 0)", (pw,))
        c.execute("INSERT INTO users(id, customer_id, username, password_hash, role, must_change_password) "
                  "VALUES (102, 1, 'alpha_support', ?, 'department', 0)", (pw,))
        c.execute("INSERT INTO user_departments VALUES (102, 10)")
        c.execute("INSERT INTO users(id, customer_id, username, password_hash, role, must_change_password) "
                  "VALUES (103, 2, 'beta_admin', ?, 'customer_admin', 0)", (pw,))
        c.execute("INSERT INTO users(id, customer_id, username, password_hash, role, must_change_password) "
                  "VALUES (104, 1, 'fresh', ?, 'department', 1)", (pw,))
        c.execute("INSERT INTO user_departments VALUES (104, 11)")
    index_all(db, cfg)
    app = create_app(cfg, start_indexer=False)
    # Default client sits on the office LAN; tests build outside/tunnel clients explicitly.
    client = TestClient(app, base_url="https://testserver", client=OFFICE)
    return {"cfg": cfg, "db": db, "client": client, "app": app, "drive_a": drive_a, "drive_b": drive_b}


OFFICE = ("10.50.5.5", 50000)
OUTSIDE = ("203.0.113.9", 50000)


def client_from(app, addr, **kw) -> TestClient:
    return TestClient(app, base_url="https://testserver", client=addr, **kw)


PW = "Correct-Horse-Battery-9"
HDR = {"X-Requested-With": "TeleVault"}


def login_password_only(client: TestClient, username: str, password: str = PW):
    return client.post("/api/auth/login", json={"username": username, "password": password}, headers=HDR)


def mfa_code(client: TestClient, username: str, reset_replay: bool = True) -> str:
    """Current TOTP for a user, read from the test DB. reset_replay lets one test sign the
    same user in several times inside one 30 s step."""
    from televault.mfa import decrypt_secret, totp_now
    app = client.app
    with app.state.db.conn() as c:
        row = c.execute("SELECT id, mfa_secret FROM users WHERE username = ?", (username,)).fetchone()
        if reset_replay:
            c.execute("UPDATE users SET mfa_last_step = 0 WHERE id = ?", (row["id"],))
    return totp_now(decrypt_secret(app.state.cfg, row["mfa_secret"]))


def login(client: TestClient, username: str, password: str = PW):
    """Password + mandatory authenticator step (enrolling on first use)."""
    r = login_password_only(client, username, password)
    if r.status_code != 200:
        return r
    if not r.json()["mfa_enrolled"]:
        assert client.post("/api/auth/mfa/setup", headers=HDR).status_code == 200
    v = client.post("/api/auth/mfa/verify", json={"code": mfa_code(client, username)}, headers=HDR)
    assert v.status_code == 200, v.text
    return r
