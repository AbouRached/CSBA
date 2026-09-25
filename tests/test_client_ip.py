"""client_ip(): CF-Connecting-IP is trusted only when enabled and the peer is loopback."""
from __future__ import annotations

from types import SimpleNamespace

from televault.deps import client_ip


def _req(peer: str, headers: dict, trust: bool):
    app = SimpleNamespace(state=SimpleNamespace(cfg=SimpleNamespace(trust_cloudflare_header=trust)))
    return SimpleNamespace(client=SimpleNamespace(host=peer), headers=headers, app=app)


def test_cf_header_used_from_loopback_when_enabled():
    assert client_ip(_req("127.0.0.1", {"cf-connecting-ip": "203.0.113.7"}, True)) == "203.0.113.7"
    assert client_ip(_req("::1", {"cf-connecting-ip": "203.0.113.7"}, True)) == "203.0.113.7"


def test_cf_header_ignored_from_lan_peer():
    assert client_ip(_req("10.50.100.9", {"cf-connecting-ip": "1.2.3.4"}, True)) == "10.50.100.9"


def test_cf_header_ignored_when_disabled():
    assert client_ip(_req("127.0.0.1", {"cf-connecting-ip": "1.2.3.4"}, False)) == "127.0.0.1"


def test_missing_header_falls_back_to_peer():
    assert client_ip(_req("127.0.0.1", {}, True)) == "127.0.0.1"
