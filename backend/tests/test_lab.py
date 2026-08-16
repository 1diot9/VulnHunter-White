from __future__ import annotations

from app.services.lab import find_free_port, remap_ports_if_needed


def test_find_free_port():
    p = find_free_port(start=19000, end=19100)
    assert 19000 <= p < 19100


def test_remap_when_busy(monkeypatch):
    # Force first bind to fail by pretending host_port is occupied via monkeypatch of socket
    import socket

    original_bind = socket.socket.bind
    calls = {"n": 0}

    def fake_bind(self, address):  # noqa: ANN001
        calls["n"] += 1
        host, port = address
        if port == 18080 and calls["n"] == 1:
            raise OSError("busy")
        return original_bind(self, address)

    monkeypatch.setattr(socket.socket, "bind", fake_bind)
    env = {
        "host_port": 18080,
        "target_url": "http://127.0.0.1:18080",
        "notes": "",
    }
    out = remap_ports_if_needed(env)
    assert out["host_port"] != 18080
    assert str(out["host_port"]) in out["target_url"]
