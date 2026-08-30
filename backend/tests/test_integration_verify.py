"""Tests for loopback URL validation and integration helpers."""

from __future__ import annotations

from app.services.integration_sandbox import build_integration_script
from app.services.loopback_url import is_loopback_url, loopback_url_error


def test_is_loopback_url():
    assert is_loopback_url("http://127.0.0.1:8899")
    assert is_loopback_url("http://localhost:8080/path")
    assert not is_loopback_url("http://192.168.1.1:80")
    assert not is_loopback_url("ftp://127.0.0.1/")


def test_loopback_url_error():
    assert loopback_url_error("http://127.0.0.1:1") is None
    assert "loopback" in (loopback_url_error("http://example.com") or "")


def test_build_integration_script_contains_poc():
    script = build_integration_script(
        setup_commands=["npm ci"],
        start_command="node server.js -p $PORT",
    )
    assert "npm ci" in script
    assert "node server.js -p $PORT" in script
    assert 'python3 "/vuln/poc.py"' in script
