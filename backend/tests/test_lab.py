from __future__ import annotations

from app.services.lab import find_free_port, lab_doc_path, remap_ports_if_needed, write_lab_doc_if_ready
from app.services.phase_reports import reports_by_phase


def _reviewer_report_ids(project_id: int) -> set[str]:
    phase_reports = reports_by_phase(project_id)
    reviewer = next(p for p in phase_reports["phases"] if p["phase"] == "reviewer")
    return {item["id"] for item in reviewer["reports"]}


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



def test_write_lab_doc_if_ready_generates_visible_report(project):
    env = {
        "accepted": True,
        "runtime": "java",
        "image": "demo:latest",
        "container_name": f"vulnhunter-{project}",
        "container_port": 8080,
        "host_port": 18080,
        "jdwp_container_port": 5005,
        "jdwp_host_port": 15005,
        "target_url": "http://127.0.0.1:18080",
        "lab_state": "ready",
        "credentials": {"username": "admin", "password": "admin123"},
        "status": "running",
        "notes": "seeded test data",
    }

    path = write_lab_doc_if_ready(project, env, via="manual")

    assert path == lab_doc_path(project)
    doc = path.read_text(encoding="utf-8")
    assert "# 动态环境搭建" in doc
    assert "http://127.0.0.1:18080" in doc
    assert "docs/lab.md" in _reviewer_report_ids(project)
