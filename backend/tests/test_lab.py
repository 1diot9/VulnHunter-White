from __future__ import annotations

import json
import subprocess

from app.services.lab import find_free_port, lab_doc_path, load_env, recreate_lab, remap_ports_if_needed, save_env


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


def _inspect_json(project_id: int, *, running: bool, host_port: int) -> str:
    return json.dumps(
        [
            {
                "Id": "abc123",
                "Name": f"/vulnhunter-{project_id}",
                "Config": {"Image": "demo:old"},
                "State": {"Running": running, "Status": "running" if running else "exited"},
                "NetworkSettings": {
                    "Ports": {
                        "8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host_port)}],
                        "5005/tcp": [{"HostIp": "127.0.0.1", "HostPort": "15005"}],
                    }
                },
            }
        ]
    )


def _completed(command, returncode: int = 0, stdout: str = "", stderr: str = ""):  # noqa: ANN001
    return subprocess.CompletedProcess(command, returncode, stdout=stdout, stderr=stderr)


def test_recreate_lab_reuses_running_container_without_remapping(project, monkeypatch):
    from app.services import lab

    save_env(
        project,
        {
            "accepted": True,
            "runtime": "java",
            "image": "demo:old",
            "container_name": f"vulnhunter-{project}",
            "container_port": 8080,
            "host_port": 9999,
            "jdwp_container_port": 5005,
            "target_url": "http://127.0.0.1:9999/login",
            "status": "exited",
        },
    )
    monkeypatch.setattr(lab, "docker_available", lambda: True)
    monkeypatch.setattr(lab, "find_free_port", lambda *_, **__: (_ for _ in ()).throw(AssertionError("should reuse")))
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):  # noqa: ANN001, ARG001
        calls.append(command)
        if command[:2] == ["docker", "inspect"]:
            return _completed(command, stdout=_inspect_json(project, running=True, host_port=18080))
        if command[:2] == ["docker", "start"]:
            raise AssertionError("running container should not be started")
        return _completed(command, returncode=1, stderr="unexpected")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)

    result = recreate_lab(project)

    saved = load_env(project)
    assert result["ok"] is True
    assert result["via"] == "reuse"
    assert saved["status"] == "running"
    assert saved["host_port"] == 18080
    assert saved["jdwp_host_port"] == 15005
    assert saved["target_url"] == "http://127.0.0.1:18080/login"
    assert not any(call[:2] == ["docker", "start"] for call in calls)
    doc = lab_doc_path(project).read_text(encoding="utf-8")
    assert "# 动态环境搭建" in doc
    assert "http://127.0.0.1:18080/login" in doc
    assert "docker start vulnhunter-" in doc


def test_recreate_lab_starts_stopped_container_and_refreshes_ports(project, monkeypatch):
    from app.services import lab

    save_env(
        project,
        {
            "accepted": True,
            "runtime": "java",
            "image": "demo:old",
            "container_name": f"vulnhunter-{project}",
            "container_port": 8080,
            "host_port": 18080,
            "jdwp_container_port": 5005,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
        },
    )
    monkeypatch.setattr(lab, "docker_available", lambda: True)
    running = {"value": False}
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):  # noqa: ANN001, ARG001
        calls.append(command)
        if command[:2] == ["docker", "inspect"]:
            return _completed(command, stdout=_inspect_json(project, running=running["value"], host_port=18123))
        if command[:2] == ["docker", "start"]:
            running["value"] = True
            return _completed(command, stdout=f"vulnhunter-{project}\n")
        return _completed(command, returncode=1, stderr="unexpected")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)

    result = recreate_lab(project)

    saved = load_env(project)
    assert result["ok"] is True
    assert result["via"] == "start"
    assert saved["status"] == "running"
    assert saved["host_port"] == 18123
    assert saved["target_url"] == "http://127.0.0.1:18123"
    assert any(call[:2] == ["docker", "start"] for call in calls)
    assert lab_doc_path(project).is_file()


def test_recreate_lab_reports_start_failure_for_existing_container(project, monkeypatch):
    from app.services import lab

    save_env(
        project,
        {
            "accepted": True,
            "runtime": "java",
            "image": "demo:old",
            "container_name": f"vulnhunter-{project}",
            "container_port": 8080,
            "host_port": 18080,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
        },
    )
    monkeypatch.setattr(lab, "docker_available", lambda: True)

    def fake_run(command, **kwargs):  # noqa: ANN001, ARG001
        if command[:2] == ["docker", "inspect"]:
            return _completed(command, stdout=_inspect_json(project, running=False, host_port=18080))
        if command[:2] == ["docker", "start"]:
            return _completed(command, returncode=1, stderr="port is already allocated")
        return _completed(command, returncode=1, stderr="unexpected")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)

    result = recreate_lab(project)

    saved = load_env(project)
    assert result["ok"] is False
    assert "port is already allocated" in result["error"]
    assert saved["status"] == "exited"
    assert not lab_doc_path(project).exists()
