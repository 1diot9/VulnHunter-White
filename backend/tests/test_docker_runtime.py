"""Docker Desktop path rewrite and loopback URL helpers."""

from __future__ import annotations

import os

import pytest

from app.services import docker_paths, runtime


@pytest.fixture(autouse=True)
def _reset_runtime(monkeypatch):
    runtime.reset_runtime_cache()
    docker_paths.reset_docker_paths()
    yield
    runtime.reset_runtime_cache()
    docker_paths.reset_docker_paths()


def test_ensure_sandbox_bind_readable(tmp_path):
    work = tmp_path / "vh-sandbox-x"
    work.mkdir(mode=0o700)
    script = work / "run.py"
    script.write_text("print(1)\n", encoding="utf-8")
    script.chmod(0o600)
    docker_paths.ensure_sandbox_bind_readable(work)
    # Windows may report 0o777 after chmod; require others can traverse/read.
    assert work.stat().st_mode & 0o005
    assert script.stat().st_mode & 0o004


def test_to_host_bind_path_noop_on_host(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "host")
    runtime.reset_runtime_cache()
    docker_paths.reset_docker_paths()
    target = tmp_path / "data" / "tmp" / "x"
    target.mkdir(parents=True)
    assert docker_paths.to_host_bind_path(target) == str(target.resolve())


def test_to_host_bind_path_windows_host_data(monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    monkeypatch.setenv("VULNHUNTER_HOST_DATA", r"D:\AI\VulnHunter\data")
    runtime.reset_runtime_cache()
    docker_paths.reset_docker_paths()
    out = docker_paths.to_host_bind_path("/data/tmp/sandbox/abc")
    assert out.replace("/", "\\") == r"D:\AI\VulnHunter\data\tmp\sandbox\abc"


def test_to_host_bind_path_desktop_mnt(monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    monkeypatch.setenv("VULNHUNTER_HOST_DATA", "/run/desktop/mnt/host/d/AI/VulnHunter/data")
    runtime.reset_runtime_cache()
    docker_paths.reset_docker_paths()
    out = docker_paths.to_host_bind_path("/app/data/projects/23/src")
    assert out == "/run/desktop/mnt/host/d/AI/VulnHunter/data/projects/23/src"


def test_to_host_bind_path_linux_host_data(monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    monkeypatch.setenv("VULNHUNTER_HOST_DATA", "/home/user/VulnHunter/data")
    runtime.reset_runtime_cache()
    docker_paths.reset_docker_paths()
    out = docker_paths.to_host_bind_path("/data/tmp/sandbox/abc")
    assert out == "/home/user/VulnHunter/data/tmp/sandbox/abc"


def test_rewrite_loopback_url_docker(monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    assert (
        docker_paths.rewrite_loopback_url("http://127.0.0.1:8080/login")
        == "http://host.docker.internal:8080/login"
    )
    assert (
        docker_paths.rewrite_loopback_url("http://localhost:9000")
        == "http://host.docker.internal:9000"
    )
    assert docker_paths.rewrite_loopback_url("http://10.0.0.8:80") == "http://10.0.0.8:80"


def test_rewrite_loopback_url_host_noop(monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "host")
    runtime.reset_runtime_cache()
    assert docker_paths.rewrite_loopback_url("http://127.0.0.1:8080") == "http://127.0.0.1:8080"


def test_runtime_payload_docker(monkeypatch):
    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    payload = runtime.runtime_payload()
    assert payload["runtime"] == "docker"
    assert payload["docker_lab_build_enabled"] is False
    assert payload["manual_lab_allowed"] is True


def test_assert_lab_without_manual_rejected(monkeypatch):
    from app.dynamic_verify import assert_verify_mode_allowed_for_runtime

    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    with pytest.raises(ValueError, match="人工靶场"):
        assert_verify_mode_allowed_for_runtime("lab", manual_lab=False, manual_lab_prompt="")


def test_assert_lab_with_manual_ok(monkeypatch):
    from app.dynamic_verify import assert_verify_mode_allowed_for_runtime

    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    assert_verify_mode_allowed_for_runtime(
        "lab", manual_lab=True, manual_lab_prompt="http://127.0.0.1:8080"
    )


def test_effective_mode_remaps_lab_without_manual(monkeypatch):
    from types import SimpleNamespace

    from app.dynamic_verify import VERIFY_MODE_HARNESS, effective_project_verify_mode

    monkeypatch.setenv("VULNHUNTER_RUNTIME", "docker")
    runtime.reset_runtime_cache()
    proj = SimpleNamespace(
        dynamic_verify_mode="lab",
        dynamic_verify_enabled=True,
        manual_lab=False,
        manual_lab_prompt="",
    )
    assert effective_project_verify_mode(proj) == VERIFY_MODE_HARNESS
