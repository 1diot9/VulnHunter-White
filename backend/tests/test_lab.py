from __future__ import annotations

import json
import subprocess

from app.services.lab import (
    LAB_REBUILD_MAX,
    clear_lab_retry_flags,
    find_free_port,
    finish_manual_lab,
    invalidate_lab_for_rebuild,
    lab_bring_up_failed,
    lab_compose_project,
    lab_container_name,
    lab_doc_path,
    lab_had_docker_lab,
    lab_image_name,
    lab_name_prefixes,
    lab_naming,
    lab_ready,
    lab_rebuild_count,
    lab_rebuild_requested,
    lab_round_complete,
    lab_setup_failed,
    lab_setup_finished,
    load_env,
    mark_lab_bring_up_failed,
    mark_lab_setup_finished,
    name_matches_lab_prefix,
    recreate_lab,
    remap_ports_if_needed,
    reset_lab_setup_for_retry,
    save_env,
    sync_manual_lab_notes,
)


def test_find_free_port():
    p = find_free_port(start=19000, end=19100)
    assert 19000 <= p < 19100


def test_lab_resource_names_fallback_without_project_name():
    assert lab_compose_project(7, project_name="") == "vulnhunter-7"
    assert lab_container_name(7, project_name="") == "vulnhunter-7"
    assert lab_container_name(7, "mysql", project_name="") == "vulnhunter-7-mysql"
    assert lab_container_name(7, " XXL_Job ", project_name="") == "vulnhunter-7-xxl-job"
    assert lab_image_name(7, project_name="") == "vulnhunter-7:lab"
    assert lab_image_name(7, "executor", project_name="") == "vulnhunter-7-executor:lab"
    names = lab_naming(7, project_name="")
    assert names["lab_image"] == "vulnhunter-7:lab"
    assert names["lab_container"] == "vulnhunter-7"
    assert names["lab_compose_project"] == "vulnhunter-7"
    assert "--label vulnhunter=1" in names["lab_label_args"]
    assert "vulnhunter.project=7" in names["lab_label_args"]


def test_lab_resource_names_include_sanitized_project_name():
    assert lab_compose_project(7, project_name="XXL-JOB") == "xxl-job-7"
    assert lab_container_name(7, project_name="XXL-JOB") == "xxl-job-7"
    assert lab_container_name(7, "mysql", project_name="XXL-JOB") == "xxl-job-7-mysql"
    assert lab_container_name(7, " XXL_Job ", project_name="My App / Foo") == "my-app-foo-7-xxl-job"
    assert lab_image_name(7, project_name="XXL-JOB") == "xxl-job-7:lab"
    assert lab_image_name(7, "executor", project_name="XXL-JOB") == "xxl-job-7-executor:lab"
    assert lab_compose_project(7, project_name="若依管理系统") == "vulnhunter-7"
    assert lab_compose_project(7, project_name="若依RuoYi") == "ruoyi-7"
    long_name = "A" * 80
    assert lab_compose_project(7, project_name=long_name) == f"{'a' * 48}-7"
    names = lab_naming(7, project_name="My App")
    assert names["lab_image"] == "my-app-7:lab"
    assert names["lab_container"] == "my-app-7"
    assert names["lab_compose_project"] == "my-app-7"


def test_lab_resource_names_lookup_project(project):
    assert lab_compose_project(project) == f"demo-{project}"
    assert lab_container_name(project) == f"demo-{project}"
    assert lab_container_name(project, "mysql") == f"demo-{project}-mysql"
    assert lab_image_name(project) == f"demo-{project}:lab"
    names = lab_naming(project)
    assert names["lab_container"] == f"demo-{project}"
    assert names["lab_compose_project"] == f"demo-{project}"


def test_lab_name_prefix_does_not_match_longer_id():
    assert name_matches_lab_prefix("halo-10", "halo-10")
    assert name_matches_lab_prefix("halo-10-mysql", "halo-10")
    assert not name_matches_lab_prefix("halo-101", "halo-10")
    assert not name_matches_lab_prefix("halo-1", "halo-10")
    prefixes = lab_name_prefixes(7, project_name="demo")
    assert prefixes[0] == "demo-7"
    assert "vulnhunter-7" in prefixes


def test_remap_when_busy(monkeypatch):
    # Force first bind to fail by pretending host_port is occupied via monkeypatch of socket
    import socket

    from app.services import docker_service as ds

    original_bind = socket.socket.bind
    calls = {"n": 0}

    def fake_bind(self, address):  # noqa: ANN001
        calls["n"] += 1
        host, port = address
        if port == 18080:
            raise OSError("busy")
        return original_bind(self, address)

    monkeypatch.setattr(socket.socket, "bind", fake_bind)
    # is_port_in_use also connect-probes; keep connect failing so bind is the signal
    monkeypatch.setattr(ds.docker_service, "allocate_free_ports", lambda n, host="127.0.0.1": [19001][:n])
    monkeypatch.setattr(ds.docker_service, "find_free_port", lambda host="127.0.0.1": 19001)
    monkeypatch.setattr(ds.docker_service, "is_port_in_use", lambda p, host="127.0.0.1": int(p) == 18080)

    env = {
        "host_port": 18080,
        "target_url": "http://127.0.0.1:18080",
        "notes": "",
    }
    out, mapping, changes = remap_ports_if_needed(env)
    assert out["host_port"] == 19001
    assert mapping.get(18080) == 19001
    assert str(out["host_port"]) in out["target_url"]
    assert changes


def _inspect_json(project_id: int, *, running: bool, host_port: int) -> str:
    return json.dumps(
        [
            {
                "Id": "abc123",
                "Name": f"/{lab_container_name(project_id)}",
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
    assert f"docker start {lab_container_name(project)}" in doc


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
            return _completed(command, stdout=f"{lab_container_name(project)}\n")
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


def test_recreate_lab_compose_uses_canonical_project_name(project, monkeypatch):
    from app.services import lab
    from app.services.paths import env_dir

    compose_path = env_dir(project) / "docker-compose.yml"
    compose_path.write_text("services:\n  app:\n    image: demo:old\n", encoding="utf-8")
    save_env(
        project,
        {
            "accepted": True,
            "runtime": "java",
            "image": lab_image_name(project),
            "container_name": lab_container_name(project),
            "container_port": 8080,
            "host_port": 18080,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
        },
    )
    monkeypatch.setattr(lab, "docker_available", lambda: True)
    started = {"compose": False}
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):  # noqa: ANN001, ARG001
        calls.append(command)
        if command[:2] == ["docker", "compose"]:
            started["compose"] = True
            return _completed(command, stdout="started\n")
        if command[:2] == ["docker", "inspect"]:
            if not started["compose"]:
                return _completed(command, returncode=1, stderr="missing")
            return _completed(command, stdout=_inspect_json(project, running=True, host_port=18080))
        return _completed(command, returncode=1, stderr="unexpected")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)

    result = recreate_lab(project)

    compose_calls = [c for c in calls if c[:2] == ["docker", "compose"]]
    assert result["ok"] is True
    assert result["via"] == "compose"
    assert compose_calls
    assert compose_calls[0][2:6] == ["-p", lab_compose_project(project), "-f", str(compose_path)]
    assert compose_calls[0][-2:] == ["up", "-d"]
    assert load_env(project)["container_name"] == lab_container_name(project)


def test_recreate_lab_start_mode_does_not_compose(project, monkeypatch):
    from app.services import lab
    from app.services.paths import env_dir

    compose_path = env_dir(project) / "docker-compose.yml"
    compose_path.write_text("services:\n  app:\n    image: demo:old\n", encoding="utf-8")
    save_env(
        project,
        {
            "accepted": True,
            "runtime": "java",
            "image": lab_image_name(project),
            "container_name": lab_container_name(project),
            "container_port": 8080,
            "host_port": 18080,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
        },
    )
    monkeypatch.setattr(lab, "docker_available", lambda: True)
    calls: list[list[str]] = []

    def fake_run(command, **kwargs):  # noqa: ANN001, ARG001
        calls.append(command)
        if command[:2] == ["docker", "inspect"]:
            return _completed(command, returncode=1, stderr="missing")
        return _completed(command, returncode=1, stderr="unexpected")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)

    result = recreate_lab(project, mode="start")

    assert result["ok"] is False
    assert result["error_class"] == "missing"
    assert result["need_agent"] is True
    assert not any(c[:2] == ["docker", "compose"] for c in calls)


def test_mark_lab_bring_up_failed_clears_target_gate(project):
    save_env(
        project,
        {
            "setup_finished": True,
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
            "container_name": lab_container_name(project),
            "lab_ever_ready": True,
        },
    )
    assert lab_had_docker_lab(project) is True
    env = mark_lab_bring_up_failed(project, reason="start failed", via="test")
    assert env["bring_up_failed"] is True
    assert env["accepted"] is False
    assert "target_url" not in env or not env.get("target_url")
    assert env.get("last_target_url") == "http://127.0.0.1:18080"
    assert lab_bring_up_failed(project) is True
    assert "start failed" in lab_doc_path(project).read_text(encoding="utf-8")
    reset_lab_setup_for_retry(project, "再试")
    assert lab_bring_up_failed(project) is False
    assert lab_setup_finished(project) is False


def test_lab_setup_finished_only_after_mark(project):
    assert lab_setup_finished(project) is False
    save_env(
        project,
        {
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
        },
    )
    assert lab_setup_finished(project) is False
    mark_lab_setup_finished(project, via="test")
    assert lab_setup_finished(project) is True
    assert lab_doc_path(project).is_file()


def test_mark_lab_setup_finished_skipped_writes_doc(project):
    env = mark_lab_setup_finished(project, skipped=True, notes="无 docker", via="test")
    assert env["setup_finished"] is True
    assert env["accepted"] is False
    assert lab_setup_finished(project) is True
    assert lab_setup_failed(project) is True
    assert "无 docker" in lab_doc_path(project).read_text(encoding="utf-8")


def test_reset_lab_setup_for_retry_clears_finished_and_stores_message(project):
    mark_lab_setup_finished(project, skipped=True, notes="环境搭建轮次重试用尽", via="test")
    assert lab_setup_failed(project) is True
    reset_lab_setup_for_retry(project, "优先 compose")
    assert lab_setup_finished(project) is False
    env = load_env(project)
    assert env.get("user_retry_requested") is True
    assert env.get("retry_user_message") == "优先 compose"


def test_invalidate_lab_for_rebuild_clears_ready_and_reopens_setup(project):
    save_env(
        project,
        {
            "setup_finished": True,
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
            "container_name": lab_container_name(project),
            "image": lab_image_name(project),
            "lab_ever_ready": True,
        },
    )
    env = invalidate_lab_for_rebuild(project, "/portal 404，数据库容器已退出")
    assert env["accepted"] is False
    assert env["setup_finished"] is False
    assert env["status"] == "needs_rebuild"
    assert env["lab_state"] == "setup"
    assert env.get("lab_rebuild_requested") is True
    assert env.get("rebuild_requested_by") == "reviewer"
    assert env.get("user_retry_requested") is True
    assert env.get("retry_user_message") == "/portal 404，数据库容器已退出"
    assert env.get("last_target_url") == "http://127.0.0.1:18080"
    assert not env.get("target_url")
    assert env.get("container_name") == lab_container_name(project)
    assert env.get("image") == lab_image_name(project)
    assert env.get("lab_rebuild_count") == 1
    assert lab_rebuild_requested(project) is True
    assert lab_rebuild_count(project) == 1
    assert lab_ready(env) is False
    assert lab_setup_finished(project) is False
    doc = lab_doc_path(project).read_text(encoding="utf-8")
    assert "reviewer-rebuild" in doc or "needs_rebuild" in doc
    assert "/portal 404" in doc or "假就绪" in doc or "reviewer_rebuild" in doc


def test_lab_ready_false_after_rebuild_request_even_if_status_running(project):
    save_env(
        project,
        {
            "setup_finished": True,
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
        },
    )
    invalidate_lab_for_rebuild(project, "业务入口 404")
    env = load_env(project)
    assert lab_ready(env) is False


def test_clear_lab_retry_flags_clears_rebuild_markers(project):
    invalidate_lab_for_rebuild(project, "sidecar 退出")
    assert lab_rebuild_requested(project) is True
    clear_lab_retry_flags(project)
    env = load_env(project)
    assert "lab_rebuild_requested" not in env
    assert "rebuild_requested_by" not in env
    assert "user_retry_requested" not in env
    assert env.get("lab_rebuild_count") == 1


def test_mark_lab_setup_finished_ready_resets_rebuild_count(project):
    invalidate_lab_for_rebuild(project, "假就绪")
    save_env(
        project,
        {
            **load_env(project),
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
        },
    )
    env = mark_lab_setup_finished(project, via="test")
    assert env.get("setup_finished") is True
    assert "lab_rebuild_requested" not in env
    assert "lab_rebuild_count" not in env
    assert lab_rebuild_count(project) == 0
    assert LAB_REBUILD_MAX == 2


def test_lab_round_complete_false_while_rebuild_requested(project):
    save_env(
        project,
        {
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
            "lab_rebuild_requested": True,
            "setup_finished": False,
        },
    )
    assert lab_ready(load_env(project)) is True
    assert lab_round_complete(project) is False
    assert lab_round_complete(project, {"lab_done": True}) is True


def test_lab_setup_failed_false_when_running(project):
    save_env(
        project,
        {
            "setup_finished": True,
            "accepted": True,
            "target_url": "http://127.0.0.1:18080",
            "status": "running",
        },
    )
    assert lab_setup_finished(project) is True
    assert lab_setup_failed(project) is False


def test_finish_manual_lab_skips_docker_and_writes_notes(project):
    env = finish_manual_lab(project, "http://127.0.0.1:8080 admin/admin")
    assert env["lab_kind"] == "manual"
    assert env["status"] == "manual"
    assert env["accepted"] is False
    assert lab_setup_finished(project) is True
    doc = lab_doc_path(project).read_text(encoding="utf-8")
    assert "http://127.0.0.1:8080 admin/admin" in doc
    synced = sync_manual_lab_notes(project, "http://10.0.0.8:9")
    assert synced is not None
    assert "http://10.0.0.8:9" in lab_doc_path(project).read_text(encoding="utf-8")


def test_patch_lab_ports_updates_env_and_target_url(project):
    from app.services.lab import patch_lab_ports

    save_env(
        project,
        {
            "accepted": True,
            "host_port": 18080,
            "target_url": "http://127.0.0.1:18080/app",
            "status": "exited",
            "container_name": f"demo-{project}",
        },
    )
    out = patch_lab_ports(project, host_port=19090)
    assert out["ok"] is True
    assert out["host_port"] == 19090
    saved = load_env(project)
    assert saved["host_port"] == 19090
    assert saved["target_url"] == "http://127.0.0.1:19090/app"


def test_start_lab_starts_stopped_container(project, monkeypatch):
    from app.services import lab
    from app.services.lab import start_lab

    save_env(
        project,
        {
            "accepted": True,
            "runtime": "java",
            "image": "demo:lab",
            "container_name": lab_container_name(project),
            "container_port": 8080,
            "host_port": 18080,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
        },
    )
    monkeypatch.setattr(lab, "docker_available", lambda: True)
    monkeypatch.setattr(
        "app.services.lab_ports.any_host_ports_in_use",
        lambda **_: False,
    )

    inspect_n = {"n": 0}

    def fake_run(command, **kwargs):  # noqa: ANN001, ARG001
        if command[:2] == ["docker", "inspect"]:
            inspect_n["n"] += 1
            running = inspect_n["n"] > 1
            return _completed(
                command,
                stdout=_inspect_json(project, running=running, host_port=18080),
            )
        if command[:2] == ["docker", "start"]:
            return _completed(command)
        return _completed(command, returncode=1, stderr="unexpected")

    monkeypatch.setattr(lab.subprocess, "run", fake_run)
    result = start_lab(project)
    assert result["ok"] is True
    assert result["status"] == "running"
    assert load_env(project)["status"] == "running"


def test_start_lab_recreates_when_ports_busy(project, monkeypatch):
    from app.services import lab
    from app.services.lab import start_lab
    from app.services.paths import env_dir

    ed = env_dir(project)
    compose = ed / "docker-compose.yml"
    compose.write_text(
        'services:\n  app:\n    image: demo:lab\n    ports:\n      - "127.0.0.1:18080:8080"\n',
        encoding="utf-8",
    )
    save_env(
        project,
        {
            "accepted": True,
            "image": "demo:lab",
            "container_name": lab_container_name(project),
            "container_port": 8080,
            "host_port": 18080,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
        },
    )
    monkeypatch.setattr(lab, "docker_available", lambda: True)
    monkeypatch.setattr(
        "app.services.lab_ports.any_host_ports_in_use",
        lambda **_: True,
    )
    monkeypatch.setattr(
        "app.services.docker_service.docker_service.is_port_in_use",
        lambda p, host="127.0.0.1": int(p) == 18080,
    )
    monkeypatch.setattr(
        "app.services.docker_service.docker_service.allocate_free_ports",
        lambda n, host="127.0.0.1": [28080][:n],
    )
    monkeypatch.setattr(
        "app.services.docker_service.docker_service.find_free_port",
        lambda host="127.0.0.1": 28080,
    )
    monkeypatch.setattr(lab, "_remove_lab_containers", lambda *_a, **_k: None)

    # Existing stopped container → ports busy → recreate path
    def inspect_stopped(candidates):  # noqa: ANN001
        import json

        return (
            candidates[0],
            json.loads(_inspect_json(project, running=False, host_port=18080))[0],
        )

    after_up = {"done": False}

    def inspect_maybe(candidates):  # noqa: ANN001
        if after_up["done"]:
            import json

            return (
                candidates[0],
                json.loads(_inspect_json(project, running=True, host_port=28080))[0],
            )
        return inspect_stopped(candidates)

    def fake_run(command, **kwargs):  # noqa: ANN001, ARG001
        if command[:2] == ["docker", "compose"]:
            after_up["done"] = True
            return _completed(command)
        return _completed(command, returncode=1, stderr="unexpected")

    monkeypatch.setattr(lab, "_inspect_container", inspect_maybe)
    monkeypatch.setattr(lab.subprocess, "run", fake_run)

    result = start_lab(project)
    assert result["ok"] is True
    assert result["ports_remapped"] is True
    assert load_env(project)["host_port"] == 28080
    assert "28080:8080" in compose.read_text(encoding="utf-8")


def test_project_lab_api_requires_lab_mode(project, tmp_env):
    from fastapi.testclient import TestClient
    from app.main import app

    with TestClient(app) as client:
        denied = client.get(f"/api/projects/{project}/lab")
        assert denied.status_code == 400

    models = tmp_env["models"]
    Session = tmp_env["Session"]
    with Session() as db:
        p = db.get(models.Project, project)
        p.dynamic_verify_mode = "lab"
        p.dynamic_verify_enabled = True
        db.commit()

    save_env(
        project,
        {
            "accepted": True,
            "host_port": 18080,
            "target_url": "http://127.0.0.1:18080",
            "status": "exited",
            "container_name": f"demo-{project}",
            "image": "demo:lab",
        },
    )
    with TestClient(app) as client:
        status = client.get(f"/api/projects/{project}/lab")
        assert status.status_code == 200
        body = status.json()
        assert body["has_env"] is True
        assert body["host_port"] == 18080

        patched = client.patch(
            f"/api/projects/{project}/lab",
            json={"host_port": 18181},
        )
        assert patched.status_code == 200
        assert patched.json()["host_port"] == 18181
        assert load_env(project)["host_port"] == 18181
