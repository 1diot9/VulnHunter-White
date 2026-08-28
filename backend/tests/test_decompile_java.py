"""Tests for ListBytecode / DecompileJava and jadx queue."""

from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services import decompile_java as dj
from app.services.paths import src_dir
from app.tools import ROLE_ACL, ToolContext, registry
from app.tools.sandbox import SandboxError, block_dangerous_shell


def _ctx(project_id: int, role: str = "recon", **kwargs) -> ToolContext:
    return ToolContext(
        project_id=project_id,
        role=role,
        phase=role,
        state=kwargs.pop("state", {}),
        **kwargs,
    )


def _write_class(path: Path, payload: bytes = b"\xca\xfe\xba\xbe") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload + b"\x00" * 32)


def _write_jar(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)


@pytest.fixture(autouse=True)
def _reset_decompile_state(monkeypatch):
    with dj._lock:
        dj._jobs.clear()
        dj._key_to_job.clear()
        dj._project_cancel.clear()
    dj._run_jadx_hook = None
    yield
    with dj._lock:
        dj._jobs.clear()
        dj._key_to_job.clear()
        dj._project_cancel.clear()
    dj._run_jadx_hook = None


def test_acl_includes_decompile_tools(tmp_env):
    for role in ("recon", "worker", "reviewer", "fix"):
        assert "ListBytecode" in ROLE_ACL[role]
        assert "DecompileJava" in ROLE_ACL[role]
    assert "ListBytecode" not in ROLE_ACL["fast_worker"]
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon")}
    assert "ListBytecode" in names
    assert "DecompileJava" in names


def test_list_bytecode_finds_jar_and_skips_target(tmp_env, project):
    src = src_dir(project)
    _write_jar(src / "lib" / "app-core.jar", {"com/demo/A.class": b"\xca\xfe\xba\xbe" + b"\x00" * 8})
    _write_jar(src / "target" / "hidden.jar", {"com/x/Y.class": b"\xca\xfe\xba\xbe" + b"\x00" * 8})
    out = registry.dispatch(_ctx(project), "ListBytecode", {})
    assert out["ok"] is True
    paths = [f["path"] for f in out["files"]]
    assert "src/lib/app-core.jar" in paths
    assert not any("target/" in p for p in paths)


def test_list_bytecode_include_build_dirs_recon_only(tmp_env, project):
    src = src_dir(project)
    _write_jar(src / "target" / "built.jar", {"a/B.class": b"\xca\xfe\xba\xbe" + b"\x00" * 8})
    denied = registry.dispatch(_ctx(project, "worker"), "ListBytecode", {"include_build_dirs": True})
    assert denied["ok"] is False
    ok = registry.dispatch(_ctx(project, "recon"), "ListBytecode", {"include_build_dirs": True})
    assert ok["ok"] is True
    assert any("built.jar" in f["path"] for f in ok["files"])


def test_third_party_rejected_unless_force(tmp_env, project, monkeypatch):
    src = src_dir(project)
    _write_jar(src / "lib" / "spring-core-5.0.jar", {"org/x/Y.class": b"\xca\xfe" + b"\x00" * 16})
    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    out = registry.dispatch(_ctx(project), "DecompileJava", {"path": "src/lib/spring-core-5.0.jar"})
    assert out["ok"] is False
    assert "第三方" in (out.get("error") or "")


def test_jar_size_limit(tmp_env, project, monkeypatch):
    src = src_dir(project)
    big = src / "lib" / "huge-app.jar"
    _write_jar(big, {"com/a/A.class": b"\x00" * 100})
    # inflate size beyond limit without rewriting jar content meaningfully
    monkeypatch.setattr(dj, "_max_jar_bytes", lambda: 10)
    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    out = registry.dispatch(_ctx(project), "DecompileJava", {"path": "src/lib/huge-app.jar"})
    assert out["ok"] is False
    assert "上限" in (out.get("error") or "")


def test_decompile_async_ready_and_index_hit(tmp_env, project, monkeypatch):
    src = src_dir(project)
    jar = src / "lib" / "app.jar"
    _write_jar(jar, {"com/demo/Hello.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "com" / "demo" / "Hello.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class Hello {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "jadx 1.5.0")
    dj._run_jadx_hook = fake_run

    state: dict = {}
    first = registry.dispatch(_ctx(project, state=state), "DecompileJava", {"path": "src/lib/app.jar"})
    assert first["ok"] is True
    assert first["status"] in ("queued", "running", "ready")
    job_id = first["job_id"]
    assert job_id in state.get("decompile_jobs", [])

    deadline = time.time() + 5
    status = first
    while time.time() < deadline:
        status = dj.get_job_status(project, job_id=job_id) or {}
        if status.get("status") == "ready":
            break
        time.sleep(0.05)
    assert status.get("status") == "ready"
    assert status.get("class_count", 0) >= 1
    from app.services.paths import project_root

    out_java = project_root(project) / status["output_root"] / "com" / "demo" / "Hello.java"
    assert out_java.is_file()

    second = registry.dispatch(_ctx(project), "DecompileJava", {"path": "src/lib/app.jar"})
    assert second["status"] == "ready"
    assert second.get("output_root") == status.get("output_root")


def test_shell_blocks_jadx(tmp_env, project):
    with pytest.raises(SandboxError, match="DecompileJava"):
        block_dangerous_shell("jadx -d out app.jar", project)
    with pytest.raises(SandboxError, match="DecompileJava"):
        block_dangerous_shell("C:\\tools\\jadx.bat -d out app.jar", project)


def test_write_blocked_under_decompiled(tmp_env, project):
    out = registry.dispatch(
        _ctx(project),
        "Write",
        {"path": "workspace/decompiled/index.jsonl", "content": "{}\n"},
    )
    assert out["ok"] is False
    assert "禁止" in (out.get("error") or "")


def test_jadx_probe_missing(tmp_env, monkeypatch):
    monkeypatch.setattr("app.services.decompile_java.resolve_jadx_binary", lambda path_override=None: None)
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        r = client.post("/api/settings/jadx/test", json={"jadx_path": "C:/missing/jadx.bat"})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "找不到" in (body.get("error") or "") or "未找到" in (body.get("error") or "")


def test_jadx_probe_success(tmp_env, monkeypatch):
    monkeypatch.setattr(
        "app.services.decompile_java.resolve_jadx_binary",
        lambda path_override=None: "C:/tools/jadx.bat",
    )
    monkeypatch.setattr("app.services.decompile_java.jadx_version_string", lambda _b=None: "1.5.1")
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        r = client.post("/api/settings/jadx/test", json={})
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is True
    assert body["version"] == "1.5.1"
    assert "jadx" in body["path"].lower()


def test_skip_when_java_source_exists(tmp_env, project, monkeypatch):
    src = src_dir(project)
    java = src / "com" / "demo" / "Hello.java"
    java.parent.mkdir(parents=True, exist_ok=True)
    java.write_text("package com.demo;\nclass Hello {}\n", encoding="utf-8")
    _write_class(src / "WEB-INF" / "classes" / "com" / "demo" / "Hello.class")

    def fake_run(cmd, *, timeout, job):
        raise AssertionError("jadx should not run for skipped class")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda path_override=None: "jadx")
    dj._run_jadx_hook = fake_run
    out = registry.dispatch(
        _ctx(project),
        "DecompileJava",
        {"path": "src/WEB-INF/classes/com/demo/Hello.class"},
    )
    # may be queued then skip in worker — wait
    deadline = time.time() + 5
    status = out
    jid = out.get("job_id")
    while time.time() < deadline and jid:
        status = dj.get_job_status(project, job_id=jid) or status
        if status.get("status") in ("skipped", "failed", "ready"):
            break
        time.sleep(0.05)
    assert status.get("status") == "skipped"
