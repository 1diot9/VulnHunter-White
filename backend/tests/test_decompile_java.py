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
    from app.services import decompile_store as decompile_store

    decompile_store.reset_engine()
    dj.reset_decompile_service()
    with dj._lock:
        dj._jobs.clear()
        dj._key_to_job.clear()
        dj._project_cancel.clear()
    dj._bytecode_present_mem.clear()
    dj._run_jadx_hook = None
    yield
    dj.reset_decompile_service()
    decompile_store.reset_engine()
    with dj._lock:
        dj._jobs.clear()
        dj._key_to_job.clear()
        dj._project_cancel.clear()
    dj._bytecode_present_mem.clear()
    dj._run_jadx_hook = None


def test_acl_includes_decompile_tools(tmp_env):
    for role in ("recon", "worker", "reviewer", "fix"):
        assert "ListBytecode" in ROLE_ACL[role]
        assert "DecompileJava" in ROLE_ACL[role]
    assert "MarkBusinessJar" in ROLE_ACL["recon"]
    assert "MarkBusinessJar" not in ROLE_ACL["worker"]
    assert "ListBytecode" not in ROLE_ACL["fast_worker"]
    names = {t["function"]["name"] for t in registry.openai_tools_for_role("recon")}
    assert "ListBytecode" in names
    assert "DecompileJava" in names
    assert "MarkBusinessJar" in names


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


def test_jadx_cli_paths_never_use_extended_prefix(tmp_path):
    from app.services.paths import windows_long_path

    src = tmp_path / "app.jar"
    src.write_bytes(b"x")
    out = tmp_path / "out"
    cmd = dj._jadx_command("jadx", windows_long_path(out), windows_long_path(src))
    assert cmd[0] == "jadx"
    assert cmd[1] == "-d"
    for arg in cmd[1:]:
        assert not str(arg).startswith("\\\\?\\"), arg
    assert Path(cmd[-1]).name == "app.jar"
    assert Path(cmd[2]).name == "out"


def test_decompile_failure_includes_jadx_output(tmp_env, project, monkeypatch):
    src = src_dir(project)
    jar = src / "lib" / "app.jar"
    _write_jar(jar, {"com/demo/Hello.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    seen: list[list[str]] = []

    def fake_run(cmd, *, timeout, job):
        seen.append(list(cmd))
        return SimpleNamespace(returncode=1, stdout="", stderr="ERROR: Load files failed: bad path")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    dj._run_jadx_hook = fake_run

    out = registry.dispatch(_ctx(project), "DecompileJava", {"path": "src/lib/app.jar"})
    jid = out.get("job_id")
    deadline = time.time() + 5
    status = out
    while time.time() < deadline and jid:
        status = dj.get_job_status(project, job_id=jid) or status
        if status.get("status") in ("failed", "ready", "skipped"):
            break
        time.sleep(0.05)
    assert status.get("status") == "failed"
    err = status.get("error") or ""
    assert "退出码 1" in err
    assert "无 .java 产出" in err
    assert "Load files failed" in err
    assert seen
    for arg in seen[0][1:]:
        assert not str(arg).startswith("\\\\?\\")


def test_mark_business_jar_queues_and_ingests(tmp_env, project, monkeypatch):
    from app.models import FileWeight, SessionLocal
    from app.services.paths import project_root
    from app.tools.phase_recon import recon_map_ready

    src = src_dir(project)
    jar = src / "lib" / "app.jar"
    _write_jar(jar, {"com/demo/Hello.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    docs = project_root(project) / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    (docs / "auth.md").write_text("# auth\n", encoding="utf-8")
    assert recon_map_ready(project) is False

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "sources" / "com" / "demo" / "Hello.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class Hello {}\n", encoding="utf-8")
        inner = out_dir / "sources" / "com" / "demo" / "Hello$1.java"
        inner.write_text("class Hello$1 {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    dj._run_jadx_hook = fake_run

    mark = registry.dispatch(
        _ctx(project),
        "MarkBusinessJar",
        {"paths": ["src/lib/app.jar"], "done": True},
    )
    assert mark.get("ok") is True
    assert mark.get("complete") is True
    assert recon_map_ready(project) is True

    deadline = time.time() + 15
    while time.time() < deadline:
        st = dj.get_job_status(project, source="src/lib/app.jar") or {}
        if st.get("status") == "ready":
            break
        time.sleep(0.05)
    assert st.get("status") == "ready"

    ingest = dj.ingest_decompiled_classes(project, "src/lib/app.jar")
    assert ingest.get("ok") is True

    with SessionLocal() as db:
        rows = db.query(FileWeight).filter(FileWeight.project_id == project).all()
    paths = [r.path for r in rows]
    assert any(p.endswith("Hello.java") and p.startswith("workspace/decompiled/") for p in paths)
    assert not any("$" in Path(p).name for p in paths)

    assert ingest.get("added", 0) >= 0

    # DecompileJava alone does not add FileWeight
    jar2 = src / "lib" / "other.jar"
    _write_jar(jar2, {"com/x/Other.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    before = len(paths)
    registry.dispatch(_ctx(project), "DecompileJava", {"path": "src/lib/other.jar", "force": True, "reason": "read"})
    deadline = time.time() + 5
    while time.time() < deadline:
        st2 = dj.get_job_status(project, source="src/lib/other.jar") or {}
        if st2.get("status") == "ready":
            break
        time.sleep(0.05)
    with SessionLocal() as db:
        after = db.query(FileWeight).filter(FileWeight.project_id == project).count()
    assert after == before


def test_business_jar_map_ready_uses_doc_without_walk(tmp_env, project, monkeypatch):
    from app.services.paths import docs_dir

    docs = docs_dir(project)
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "business-jars.md").write_text(
        "---\ncomplete: true\nnone: false\npaths: []\ningested: []\n---\n",
        encoding="utf-8",
    )

    def boom(*_a, **_k):
        raise AssertionError("complete business-jars.md should not walk src/")

    monkeypatch.setattr(dj, "list_bytecode", boom)
    assert dj.business_jar_map_ready(project) is True
    assert dj.business_jar_map_ready(project, scan=False) is True


def test_business_jar_map_ready_list_path_does_not_walk(tmp_env, project, monkeypatch):
    from app.services.paths import docs_dir
    from app.tools.phase_recon import recon_map_ready, recon_subphases

    docs = docs_dir(project)
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    (docs / "auth.md").write_text("# auth\n", encoding="utf-8")
    _write_jar(src_dir(project) / "lib" / "app.jar", {"com/demo/Hello.class": b"\xca\xfe\xba\xbe"})

    def boom(*_a, **_k):
        raise AssertionError("list/recon_subphases should not walk src/")

    monkeypatch.setattr(dj, "list_bytecode", boom)
    assert dj.business_jar_map_ready(project, scan=False) is True
    assert recon_map_ready(project, scan=False) is True
    subs = {s["id"]: s["done"] for s in recon_subphases(project, unmarked=0)}
    assert subs["map"] is True


def test_bytecode_present_caches_scan(tmp_env, project, monkeypatch):
    calls = {"n": 0}
    real = dj.list_bytecode

    def counted(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(dj, "list_bytecode", counted)
    assert dj.bytecode_present(project) is False
    assert dj.bytecode_present(project) is False
    assert calls["n"] == 1


def test_ingest_one_jar_while_another_still_running(tmp_env, project, monkeypatch):
    import threading

    from app.models import FileWeight, SessionLocal
    from app.services.paths import project_root
    from app.tools.phase_recon import recon_gates_status

    src = src_dir(project)
    _write_jar(src / "lib" / "first.jar", {"com/demo/First.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    _write_jar(src / "lib" / "second.jar", {"com/demo/Second.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    docs = project_root(project) / "docs"
    docs.mkdir(parents=True, exist_ok=True)
    (docs / "code-map.md").write_text("# map\n", encoding="utf-8")
    (docs / "auth.md").write_text("# auth\n", encoding="utf-8")

    release_second = threading.Event()

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        name = "Second" if "second.jar" in job.source_rel.replace("\\", "/") else "First"
        if name == "Second":
            if not release_second.wait(timeout=8):
                raise TimeoutError("second jar was not released")
        target = out_dir / "sources" / "com" / "demo" / f"{name}.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"class {name} {{}}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    dj._run_jadx_hook = fake_run

    mark = registry.dispatch(
        _ctx(project),
        "MarkBusinessJar",
        {"paths": ["src/lib/first.jar", "src/lib/second.jar"], "done": True},
    )
    assert mark.get("ok") is True

    deadline = time.time() + 15
    first_ready = False
    while time.time() < deadline:
        st = dj.get_job_status(project, source="src/lib/first.jar") or {}
        if st.get("status") == "ready":
            first_ready = True
            break
        time.sleep(0.05)
    assert first_ready

    ingest = dj.ingest_ready_business_jars(project)
    assert ingest.get("ok") is True
    with SessionLocal() as db:
        paths = [r.path for r in db.query(FileWeight).filter(FileWeight.project_id == project).all()]
    assert any(p.endswith("First.java") and p.startswith("workspace/decompiled/") for p in paths)
    assert not any(p.endswith("Second.java") for p in paths)
    assert dj.business_jar_decompile_pending(project) is True

    with SessionLocal() as db:
        for fw in db.query(FileWeight).filter(FileWeight.project_id == project).all():
            if fw.weight is None and not fw.skipped:
                fw.weight = 50
        db.commit()
    status = recon_gates_status(project)
    assert status["unmarked"] == 0
    assert any("仍在反编译" in e for e in status["errors"])
    assert {s["id"]: s["done"] for s in status["subphases"]}["mark"] is False
    assert dj.business_jar_coverage_pending(project) is True
    assert dj.wait_business_jar_ingest(project).get("ok") is True
    assert dj.business_jar_decompile_pending(project) is True

    release_second.set()
    deadline = time.time() + 15
    second_ready = False
    while time.time() < deadline:
        st = dj.get_job_status(project, source="src/lib/second.jar") or {}
        if st.get("status") == "ready":
            second_ready = True
            break
        time.sleep(0.05)
    assert second_ready
    ingest2 = dj.ingest_ready_business_jars(project)
    assert ingest2.get("ok") is True
    with SessionLocal() as db:
        paths = [r.path for r in db.query(FileWeight).filter(FileWeight.project_id == project).all()]
    assert any(p.endswith("Second.java") and p.startswith("workspace/decompiled/") for p in paths)
    assert dj.business_jar_decompile_pending(project) is False
    assert dj.business_jar_coverage_pending(project) is False


def test_stale_queued_index_requeues_after_process_restart(tmp_env, project, monkeypatch):
    from app.services.paths import project_root

    src = src_dir(project)
    jar = src / "lib" / "app.jar"
    _write_jar(jar, {"com/demo/Hello.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "sources" / "com" / "demo" / "Hello.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class Hello {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    dj._run_jadx_hook = fake_run

    first = dj.submit_decompile(project, "src/lib/app.jar", audit_queue=True)
    job_id = first.get("job_id")
    assert job_id
    index_key = first.get("index_key")
    assert index_key
    deadline = time.time() + 15
    while time.time() < deadline:
        if (dj.get_job_status(project, job_id=job_id) or {}).get("status") == "ready":
            break
        time.sleep(0.05)
    assert (dj.get_job_status(project, job_id=job_id) or {}).get("status") == "ready"

    with dj._lock:
        dj._jobs.clear()
        dj._key_to_job.clear()
    entries = dj._load_index(project)
    entries[index_key]["status"] = "queued"
    entries[index_key]["error"] = ""
    dj._rewrite_index(project, entries)

    stale = dj.get_job_status(project, source="src/lib/app.jar")
    assert stale and stale.get("status") == "queued"
    assert job_id not in dj._jobs

    resumed = dj.resume_orphaned_decompile_jobs(project)
    assert resumed.get("resumed") == 1
    new_id = (resumed.get("details") or [{}])[0].get("job_id")
    assert new_id and new_id in dj._jobs

    deadline = time.time() + 15
    status = {}
    while time.time() < deadline:
        status = dj.get_job_status(project, source="src/lib/app.jar") or {}
        if status.get("status") == "ready":
            break
        time.sleep(0.05)
    assert status.get("status") == "ready"
    out_java = project_root(project) / status["output_root"] / "sources" / "com" / "demo" / "Hello.java"
    assert out_java.is_file()


def test_wait_gate_starts_marking_without_all_jars(tmp_env, project, monkeypatch):
    import threading

    from app.services import pipeline

    scheduled: list[tuple[str, int]] = []

    def _boom(*_a, **_k):
        raise AssertionError("盖章线程不得同步 resume / 入库")

    monkeypatch.setattr(dj, "business_jar_map_ready", lambda pid: True)
    monkeypatch.setattr(
        dj,
        "load_business_jar_state",
        lambda pid: {"paths": ["src/lib/a.jar", "src/lib/b.jar"], "ingested": ["src/lib/a.jar"]},
    )
    monkeypatch.setattr(dj, "resume_orphaned_decompile_jobs", _boom)
    monkeypatch.setattr(dj, "ingest_ready_business_jars", _boom)
    monkeypatch.setattr(dj, "wait_business_jar_ingest", _boom)
    monkeypatch.setattr(dj, "business_jar_decompile_pending", lambda pid: True)
    monkeypatch.setattr(dj, "schedule_decompile_resume", lambda pid: scheduled.append(("resume", pid)))
    monkeypatch.setattr(dj, "schedule_jar_ingest", lambda pid, source="": scheduled.append(("ingest", pid)))

    cancel = threading.Event()
    t0 = time.time()
    assert pipeline._wait_business_jar_ingest_gate(project, cancel) is True
    assert time.time() - t0 < 1.0
    assert ("resume", project) in scheduled
    assert ("ingest", project) in scheduled


def test_weight_path_candidates_workspace(tmp_env):
    from app.tools.phase_recon import weight_path_candidates

    cands = weight_path_candidates("workspace/decompiled/abc/sources/Foo.java")
    assert cands == ["workspace/decompiled/abc/sources/Foo.java"]
    assert "src/workspace" not in cands[0]


def test_read_snippet_workspace_path(tmp_env, project):
    from app.services.pipeline import _read_file_snippet
    from app.services.paths import project_root

    rel = "workspace/decompiled/test/sources/Demo.java"
    target = project_root(project) / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("class Demo {}\n", encoding="utf-8")
    text = _read_file_snippet(project, rel)
    assert "class Demo" in text


def test_ingest_ready_jars_one_per_call(tmp_env, project, monkeypatch):
    from app.models import FileWeight, SessionLocal

    src = src_dir(project)
    _write_jar(src / "lib" / "first.jar", {"com/demo/First.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    _write_jar(src / "lib" / "second.jar", {"com/demo/Second.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        name = "Second" if "second.jar" in job.source_rel.replace("\\", "/") else "First"
        target = out_dir / "sources" / "com" / "demo" / f"{name}.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(f"class {name} {{}}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    monkeypatch.setattr(dj, "_maybe_ingest_business_jar", lambda _job: None)
    dj._run_jadx_hook = fake_run

    registry.dispatch(
        _ctx(project),
        "MarkBusinessJar",
        {"paths": ["src/lib/first.jar", "src/lib/second.jar"], "done": True},
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        a = (dj.get_job_status(project, source="src/lib/first.jar") or {}).get("status")
        b = (dj.get_job_status(project, source="src/lib/second.jar") or {}).get("status")
        if a == "ready" and b == "ready":
            break
        time.sleep(0.05)
    assert (dj.get_job_status(project, source="src/lib/first.jar") or {}).get("status") == "ready"
    assert (dj.get_job_status(project, source="src/lib/second.jar") or {}).get("status") == "ready"

    first = dj.ingest_ready_business_jars(project)
    assert first.get("ok") is True
    with SessionLocal() as db:
        paths = [r.path for r in db.query(FileWeight).filter(FileWeight.project_id == project).all()]
    assert any(p.endswith("First.java") for p in paths)
    assert not any(p.endswith("Second.java") for p in paths)

    second = dj.ingest_ready_business_jars(project)
    assert second.get("ok") is True
    with SessionLocal() as db:
        paths = [r.path for r in db.query(FileWeight).filter(FileWeight.project_id == project).all()]
    assert any(p.endswith("Second.java") for p in paths)


def test_ready_jar_ingests_on_sidecar_not_jadx_thread(tmp_env, project, monkeypatch):
    import threading

    from app.models import FileWeight, SessionLocal

    src = src_dir(project)
    _write_jar(src / "lib" / "app.jar", {"com/demo/Hello.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    callers: list[str] = []
    real = dj.ingest_decompiled_classes

    def wrapped(pid, source):
        callers.append(threading.current_thread().name)
        return real(pid, source)

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "sources" / "com" / "demo" / "Hello.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class Hello {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "ingest_decompiled_classes", wrapped)
    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    dj._run_jadx_hook = fake_run

    mark = registry.dispatch(
        _ctx(project),
        "MarkBusinessJar",
        {"paths": ["src/lib/app.jar"], "done": True},
    )
    assert mark.get("ok") is True
    deadline = time.time() + 15
    while time.time() < deadline:
        if (dj.get_job_status(project, source="src/lib/app.jar") or {}).get("status") == "ready":
            break
        time.sleep(0.05)
    assert (dj.get_job_status(project, source="src/lib/app.jar") or {}).get("status") == "ready"
    assert dj.wait_decompile_service_idle(timeout=10)
    assert callers
    assert all(not name.startswith("vh-jadx") for name in callers)
    assert any(name == "vh-decompile-svc" for name in callers)
    with SessionLocal() as db:
        paths = [r.path for r in db.query(FileWeight).filter(FileWeight.project_id == project).all()]
    assert any(p.endswith("Hello.java") and p.startswith("workspace/decompiled/") for p in paths)


def test_has_unmarked_files_is_existence_check(tmp_env, project):
    from app.models import FileWeight, SessionLocal
    from app.tools.phase_recon import has_unmarked_files

    assert has_unmarked_files(project) is False
    with SessionLocal() as db:
        db.add(
            FileWeight(
                project_id=project,
                path="src/a.java",
                weight=None,
                skipped=False,
                audited=False,
            )
        )
        db.commit()
    assert has_unmarked_files(project) is True


def test_ingest_queues_pending_when_app_db_busy(tmp_env, project, monkeypatch):
    from app.models import FileWeight, SessionLocal
    from app.services import decompile_store as store

    src = src_dir(project)
    _write_jar(src / "lib" / "app.jar", {"com/demo/Hello.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "sources" / "com" / "demo" / "Hello.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class Hello {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    monkeypatch.setattr(dj, "_maybe_ingest_business_jar", lambda _job: None)
    dj._run_jadx_hook = fake_run

    registry.dispatch(
        _ctx(project),
        "MarkBusinessJar",
        {"paths": ["src/lib/app.jar"], "done": True},
    )
    deadline = time.time() + 15
    while time.time() < deadline:
        if (dj.get_job_status(project, source="src/lib/app.jar") or {}).get("status") == "ready":
            break
        time.sleep(0.05)
    assert (dj.get_job_status(project, source="src/lib/app.jar") or {}).get("status") == "ready"

    store.acquire_app_db_write()
    try:
        out = dj.ingest_decompiled_classes(project, "src/lib/app.jar")
        assert out.get("ok") is True
        assert int(out.get("added") or 0) == 0
        assert store.pending_count(project, "src/lib/app.jar") >= 1
        with SessionLocal() as db:
            paths = [r.path for r in db.query(FileWeight).filter(FileWeight.project_id == project).all()]
        assert not any(p.endswith("Hello.java") for p in paths)
    finally:
        store.release_app_db_write()

    added = dj.drip_pending_fileweights(project, source_rel="src/lib/app.jar")
    assert added >= 1
    assert store.pending_count(project, "src/lib/app.jar") == 0
    with SessionLocal() as db:
        paths = [r.path for r in db.query(FileWeight).filter(FileWeight.project_id == project).all()]
    assert any(p.endswith("Hello.java") and p.startswith("workspace/decompiled/") for p in paths)


def test_decompile_store_upserts_job_on_ready(tmp_env, project, monkeypatch):
    from app.services import decompile_store as store
    from app.services.decompile_store import DecompileJobRow

    src = src_dir(project)
    _write_jar(src / "lib" / "app.jar", {"com/demo/Hello.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "sources" / "com" / "demo" / "Hello.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class Hello {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    monkeypatch.setattr(dj, "_maybe_ingest_business_jar", lambda _job: None)
    dj._run_jadx_hook = fake_run

    result = dj.submit_decompile(project, "src/lib/app.jar", audit_queue=True)
    job_id = result.get("job_id")
    deadline = time.time() + 15
    while time.time() < deadline:
        if (dj.get_job_status(project, source="src/lib/app.jar") or {}).get("status") == "ready":
            break
        time.sleep(0.05)
    assert job_id
    with store.SessionLocal() as db:
        row = db.get(DecompileJobRow, job_id)
    assert row is not None
    assert row.status == "ready"
    assert row.project_id == project


def test_jadx_lane_workers_reserves_interactive_slot(tmp_env, monkeypatch):
    monkeypatch.setattr(dj.settings, "decompile_concurrency", 2)
    sizes = dj.jadx_lane_workers()
    assert sizes[dj._LANE_BATCH] == 1
    assert sizes[dj._LANE_INTERACTIVE] == 1
    monkeypatch.setattr(dj.settings, "decompile_concurrency", 1)
    shared = dj.jadx_lane_workers()
    assert shared[dj._LANE_BATCH] == 1
    assert shared[dj._LANE_INTERACTIVE] == 0


def test_submit_lanes_split_batch_and_interactive(tmp_env, project, monkeypatch):
    src = src_dir(project)
    _write_jar(src / "lib" / "biz.jar", {"com/demo/Biz.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    _write_jar(src / "lib" / "read.jar", {"com/demo/Read.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    def fake_run(cmd, *, timeout, job):
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "com" / "demo" / "X.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class X {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    dj._run_jadx_hook = fake_run

    batch = dj.submit_decompile(project, "src/lib/biz.jar", audit_queue=True)
    interactive = dj.submit_decompile(project, "src/lib/read.jar")
    assert dj._jobs[batch["job_id"]].lane == dj._LANE_BATCH
    assert dj._jobs[interactive["job_id"]].lane == dj._LANE_INTERACTIVE
    heuristic = dj.submit_decompile(project, "src/lib/biz.jar", lane=dj._LANE_BATCH)
    assert heuristic.get("job_id") == batch["job_id"]


def test_worker_decompile_not_blocked_by_full_batch_queue(tmp_env, project, monkeypatch):
    import threading

    src = src_dir(project)
    _write_jar(src / "lib" / "batch-a.jar", {"com/demo/A.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    _write_jar(src / "lib" / "batch-b.jar", {"com/demo/B.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})
    _write_jar(src / "lib" / "worker-app.jar", {"com/demo/W.class": b"\xca\xfe\xba\xbe" + b"\x00" * 20})

    monkeypatch.setattr(dj.settings, "decompile_concurrency", 2)
    batch_hold = threading.Event()
    batch_entered = threading.Event()
    interactive_started = threading.Event()
    interactive_threads: list[str] = []

    def fake_run(cmd, *, timeout, job):
        if getattr(job, "lane", "") == dj._LANE_BATCH:
            batch_entered.set()
            batch_hold.wait(timeout=10)
        else:
            interactive_threads.append(threading.current_thread().name)
            interactive_started.set()
        out_dir = Path(cmd[cmd.index("-d") + 1])
        target = out_dir / "com" / "demo" / "Out.java"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("class Out {}\n", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(dj, "resolve_jadx_binary", lambda: "jadx")
    monkeypatch.setattr(dj, "jadx_version_string", lambda _b=None: "1.5.5")
    dj._run_jadx_hook = fake_run

    worker_out: dict = {}
    try:
        dj.submit_decompile(project, "src/lib/batch-a.jar", audit_queue=True)
        dj.submit_decompile(project, "src/lib/batch-b.jar", audit_queue=True)
        assert batch_entered.wait(timeout=5)
        worker_out = registry.dispatch(
            _ctx(project, role="worker"),
            "DecompileJava",
            {"path": "src/lib/worker-app.jar"},
        )
        assert worker_out.get("ok") is True
        assert worker_out.get("status") in ("queued", "running", "ready")
        assert interactive_started.wait(timeout=5)
        assert any(name.startswith("vh-jadx-w") for name in interactive_threads)
    finally:
        batch_hold.set()

    jid = worker_out.get("job_id")
    deadline = time.time() + 8
    while time.time() < deadline and jid:
        st = dj.get_job_status(project, job_id=jid) or {}
        if st.get("status") in ("ready", "failed", "skipped"):
            break
        time.sleep(0.05)
    assert (dj.get_job_status(project, job_id=jid) or {}).get("status") == "ready"
