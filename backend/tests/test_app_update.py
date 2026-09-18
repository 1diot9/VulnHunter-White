from __future__ import annotations

from dataclasses import dataclass

from fastapi.testclient import TestClient

from app.services.app_update import (
    apply_update,
    check_for_update,
    parse_changelog_version,
    redact_remote_url,
    reset_app_update_state,
    short_sha,
    start_app_update_checker,
    status_to_out,
)


@dataclass
class _GitProc:
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""


OLD = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
NEW = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _git_router(commands: list[list[str]], *, dirty: str = "", head: list[str] | None = None):
    current = head or [OLD]

    def fake_git(args, **kwargs):
        commands.append(list(args))
        if args[:2] == ["rev-parse", "--is-inside-work-tree"]:
            return _GitProc(stdout="true\n")
        if args[:1] == ["status"]:
            return _GitProc(stdout=dirty)
        if args[:2] == ["rev-parse", "HEAD"]:
            return _GitProc(stdout=f"{current[0]}\n")
        if args[:2] == ["rev-parse", "FETCH_HEAD"]:
            return _GitProc(stdout=f"{NEW}\n")
        if args[:1] == ["remote"] and args[1:] == []:
            return _GitProc(stdout="origin\n")
        if args[:3] == ["remote", "get-url", "origin"]:
            return _GitProc(stdout="https://github.com/1diot9/VulnHunter-White.git\n")
        if args[:2] == ["rev-parse", "--abbrev-ref"]:
            return _GitProc(stdout="origin/main\n")
        if args[:1] == ["ls-remote"]:
            return _GitProc(stdout=f"{NEW}\trefs/heads/main\n")
        if args[:1] == ["fetch"]:
            return _GitProc()
        if args[:2] == ["merge-base", "--is-ancestor"]:
            ancestor, descendant = args[2], args[3]
            if ancestor == current[0] and descendant == NEW:
                return _GitProc()
            return _GitProc(returncode=1)
        if args[:2] == ["merge", "--ff-only"]:
            current[0] = NEW
            return _GitProc()
        if args[:2] == ["diff", "--name-only"]:
            return _GitProc(stdout="README.md\n")
        raise AssertionError(args)

    return fake_git


def test_parse_changelog_and_redact():
    assert parse_changelog_version("# Changelog\n\n## V1.2.6 - 2026-09-18\n") == "V1.2.6"
    assert parse_changelog_version("no version") == ""
    assert short_sha(NEW) == "bbbbbbb"
    assert (
        redact_remote_url("https://ghp_secret@github.com/1diot9/VulnHunter-White.git")
        == "https://github.com/1diot9/VulnHunter-White.git"
    )


def test_check_detects_upstream_update(tmp_env, tmp_path, monkeypatch):
    from app.services import app_update as mod

    reset_app_update_state()
    (tmp_path / "CHANGELOG.md").write_text("## V1.2.6 - 2026-09-18\n", encoding="utf-8")
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    monkeypatch.setattr(mod, "is_docker_runtime", lambda: False)
    monkeypatch.setattr(mod, "_remote_changelog_version", lambda url, sha: "V1.2.7")
    commands: list[list[str]] = []
    monkeypatch.setattr(mod, "_git", _git_router(commands))

    status = check_for_update()
    assert status.git_available is True
    assert status.update_available is True
    assert status.can_apply is True
    assert status.current_sha == OLD
    assert status.remote_sha == NEW
    assert status.remote_version == "V1.2.7"
    assert status.current_version == "V1.2.6"
    assert any(args[:1] == ["ls-remote"] for args in commands)


def test_check_blocks_dirty_and_docker(tmp_env, tmp_path, monkeypatch):
    from app.services import app_update as mod

    reset_app_update_state()
    (tmp_path / "CHANGELOG.md").write_text("## V1.2.6 - 2026-09-18\n", encoding="utf-8")
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    monkeypatch.setattr(mod, "_remote_changelog_version", lambda url, sha: "")

    monkeypatch.setattr(mod, "is_docker_runtime", lambda: False)
    monkeypatch.setattr(mod, "_git", _git_router([], dirty=" M README.md\n"))
    dirty = check_for_update()
    assert dirty.update_available is True
    assert dirty.dirty is True
    assert dirty.can_apply is False
    assert dirty.apply_blocked_reason == "dirty"

    reset_app_update_state()
    monkeypatch.setattr(mod, "is_docker_runtime", lambda: True)
    monkeypatch.setattr(mod, "_git", _git_router([]))
    docker = check_for_update()
    assert docker.update_available is True
    assert docker.can_apply is False
    assert docker.apply_blocked_reason == "docker"


def test_apply_fast_forward_restarts(tmp_env, tmp_path, monkeypatch):
    from app.services import app_update as mod

    reset_app_update_state()
    (tmp_path / "CHANGELOG.md").write_text("## V1.2.6 - 2026-09-18\n", encoding="utf-8")
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    monkeypatch.setattr(mod, "is_docker_runtime", lambda: False)
    monkeypatch.setattr(mod, "_remote_changelog_version", lambda url, sha: "V1.2.7")
    monkeypatch.setattr(mod, "_install_changed_deps", lambda old, new: "")
    spawned: list[int] = []
    monkeypatch.setattr(mod, "_spawn_restarter", lambda: spawned.append(1) or True)
    monkeypatch.setattr(mod, "_git", _git_router([]))

    out = apply_update()
    assert out["ok"] is True, out
    assert out["restarting"] is True
    assert out["pulled"] is True
    assert out["old_sha"] == OLD
    assert out["new_sha"] == NEW
    assert spawned == [1]


def test_apply_refuses_when_diverged(tmp_env, tmp_path, monkeypatch):
    from app.services import app_update as mod

    reset_app_update_state()
    (tmp_path / "CHANGELOG.md").write_text("## V1.2.6 - 2026-09-18\n", encoding="utf-8")
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    monkeypatch.setattr(mod, "is_docker_runtime", lambda: False)
    monkeypatch.setattr(mod, "_remote_changelog_version", lambda url, sha: "")
    monkeypatch.setattr(mod, "_spawn_restarter", lambda: True)

    def fake_git(args, **kwargs):
        if args[:2] == ["merge-base", "--is-ancestor"]:
            return _GitProc(returncode=1)
        router = _git_router([])
        if args[:1] == ["fetch"]:
            return _GitProc()
        if args[:2] == ["rev-parse", "FETCH_HEAD"]:
            return _GitProc(stdout=f"{NEW}\n")
        return router(args, **kwargs)

    monkeypatch.setattr(mod, "_git", fake_git)
    out = apply_update()
    assert out["ok"] is False
    assert out["reason"] == "diverged"
    assert out["restarting"] is False


def test_app_update_api(tmp_env, tmp_path, monkeypatch):
    from app.main import app
    from app.services import app_update as mod

    reset_app_update_state()
    (tmp_path / "CHANGELOG.md").write_text("## V1.2.6 - 2026-09-18\n", encoding="utf-8")
    monkeypatch.setattr(mod, "ROOT_DIR", tmp_path)
    monkeypatch.setattr(mod, "is_docker_runtime", lambda: False)
    monkeypatch.setattr(mod, "_remote_changelog_version", lambda url, sha: "V1.2.7")
    monkeypatch.setattr(mod, "_install_changed_deps", lambda old, new: "")
    monkeypatch.setattr(mod, "_spawn_restarter", lambda: True)
    monkeypatch.setattr(mod, "_git", _git_router([]))

    with TestClient(app) as client:
        cached = client.get("/api/settings/app-update")
        assert cached.status_code == 200
        body = cached.json()
        assert body["update_available"] is True
        assert body["can_apply"] is True
        assert body["current_sha_short"] == "aaaaaaa"
        assert body["remote_version"] == "V1.2.7"

        checked = client.post("/api/settings/app-update/check")
        assert checked.status_code == 200
        assert checked.json()["update_available"] is True

        applied = client.post("/api/settings/app-update/apply")
        assert applied.status_code == 200
        assert applied.json()["ok"] is True, applied.json()
        assert applied.json()["restarting"] is True


def test_start_checker_respects_disable(tmp_env, monkeypatch):
    from app.services import app_update as mod

    reset_app_update_state()
    monkeypatch.setattr(mod.settings, "app_update_check", False)
    start_app_update_checker()
    assert mod._poll_thread is None
    payload = status_to_out(mod.AppUpdateStatus(current_sha=OLD))
    assert payload["current_sha_short"] == "aaaaaaa"
