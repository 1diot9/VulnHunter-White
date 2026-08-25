from __future__ import annotations

import tempfile
from pathlib import Path

from app.services.lab import save_env
from app.services.paths import project_root, project_runtime_dir
from app.services.poc_run import (
    POC_RUN_SCRIPT_NAME,
    execute_poc_file,
    execute_poc_text,
    resolve_lab_target_url,
)

_OK = """
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
args = p.parse_args()
print("hit", args.url)
raise SystemExit(0)
"""

_FAIL = """
import argparse
p = argparse.ArgumentParser()
p.add_argument("-u", "--url", required=True)
p.add_argument("--proxy", default="")
args = p.parse_args()
print("miss", args.url)
raise SystemExit(2)
"""


def test_execute_poc_text_honors_exit_code(tmp_env, project):
    cwd = project_root(project)
    ok = execute_poc_text(_OK, target_url="http://127.0.0.1:18080", cwd=cwd)
    assert ok["ok"] is True
    assert ok["exit_code"] == 0
    assert "http://127.0.0.1:18080" in ok["stdout"]
    bad = execute_poc_text(_FAIL, target_url="http://127.0.0.1:18080", cwd=cwd)
    assert bad["ok"] is False
    assert bad["exit_code"] == 2
    assert "未打出冲击" in bad["error"]


def test_execute_poc_text_stays_in_project_workspace(tmp_env, project, monkeypatch):
    cwd = project_root(project)
    runtime = project_runtime_dir(project).resolve()
    dir_kwargs: list[Path] = []
    scripts: list[Path] = []
    orig_td = tempfile.TemporaryDirectory

    class TrackingTemporaryDirectory(orig_td):
        def __init__(self, *args, **kwargs):
            dir_kwargs.append(Path(kwargs["dir"]).resolve())
            super().__init__(*args, **kwargs)

    def tracking_run(script, **kwargs):
        scripts.append(Path(script).resolve())
        return execute_poc_file(script, **kwargs)

    monkeypatch.setattr("app.services.poc_run.tempfile.TemporaryDirectory", TrackingTemporaryDirectory)
    monkeypatch.setattr("app.services.poc_run.execute_poc_file", tracking_run)
    execute_poc_text(_OK, target_url="http://127.0.0.1:18080", cwd=cwd, project_id=project)
    assert dir_kwargs == [runtime]
    assert scripts
    script = scripts[0]
    assert script.is_relative_to(runtime)
    assert script.name == POC_RUN_SCRIPT_NAME
    assert script.name != "poc.py"
    assert not list(runtime.glob("lab-verify-*"))
    assert not list(runtime.glob("vulnhunter-poc-*"))


def test_resolve_lab_target_prefers_env_json(tmp_env, project):
    assert resolve_lab_target_url(project) is None
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    assert resolve_lab_target_url(project) == "http://127.0.0.1:18080"
