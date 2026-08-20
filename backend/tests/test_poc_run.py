from __future__ import annotations

from app.services.paths import project_root
from app.services.poc_run import execute_poc_text, resolve_lab_target_url
from app.services.lab import save_env

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


def test_resolve_lab_target_prefers_env_json(tmp_env, project):
    assert resolve_lab_target_url(project) is None
    save_env(
        project,
        {"accepted": True, "status": "running", "target_url": "http://127.0.0.1:18080"},
    )
    assert resolve_lab_target_url(project) == "http://127.0.0.1:18080"
