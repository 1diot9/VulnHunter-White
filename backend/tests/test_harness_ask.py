from __future__ import annotations

import json

from fastapi.testclient import TestClient

from app.agent.checkpoint import LoopCheckpoint, load_checkpoint, save_checkpoint
from app.services.harness_ask import (
    HARNESS_ASK_AWAITING,
    awaiting_harness_count,
    park_harness_ask_user,
    resolve_harness_consent,
)


def _pending_vuln(project_id: int) -> int:
    from app.models import SessionLocal, Vuln

    with SessionLocal() as db:
        vuln = Vuln(
            project_id=project_id,
            title="局部验证待审",
            vuln_type="sqli",
            status="pending_review",
        )
        db.add(vuln)
        db.commit()
        db.refresh(vuln)
        return int(vuln.id)


def test_park_and_list_harness_consent(tmp_env, project):
    from app.main import app

    vuln_id = _pending_vuln(project)
    out = park_harness_ask_user(project, vuln_id, reason="RunCode 连续失败：缺 javax.servlet")
    assert out["ok"] is True
    assert out["awaiting_user"] is True
    assert awaiting_harness_count(project) == 1

    with TestClient(app) as client:
        listed = client.get("/api/vulns/harness-consent")
        assert listed.status_code == 200
        rows = listed.json()
        assert any(row["id"] == vuln_id for row in rows)
        assert "javax.servlet" in (rows[0].get("harness_ask_reason") or "")
        count = client.get("/api/vulns/verifier-consent/count")
        body = count.json()
        assert body["harness"] >= 1
        assert body["count"] >= body["harness"]


def test_resolve_harness_consent_continue(tmp_env, project, monkeypatch):
    from app.models import PhaseRun, SessionLocal, Vuln

    kicked: list[int] = []
    monkeypatch.setattr("app.services.pipeline.kick_reviewer", lambda pid: kicked.append(pid))

    vuln_id = _pending_vuln(project)
    park_harness_ask_user(project, vuln_id, reason="连续失败")
    with SessionLocal() as db:
        run = PhaseRun(
            project_id=project,
            phase="reviewer",
            role="reviewer",
            status="awaiting_user",
            vuln_id=vuln_id,
        )
        db.add(run)
        db.commit()
        run_id = int(run.id)

    tool_call_id = "ask-runcode-1"
    cp = LoopCheckpoint(
        project_id=project,
        phase_run_id=run_id,
        role="reviewer",
        phase="reviewer",
        system_prompt="sys",
        user_prompt="user",
        messages=[
            {"role": "system", "content": "sys"},
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": tool_call_id,
                        "type": "function",
                        "function": {
                            "name": "AskUser",
                            "arguments": json.dumps({"reason": "连续失败"}, ensure_ascii=False),
                        },
                    }
                ],
            },
        ],
        state={"awaiting_user": True, "runcode_fail_streak": 3},
        vuln_id=vuln_id,
    )
    save_checkpoint(cp, status="awaiting_user")

    cont = resolve_harness_consent(vuln_id, action="continue", instruction="改成抽出函数")
    assert cont["ok"] is True, cont
    assert kicked == [project]
    with SessionLocal() as db:
        v = db.get(Vuln, vuln_id)
        assert v.harness_ask_status != HARNESS_ASK_AWAITING
        assert v.harness_user_instruction == "改成抽出函数"
        pr = db.get(PhaseRun, run_id)
        assert pr.status == "paused"

    loaded = load_checkpoint(project, run_id)
    assert loaded is not None
    tool_msgs = [m for m in loaded.messages if m.get("role") == "tool"]
    assert len(tool_msgs) == 1
    body = json.loads(tool_msgs[0]["content"])
    assert body["decision"] == "continue"
    assert "抽出函数" in body["instruction"]
    assert loaded.state.get("runcode_fail_streak") == 0


def test_resolve_harness_consent_skip_tells_static(tmp_env, project, monkeypatch):
    from app.models import PhaseRun, SessionLocal

    monkeypatch.setattr("app.services.pipeline.kick_reviewer", lambda pid: None)
    vuln_id = _pending_vuln(project)
    park_harness_ask_user(project, vuln_id, reason="连续失败")
    with SessionLocal() as db:
        run = PhaseRun(
            project_id=project,
            phase="reviewer",
            role="reviewer",
            status="awaiting_user",
            vuln_id=vuln_id,
        )
        db.add(run)
        db.commit()
        run_id = int(run.id)
    save_checkpoint(
        LoopCheckpoint(
            project_id=project,
            phase_run_id=run_id,
            role="reviewer",
            phase="reviewer",
            system_prompt="s",
            user_prompt="u",
            messages=[
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "ask-1",
                            "type": "function",
                            "function": {"name": "AskUser", "arguments": "{}"},
                        }
                    ],
                }
            ],
            state={"awaiting_user": True},
            vuln_id=vuln_id,
        ),
        status="awaiting_user",
    )
    skip = resolve_harness_consent(vuln_id, action="skip")
    assert skip["ok"] is True
    loaded = load_checkpoint(project, run_id)
    body = json.loads([m for m in loaded.messages if m.get("role") == "tool"][0]["content"])
    assert body["decision"] == "skip"
    assert "static_only" in body["message"]
