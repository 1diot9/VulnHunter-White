"""Initial prompt documents are loaded and injected, not hardcoded in pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from app.prompts import PROMPTS_DIR, load_prompt, render_prompt
from app.services import pipeline

INITIAL_DOCS = (
    "recon.md",
    "recon-retry-loop.md",
    "recon-retry-timeout.md",
    "recon-retry-other.md",
    "recon-old-vuln.md",
    "recon-old-vuln-retry-loop.md",
    "recon-old-vuln-retry-timeout.md",
    "recon-old-vuln-retry-other.md",
    "recon-mark.md",
    "worker.md",
    "fix.md",
    "reviewer.md",
)


def test_all_initial_prompt_docs_exist():
    for name in INITIAL_DOCS:
        path = PROMPTS_DIR / "initial" / name
        assert path.is_file(), name
        assert path.read_text(encoding="utf-8").strip()


def test_render_prompt_substitutes_placeholders():
    text = render_prompt("initial/recon.md", project_id=42)
    assert "项目 ID=42" in text
    assert "${project_id}" not in text
    assert "docs/code-map.md" in text


def test_render_prompt_does_not_rescan_values():
    snippet = "price = ${project_id} + {$not_a_placeholder}"
    text = render_prompt("initial/worker.md", snippet=snippet, project_id=7, file_path="a.py")
    assert "price = ${project_id} + {$not_a_placeholder}" in text
    assert "当前注入文件: src/a.py" in text


def test_render_prompt_missing_file():
    with pytest.raises(FileNotFoundError, match="prompt not found"):
        load_prompt("initial/does-not-exist.md")


def test_initial_prompt_helper_loads_from_initial_dir():
    text = pipeline._initial_prompt("fix.md", vuln_id=9, title="SQLi", reason="缺证据", report_path="vulns/9/report.md")
    assert "漏洞 ID=9" in text
    assert "标题=SQLi" in text
    assert "FinishFix(vuln_id=9)" in text


def test_recon_mark_and_reviewer_docs_render_runtime_fields():
    mark = pipeline._initial_prompt(
        "recon-mark.md",
        project_id=1,
        marked=3,
        total=10,
        batch_count=2,
        paths="- a.java\n- b.java",
    )
    assert "已标记 3/10，本批 2 个" in mark
    assert "- a.java" in mark

    review = pipeline._initial_prompt(
        "reviewer.md",
        vuln_id=5,
        payload='{"title":"x"}',
        lab_note="环境: ok",
        debug_plan="[]",
    )
    assert "审核漏洞 ID=5" in review
    assert "vulns/5/report.md" in review
    assert "环境: ok" in review
    assert "attack_surface" in review
    assert "impact" in review
    assert "exploit_complexity" in review
    assert "defense_status" in review


def test_reviewer_prompt_requires_attack_surface_and_severity_factors():
    text = load_prompt("reviewer.md")
    assert "attack_surface" in text
    assert "required_account" in text
    assert "impact" in text
    assert "exploit_complexity" in text
    assert "defense_status" in text
    assert "前台" in text
    assert "后台" in text


def test_worker_prompts_decouple_finish_file_and_round():
    worker = load_prompt("worker.md")
    initial = load_prompt("initial/worker.md")
    assert "FinishFile ≠ FinishRound" in worker
    assert "禁止立刻 FinishRound" in worker
    assert "禁止立刻 FinishRound" in initial
    assert "中途 FinishFile 之后必须继续分析" in worker
    assert "再 FinishRound 并附简短单轮报告" not in worker
    assert "然后 FinishRound" not in initial


def test_pipeline_source_has_no_inline_initial_prompts():
    src = Path(pipeline.__file__).read_text(encoding="utf-8")
    for needle in (
        "请开始代码地图与鉴权文档会话",
        "请开始历史漏洞会话",
        "请从该文件出发沿调用链审计",
        "你是 Fix Worker",
        "审核漏洞 ID=",
    ):
        assert needle not in src, needle
