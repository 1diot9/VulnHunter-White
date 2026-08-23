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
    "recon-map-refresh.md",
    "recon-map-refresh-retry-loop.md",
    "recon-map-refresh-retry-timeout.md",
    "recon-map-refresh-retry-other.md",
    "recon-old-vuln.md",
    "recon-old-vuln-retry-loop.md",
    "recon-old-vuln-retry-timeout.md",
    "recon-old-vuln-retry-other.md",
    "recon-old-vuln-ghsa.md",
    "recon-old-vuln-ghsa-retry-loop.md",
    "recon-old-vuln-ghsa-retry-timeout.md",
    "recon-old-vuln-ghsa-retry-other.md",
    "recon-source-ext.md",
    "recon-source-ext-retry-loop.md",
    "recon-source-ext-retry-timeout.md",
    "recon-source-ext-retry-other.md",
    "recon-mark.md",
    "worker.md",
    "fix.md",
    "reviewer.md",
    "reviewer-lab.md",
    "reviewer-lab-retry-loop.md",
    "reviewer-lab-retry-timeout.md",
    "reviewer-lab-retry-other.md",
    "reviewer-lab-user-retry.md",
    "verifier.md",
    "fast_worker.md",
    "bypass_worker.md",
    "sink_triage.md",
    "cli_indexer.md",
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
    assert "当前焦点文件: src/a.py" in text


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
    assert "advisory.md" in review
    assert "环境: ok" in review
    assert "attack_surface" in review
    assert "impact" in review
    assert "exploit_complexity" in review
    assert "defense_status" in review
    assert "submission_tier" in review
    assert "submission_reason" in review
    assert "root_cause_key" in review
    assert "config_premise" in review
    assert "CVE" in review
    assert "互联网资产证明" in review
    assert "docs/lab.md" in review
    assert "CollectLabFingerprints" in review


def test_reviewer_prompt_requires_attack_surface_and_severity_factors():
    text = load_prompt("reviewer.md")
    assert "attack_surface" in text
    assert "required_account" in text
    assert "impact" in text
    assert "exploit_complexity" in text
    assert "defense_status" in text
    assert "submission_tier" in text
    assert "submission_reason" in text
    assert "root_cause_key" in text
    assert "config_premise" in text
    assert "MergeIntoVuln" in text
    assert "SearchTools" in text
    assert "原样复用" in text
    assert "不要另写新键" in text or "禁止另写新键" in text or "禁止另造" in text
    assert "cve_candidate" in text
    assert "low_impact" in text
    assert "有 CVE 价值" in text
    assert "低危害难利用" in text
    assert "advisory_only" not in text
    assert "needs_more_evidence" not in text
    assert "证据不足" not in text
    assert "双层审核" in text
    assert "前台" in text
    assert "后台" in text
    assert "互联网资产证明" in text
    assert "FOFA" in text
    assert "X 情报社区" in text
    assert "CollectLabFingerprints" in text
    assert "fofa_fingerprint" in text
    assert "成立性否决" in text
    assert "docker exec" in text
    assert "specific_environment" in text
    assert "不要按漏洞类型" in text
    assert "默认密码" in text
    assert "弱口令" in text
    assert "SSRF 观察面" in text
    assert "仅响应差别" in text
    assert "limited_info" in text
    assert "CollectLabFingerprints" in load_prompt("initial/reviewer.md")
    assert "SearchTools" in load_prompt("reviewer.md")
    assert "SearchTools" in load_prompt("initial/reviewer.md")
    followup = load_prompt("initial/reviewer-dynamic-followup.md")
    assert "追加动态验证" in followup
    assert "evidence_level=dynamic" in followup
    assert "不要从零重做静态分析" in followup
    assert "CollectLabFingerprints" in followup
    assert "fofa_fingerprint" in load_prompt("initial/reviewer.md")
    assert "默认可利用" in load_prompt("initial/reviewer.md")
    assert "默认密码" in load_prompt("initial/reviewer.md")
    assert "MergeIntoVuln" in load_prompt("initial/reviewer.md")
    assert "audit_mode_hint" in load_prompt("initial/reviewer.md")
    assert "原样复用" in load_prompt("initial/reviewer.md")
    assert "audit_mode_hint" in load_prompt("initial/worker.md")
    assert "AppendAffectedLocations" in load_prompt("initial/worker.md")
    assert "audit_mode_hint" in load_prompt("initial/fix.md")
    assert "观察面" in load_prompt("initial/worker.md")
    assert "观察面" in load_prompt("initial/reviewer.md")
    assert "观察面" in load_prompt("initial/fix.md")
    assert "仅响应差别" in load_prompt("fast_worker.md")
    assert "仅响应差别" in load_prompt("bypass_worker.md")
    assert "观察面" in load_prompt("modes/full.md")
    assert "观察面" in load_prompt("verifier.md")


def test_worker_prompt_requires_default_exploitability():
    worker = load_prompt("worker.md")
    assert "什么算漏洞" in worker
    assert "默认配置" in worker
    assert "不要按漏洞类型填写或推断严重度" in worker
    assert "发现漏洞立即 SubmitVuln" not in worker
    assert "仅当满足上方提交闸门时 SubmitVuln" in worker
    assert "同根因只交一份" in worker
    assert "AppendAffectedLocations" in worker
    assert "同根因受影响点" in worker
    assert "root_cause_key" in worker
    assert "config_premise" in worker
    assert "特定配置" in worker
    assert "默认密码" in worker
    assert "弱口令" in worker
    assert "-u/--url" in worker
    assert "--proxy" in worker
    assert "-c/--cmd" in worker
    assert "回显" in worker
    assert "SSRF 必须标明观察面" in worker
    assert "仅响应差别" in worker
    assert "内网端口" in worker
    assert "云元数据" in worker


def test_poc_prompt_requires_cli_parameters():
    poc = load_prompt("poc.md")
    assert "-u/--url" in poc
    assert "--proxy" in poc
    assert "强制走代理" in poc
    assert "proxy_bypass" in poc
    assert "-c/--cmd" in poc
    assert "argparse" in poc
    assert "命令输出" in poc
    assert "SSRF 回显" in poc
    assert "通/不通" in poc
    assert "不要写死" in poc
    assert "退出码 0" in poc
    assert "系统再执行" in poc
    assert "--strict-ssl" in poc
    assert "跳过 TLS 证书校验" in poc
    reviewer = load_prompt("reviewer.md")
    assert "poc_code" in reviewer
    assert "-c/--cmd" in reviewer
    fast = load_prompt("fast_worker.md")
    assert "-c/--cmd" in fast
    assert "--proxy" in fast
    bypass = load_prompt("bypass_worker.md")
    assert "-c/--cmd" in bypass
    assert "--proxy" in bypass
    assert "-c/--cmd" in load_prompt("initial/worker.md")
    assert "CLI 形态" in load_prompt("initial/fix.md")
    assert "poc.py -u" in load_prompt("verifier.md")


def test_audit_mode_overlay_prompts(tmp_env, project):
    bounty_worker = load_prompt("modes/bounty.md")
    assert "赏金模式" in bounty_worker
    assert "不要 Confirm、不要标 `low_impact`" in bounty_worker
    assert "有回显" in bounty_worker
    assert "仅响应差别" in bounty_worker
    assert "存储型 XSS" in bounty_worker
    assert "1-click CSRF" in bounty_worker
    assert "普通 CSRF" in bounty_worker
    assert "源码硬编码密钥" in bounty_worker
    assert "前端传输混淆" in bounty_worker
    assert "服务端机密" in bounty_worker
    assert "应用自身提供的配置选项" in bounty_worker
    assert "不要 docker" in bounty_worker
    assert "禁止主动搭建漏洞利用环境" not in bounty_worker
    assert "被测应用必须是" in bounty_worker
    assert "旧应用镜像" in bounty_worker
    full = load_prompt("modes/full.md")
    assert "全量模式" in full
    assert "low_impact" in full

    from app.models import Project, SessionLocal
    from app.services import pipeline

    overlay = pipeline._phase_system_prompt(project, "worker.md")
    assert "赏金模式" in overlay
    assert "什么算漏洞" in overlay
    assert "-u/--url" in overlay
    assert "--proxy" in overlay
    assert "-c/--cmd" in overlay
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.audit_mode = "full"
        db.commit()
    full_overlay = pipeline._phase_system_prompt(project, "reviewer.md")
    assert "全量模式" in full_overlay
    assert "双层审核" in full_overlay
    assert "仅静态" in full_overlay
    assert "-c/--cmd" in full_overlay
    assert full_overlay.rindex("仅静态") > full_overlay.rindex("-c/--cmd")

    with SessionLocal() as db:
        p = db.get(Project, project)
        p.dynamic_verify_enabled = True
        db.commit()
    dynamic_overlay = pipeline._phase_system_prompt(project, "reviewer.md")
    assert "仅静态" not in dynamic_overlay
    assert "动态验证阶梯" in dynamic_overlay
    assert "即将落盘" in dynamic_overlay
    forced = pipeline._phase_system_prompt(project, "reviewer.md", verify_mode="off")
    assert "仅静态" in forced

    initial = pipeline._initial_prompt(
        "worker.md",
        worker_id="w1",
        round_id=1,
        file_path="a.py",
        weight=10,
        has_source=True,
        sources="login",
        snippet="x",
    )
    assert "赏金模式" in initial
    assert "${audit_mode_hint}" not in initial


def test_static_verify_overlay_prompt():
    text = load_prompt("verify/static.md")
    assert "仅静态" in text
    assert "evidence_level=static_only" in text
    assert "debug MCP" in text


def test_lab_verify_overlay_prompt():
    text = load_prompt("verify/lab.md")
    assert "靶场动态" in text
    assert "即将落盘" in text
    assert "退出码" in text


def test_harness_verify_overlay_prompt(tmp_env, project):
    from app.models import Project, SessionLocal
    from app.services import pipeline

    text = load_prompt("verify/harness.md")
    assert "局部验证" in text
    assert "evidence_level=harness" in text
    assert "RunCode" in text
    with SessionLocal() as db:
        p = db.get(Project, project)
        p.dynamic_verify_mode = "harness"
        p.dynamic_verify_enabled = True
        db.commit()
    overlay = pipeline._phase_system_prompt(project, "reviewer.md")
    assert "局部验证" in overlay
    assert "RunCode" in overlay
    assert "evidence_level=harness" in overlay


def test_reviewer_debug_mcp_is_poc_rewrite_fallback():
    reviewer = load_prompt("reviewer.md")
    followup = load_prompt("initial/reviewer-dynamic-followup.md")
    initial = load_prompt("initial/reviewer.md")
    poc = load_prompt("poc.md")
    assert "优先 debug MCP" not in reviewer
    assert "debug MCP 只用于改 PoC 时的动态调试" in reviewer
    assert "先普通动态" in reviewer
    assert "debug MCP 不是首选" in followup
    assert "才用 debug MCP 动态调试" in initial
    assert "不是首选验证方式" in poc


def test_worker_prompts_decouple_finish_file_and_round():
    worker = load_prompt("worker.md")
    initial = load_prompt("initial/worker.md")
    assert "FinishFile ≠ FinishRound" in worker
    assert "禁止立刻 FinishRound" in worker
    assert "禁止立刻 FinishRound" in initial
    assert "中途 FinishFile 之后必须继续分析" in worker
    assert "再 FinishRound 并附简短单轮报告" not in worker
    assert "然后 FinishRound" not in initial
    assert "确认没有漏洞" in worker or "确认无漏洞" in worker
    assert "不要因为文件不能当入口就 FinishFile" in initial
    assert "不能当入口" in worker
    assert "没有独立审计价值" not in worker
    assert "没有独立审计价值" not in initial


def test_worker_prompts_inject_recon_and_round_history():
    worker = load_prompt("worker.md")
    initial = load_prompt("initial/worker.md")
    assert "docs/code-map.md" in worker
    assert "docs/auth.md" in worker
    assert "最近最多 10 轮挖掘摘要" in worker
    assert "人工挖掘提示" in worker
    assert "不要重新梳理项目结构" in worker
    assert "不要重复分析项目结构" in initial
    assert "不要重复尝试摘要中已走过的路径" in initial
    assert "不要按历史摘要里的建议改方向" in worker
    assert "不要按历史摘要里的建议改方向" in initial
    assert "不要写「建议后续方向」" in worker
    assert "仅最新一轮" not in worker
    assert "仅最新一轮" not in initial
    assert "templates/round-report.md" in worker
    assert "## 本轮挖掘方向" in worker
    assert "templates/round-report.md" in initial
    assert "AddSourceExt" not in worker
    assert "AddSourceExt" not in initial
    assert "按角色选择挖掘方向" in worker
    assert "当前焦点文件" in initial
    assert "控面" in worker
    assert "回推" in worker
    assert "薄扫" in worker
    assert "WebSocket" in worker


def test_recon_mark_weights_non_http_entries():
    mark = load_prompt("recon-mark.md")
    initial = load_prompt("initial/recon-mark.md")
    recon = load_prompt("recon.md")
    recon_initial = load_prompt("initial/recon.md")
    assert "WebSocket" in mark
    assert "RPC" in mark
    assert "MQ" in mark
    assert "MarkSource" in mark
    assert "不要只标 HTTP" in mark
    assert "70–90" in mark
    assert "40–60" in mark
    assert "10–30" in mark
    assert "WebSocket" in initial
    assert "不要只标 HTTP" in initial
    assert "非 HTTP" in recon
    assert "WebSocket" in recon
    assert "WebSocket" in recon_initial
    assert "不要只标 HTTP" in recon_initial


def test_fast_worker_and_sink_triage_prompts():
    worker = load_prompt("fast_worker.md")
    initial = load_prompt("initial/fast_worker.md")
    triage = load_prompt("sink_triage.md")
    triage_initial = load_prompt("initial/sink_triage.md")
    assert "FinishSink" in worker
    assert "FinishFile" in worker
    assert "不要 FinishFile / FinishRound" in worker
    assert "FinishSink" in initial
    assert "人工挖掘提示" in worker
    assert "FinishSinkTriage" in triage
    assert "禁止读源码" in triage
    assert "FinishSinkTriage" in triage_initial
    assert "不要读文件" in triage_initial


def test_bypass_worker_prompts():
    worker = load_prompt("bypass_worker.md")
    initial = load_prompt("initial/bypass_worker.md")
    assert "FinishBypass" in worker
    assert "人工挖掘提示" in worker
    assert "不要 FinishFile / FinishRound / FinishSink" in worker
    assert "patched" in worker
    assert "unpatched" in worker
    assert "templates/vuln-report-bypass.md" in worker
    assert "### 补丁绕过简析" in worker
    assert "advisory_md" in worker
    assert "FinishBypass" in initial
    assert "${old_vuln_doc}" in initial
    assert "bypass_submitted" in initial
    assert "vuln-report-bypass.md" in initial
    assert "补丁绕过简析" in initial
    assert "简短" not in initial


def test_recon_source_ext_prompt_and_map_does_not_add_ext():
    recon = load_prompt("recon.md")
    initial = load_prompt("initial/recon.md")
    assert "不要 `AddSourceExt`" in recon
    assert "不要 AddSourceExt" in initial
    ext = load_prompt("recon-source-ext.md")
    ext_init = load_prompt("initial/recon-source-ext.md")
    assert "AddSourceExt" in ext
    assert "done=true" in ext
    assert "none=true" in ext
    assert "AddSourceExt" in ext_init


def test_worker_prompt_requires_asset_search_fingerprints():
    worker = load_prompt("worker.md")
    assert "## 互联网资产证明规则" in worker
    assert "FOFA" in worker
    assert "X 情报社区" in worker
    assert "icon_hash" in worker
    assert "docs/app-fingerprints.json" in worker
    assert "不要每条漏洞重新识别" in worker
    assert "docs/lab.md" in worker
    assert "不允许出现「或」" in worker
    assert "templates/vuln-advisory.md" in worker
    assert "advisory_md" in worker
    report = Path(__file__).resolve().parents[2] / "templates" / "vuln-report.md"
    text = report.read_text(encoding="utf-8")
    assert "SSRF 须明确：观察面" in text
    assert "仅响应差别（内网端口探测）" in text
    advisory = Path(__file__).resolve().parents[2] / "templates" / "vuln-advisory.md"
    advisory_text = advisory.read_text(encoding="utf-8")
    assert "## Title" in advisory_text
    assert "### Summary" in advisory_text
    assert "### Details" in advisory_text
    assert "### PoC" in advisory_text
    assert "### Impact" in advisory_text
    assert "## Affected products" in advisory_text
    assert "## Severity / CWE" in advisory_text


def test_pipeline_source_has_no_inline_initial_prompts():
    src = Path(pipeline.__file__).read_text(encoding="utf-8")
    for needle in (
        "请开始代码地图与鉴权文档会话",
        "请开始历史漏洞会话",
        "请根据 docs/code-map.md 检查并追加未入库扩展名",
        "请从该文件出发沿调用链审计",
        "你是 Fix Worker",
        "审核漏洞 ID=",
        "本轮是 Reviewer 的**独立环境搭建轮**",
    ):
        assert needle not in src, needle


def test_reviewer_lab_prompt_is_setup_only(tmp_env, project):
    text = load_prompt("reviewer-lab.md")
    assert "独立一轮" in text
    assert "FinishLab" in text
    assert "ConfirmVuln" in text
    assert "不要搭 Docker" in text or "不是" in text
    assert "${lab_image}" in text
    assert "${lab_container}" in text
    assert "${lab_label_args}" in text
    assert "被测应用必须用最新版本" in text
    assert "vulhub" in text
    initial = load_prompt("initial/reviewer-lab.md")
    assert "FinishLab" in initial
    assert "不要审核漏洞" in initial
    assert "${lab_image}" in initial
    assert "被测应用必须用 src/" in initial
    docker = load_prompt("docker.md")
    assert "do not review vulnerabilities" in docker
    assert "${lab_image}" in docker
    assert "${lab_container}" in docker
    assert "${lab_compose_project}" in docker
    assert "${lab_label_args}" in docker
    assert "vulnhunter.project" in docker
    assert "Audited app = latest" in docker
    assert "vulhub" in docker
    rendered = pipeline._lab_system_prompt(project)
    assert f"demo-{project}:lab" in rendered
    assert f"demo-{project}" in rendered
    assert f"vulnhunter.project={project}" in rendered or f'vulnhunter.project: "{project}"' in rendered
    assert "${lab_image}" not in rendered


def test_verifier_prompt_requires_fofa_and_three_successes():
    text = load_prompt("verifier.md")
    assert "FofaSearch" in text
    assert "FinishVerifier" in text
    assert "10" in text
    assert "3 个" in text
    assert "expand" in text
    assert "poc" in text
    assert "response" in text
    assert "未测" in text
    assert "targets" in text
    assert "共享" in text
    assert "fofa_query" in text
    assert "5 轮" in text
    assert "50" in text
    initial = load_prompt("initial/verifier.md")
    assert "FofaSearch" in initial
    assert "FinishVerifier" in initial
    assert "${fofa_query}" in initial
    assert "${fofa_alts}" in initial
    assert "${fofa_shared}" in initial
    assert "poc=" in initial
    assert "response=" in initial
    assert "targets=" in initial
    assert "fofa_query=" in initial
    assert "未测" in initial
    assert "共享" in initial
    assert "3 个" in initial
    assert "expand=true" in initial
    assert "5 轮" in initial
    assert "50" in initial
    assert "增删改" in text or "禁止" in text
    assert "AskUser" in text
    assert "AskUser" in initial
    assert "app-fingerprints" in text or "项目级" in text or "项目应用指纹" in text
    assert "body=" in text or "body=\"" in text
    assert "各试一条" in text or "另一类" in text


def test_old_vuln_prompt_persist_is_not_completion():
    text = load_prompt("recon-old-vuln.md")
    assert "不要读源码" in text
    assert "fix_status" in text
    assert "patched" in text
    assert "unpatched" in text
    assert "只落盘，不会结束本会话" in text
    assert "WriteOldVuln(done=true)" in text
    assert "ghsa_new.json" in text
    assert "WebSearch" in text
    assert "不要" in text or "禁止" in text
    assert "索引齐全后系统会结束" not in text
    assert "不要收录依赖" in text
    initial = load_prompt("initial/recon-old-vuln.md")
    assert "落盘不会结束本会话" in initial
    assert "WriteOldVuln(done=true" in initial
    assert "ghsa_new.json" in initial
    assert "${ghsa_count}" in initial
    assert "WebSearch" in initial
    assert "不要收录依赖" in initial
    ghsa = load_prompt("recon-old-vuln-ghsa.md")
    assert "WebSearch" in ghsa
    assert "SearchGitHubIssues" in ghsa
    assert "fix_status" in ghsa
    assert "不要读源码" in ghsa
    assert "WriteOldVuln(done=true" in ghsa
    assert "不要收录依赖" in ghsa
    ghsa_initial = load_prompt("initial/recon-old-vuln-ghsa.md")
    assert "WebSearch" in ghsa_initial
    assert "补漏" in ghsa_initial
    assert "WriteOldVuln(done=true" in ghsa_initial
    assert "不要收录依赖" in ghsa_initial
