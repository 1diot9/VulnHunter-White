from __future__ import annotations

import threading
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship, sessionmaker
from sqlalchemy.pool import NullPool

from .config import DB_PATH


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class AppSettings(Base):
    __tablename__ = "app_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    llm_providers: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    llm_roles: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    worker_concurrency: Mapped[int] = mapped_column(Integer, default=1)
    fix_concurrency: Mapped[int] = mapped_column(Integer, default=1)
    llm_thread_limit: Mapped[int] = mapped_column(Integer, default=6)
    github_pat: Mapped[str | None] = mapped_column(Text, nullable=True)
    fofa_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    fofa_base_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    default_base_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    default_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    context_window: Mapped[int] = mapped_column(Integer, default=128000)
    http_proxy: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    chat_proxy: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    cli_tools_dir: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    jadx_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # SHA-256 hex of the global access token. None = fall back to VULNHUNTER_ACCESS_TOKEN.
    access_token_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class CustomAuditMode(Base):
    """Named global custom audit-mode prompts (settings library)."""

    __tablename__ = "custom_audit_modes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(512), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), default="zip")  # github | zip
    source_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    identity: Mapped[str | None] = mapped_column(String(512), nullable=True)  # owner/repo or pkg
    status: Mapped[str] = mapped_column(String(64), default="pending")
    # pending | ingesting | recon | auditing | reviewing | paused | completed | error | cancelled
    phase: Mapped[str] = mapped_column(String(64), default="pending")
    # pending | recon | worker | reviewer | verifier | attack_chain | done
    recon_done: Mapped[bool] = mapped_column(Boolean, default=False)
    # bounty | full | custom — set at create time; change only while paused or completed
    audit_mode: Mapped[str] = mapped_column(String(32), default="bounty")
    # web | library | mixed — audit object profile; orthogonal to audit_mode / mining paths
    target_kind: Mapped[str] = mapped_column(String(32), default="web")
    # custom 模式：绑定全局预设 id（删库校验）+ 切换时快照名称/正文
    custom_audit_mode_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    custom_audit_mode_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    custom_audit_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 人工靶场：跳过 Docker 环境轮，审核时注入用户提供的环境说明
    manual_lab: Mapped[bool] = mapped_column(Boolean, default=False)
    manual_lab_prompt: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Verifier：Reviewer 确认前台洞后用 FOFA 搜同款目标并复测；默认关闭
    verifier_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # 攻击链串联：挖掘+审核结束后根据已确认漏洞尝试多步串联；默认关闭
    attack_chain_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # 攻击链阶段是否已跑完（含 <2 条已确认时跳过）
    attack_chain_done: Mapped[bool] = mapped_column(Boolean, default=False)
    # Reviewer 动态验证（Docker 靶场 / 先 HTTP PoC，PoC 不可用再 debug MCP）；默认关闭，仅静态复核
    dynamic_verify_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # off | lab | harness — 与 dynamic_verify_enabled 同步；旧库仅有布尔时 enabled=true 视为 lab
    dynamic_verify_mode: Mapped[str] = mapped_column(String(32), default="off")
    # 挖掘路径：启发式按文件 / 快速按 Sink / 历史漏洞绕过；至少开一条
    heuristic_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    # 启发式轻量：仅权重 100 的文件作为 Worker 入口
    heuristic_lite: Mapped[bool] = mapped_column(Boolean, default=False)
    fast_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    fast_queue_frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    # 历史漏洞绕过：收集完毕后按文档逐条尝试绕过
    bypass_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    bypass_queue_frozen: Mapped[bool] = mapped_column(Boolean, default=False)
    # 无约束扫描：不注入权重，自主挖前台洞；Reviewer 判定达成 RCE 效果后结束
    unconstrained_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    unconstrained_done: Mapped[bool] = mapped_column(Boolean, default=False)
    # 项目级模型；空则使用设置页全局 default_model
    llm_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # 挖掘 Worker 额外人工提示：注入启发式 / 快速扫描 / 历史漏洞绕过每轮用户消息
    worker_hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Recon 额外人工提示：注入侦察各小阶段每轮用户消息
    recon_hint: Mapped[str | None] = mapped_column(Text, nullable=True)
    # 项目 Token 上限（输入+输出合计）；0 = 不限制，到达后自动暂停
    max_token_usage: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_concurrency: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    files: Mapped[list[FileWeight]] = relationship(back_populates="project", cascade="all, delete-orphan")
    sources: Mapped[list[Source]] = relationship(back_populates="project", cascade="all, delete-orphan")
    sinks: Mapped[list["Sink"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    bypass_targets: Mapped[list["BypassTarget"]] = relationship(back_populates="project", cascade="all, delete-orphan")
    vulns: Mapped[list[Vuln]] = relationship(back_populates="project", cascade="all, delete-orphan")
    attack_chains: Mapped[list["AttackChain"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    phase_runs: Mapped[list[PhaseRun]] = relationship(back_populates="project", cascade="all, delete-orphan")


class FileWeight(Base):
    __tablename__ = "file_weights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)
    weight: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = unmarked
    skipped: Mapped[bool] = mapped_column(Boolean, default=False)
    audited: Mapped[bool] = mapped_column(Boolean, default=False)
    claimed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    audit_attempts: Mapped[int] = mapped_column(Integer, default=0)
    has_source: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    project: Mapped[Project] = relationship(back_populates="files")


class Source(Base):
    __tablename__ = "sources"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    method_name: Mapped[str] = mapped_column(String(512), nullable=False)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    project: Mapped[Project] = relationship(back_populates="sources")


class Sink(Base):
    __tablename__ = "sinks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    line_start: Mapped[int] = mapped_column(Integer, default=0)
    line_end: Mapped[int] = mapped_column(Integer, default=0)
    check_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(32), default="WARNING")
    confidence: Mapped[str] = mapped_column(String(32), default="MEDIUM")
    mapped_vuln_type: Mapped[str] = mapped_column(String(64), default="other")
    code_score: Mapped[int] = mapped_column(Integer, default=0)
    # candidate | queued | claimed | done | dropped_agent
    status: Mapped[str] = mapped_column(String(32), default="candidate", index=True)
    # pending | vuln_submitted | unreachable | sanitized | intended | noise
    verdict: Mapped[str] = mapped_column(String(32), default="pending")
    claimed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_decision: Mapped[str | None] = mapped_column(String(16), nullable=True)  # keep|drop|defer
    agent_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    vuln_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    project: Mapped[Project] = relationship(back_populates="sinks")


class BypassTarget(Base):
    __tablename__ = "bypass_targets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    file_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fix_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    source: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # queued | claimed | done
    status: Mapped[str] = mapped_column(String(32), default="queued", index=True)
    # pending | bypass_submitted | still_patched | unreachable | incomplete | intended
    verdict: Mapped[str] = mapped_column(String(32), default="pending")
    claimed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    agent_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    vuln_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    project: Mapped[Project] = relationship(back_populates="bypass_targets")


class Vuln(Base):
    __tablename__ = "vulns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(64), default="other")
    severity: Mapped[str] = mapped_column(String(32), default="low")
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # 旧四维校准整数分；新确认写入 cvss_score
    cvss_vector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # CVSS:3.1/AV:... 基础向量，ConfirmVuln 写入
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    # CVSS 3.1 基础分 0.0–10.0，由向量自动计算
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_no: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_sink: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_premise: Mapped[str | None] = mapped_column(Text, nullable=True)
    # default | specific — 默认配置 / 特定配置（官方已警示的风险配置不算 specific）
    config_premise: Mapped[str | None] = mapped_column(String(32), nullable=True)
    http_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    intended_behavior: Mapped[bool] = mapped_column(Boolean, default=False)
    # pending_review | returned | confirmed | false_positive | static_only | merged
    status: Mapped[str] = mapped_column(String(64), default="pending_review")
    # none | submitted | ignored — 用户对产出的提交跟踪，与审核 status 独立
    tracking_status: Mapped[str] = mapped_column(String(32), default="none")
    evidence_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # dynamic | static_only | mcp | harness
    harness_depth: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # sink | module | integration — per-vuln harness tier; L3 success → evidence dynamic
    integration_runtime: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # sandbox | host_fallback — how L3 integration verify ran
    attack_surface: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # frontend | backend — Reviewer 确认时标注
    required_account: Mapped[str | None] = mapped_column(String(32), nullable=True)
    exposure_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # direct | indirect_consumer — 组件无直接攻击面、依赖上游应用传入输入
    upstream_chain_proven: Mapped[bool] = mapped_column(Boolean, default=False)
    # user | admin — 仅后台漏洞需要
    submission_tier: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # cve_candidate | low_impact | duplicate_grouped
    submission_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # heuristic | fast | bypass | unconstrained — SubmitVuln 时按 Worker 角色写入
    mining_path: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # Reviewer：本条是否达成前台 RCE 效果（无约束扫描结束条件由 Reviewer 判定）
    rce_effect: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    root_cause_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # 同根因合并键，如 idor:SysCommentController / ssrf:checkSsrfHttpUrl
    merged_into_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # status=merged 时指向主报告 id
    review_rounds: Mapped[int] = mapped_column(Integer, default=0)
    # Consecutive Reviewer timeouts; >= before_static forces static retry; >= before_static+1 give up as FP.
    review_timeout_streak: Mapped[int] = mapped_column(Integer, default=0)
    return_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    # timeout — system closed after review timeouts; empty/null — Reviewer MarkFalsePositive
    fp_kind: Mapped[str | None] = mapped_column(String(32), nullable=True)
    report_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # none | pending | awaiting_user | verified | failed | skipped — Verifier 互联网复测
    verifier_status: Mapped[str] = mapped_column(String(32), default="none")
    verifier_verified_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    verifier_poc: Mapped[str | None] = mapped_column(Text, nullable=True)
    verifier_response: Mapped[str | None] = mapped_column(Text, nullable=True)
    verifier_targets: Mapped[str | None] = mapped_column(Text, nullable=True)
    verifier_fofa_query: Mapped[str | None] = mapped_column(Text, nullable=True)
    # AskUser 挂起时的危害说明；用户继续后的自定义指示；是否已同意打互联网目标
    verifier_ask_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    verifier_user_instruction: Mapped[str | None] = mapped_column(Text, nullable=True)
    verifier_consent: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    project: Mapped[Project] = relationship(back_populates="vulns")


class AttackChain(Base):
    """Multi-vuln exploit chain produced after mining + review."""

    __tablename__ = "attack_chains"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    # JSON list of vuln ids in chain order
    vuln_ids: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # static | verified | skipped_interaction — lab dynamic verify outcome for detailed chains
    verify_status: Mapped[str] = mapped_column(String(32), default="static")
    # Relative path to chain.py when dynamically verified (or written then skipped)
    script_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    project: Mapped[Project] = relationship(back_populates="attack_chains")


class PhaseRun(Base):
    __tablename__ = "phase_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    phase: Mapped[str] = mapped_column(String(64), nullable=False)
    # recon | worker | reviewer | reviewer-lab | verifier | attack_chain | fix
    role: Mapped[str] = mapped_column(String(64), default="worker")
    status: Mapped[str] = mapped_column(String(64), default="running")
    # running | completed | failed | cancelled | paused | awaiting_user
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    vuln_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    tokens_input: Mapped[int] = mapped_column(Integer, default=0)
    tokens_output: Mapped[int] = mapped_column(Integer, default=0)
    tokens_cached: Mapped[int] = mapped_column(Integer, default=0)
    tokens_total: Mapped[int] = mapped_column(Integer, default=0)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    project: Mapped[Project] = relationship(back_populates="phase_runs")


class ToolLog(Base):
    __tablename__ = "tool_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    phase_run_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    tool_name: Mapped[str] = mapped_column(String(128), nullable=False)
    role: Mapped[str] = mapped_column(String(64), default="")
    input_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    output_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_class: Mapped[str | None] = mapped_column(String(32), nullable=True)  # local | call | null
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class TokenUsage(Base):
    __tablename__ = "token_usages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    phase: Mapped[str] = mapped_column(String(64), nullable=False)
    role: Mapped[str] = mapped_column(String(64), default="")
    tokens_input: Mapped[int] = mapped_column(Integer, default=0)
    tokens_output: Mapped[int] = mapped_column(Integer, default=0)
    tokens_cached: Mapped[int] = mapped_column(Integer, default=0)
    tokens_total: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class GithubCandidate(Base):
    """Repos discovered from public GHSA for potential audit projects."""

    __tablename__ = "github_candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    full_name: Mapped[str] = mapped_column(String(512), nullable=False, unique=True, index=True)
    html_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    language: Mapped[str | None] = mapped_column(String(128), nullable=True)
    stars: Mapped[int] = mapped_column(Integer, default=0)
    pushed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    target_kind: Mapped[str] = mapped_column(String(32), default="web")
    target_kind_reason: Mapped[str | None] = mapped_column(String(512), nullable=True)
    advisory_count: Mapped[int] = mapped_column(Integer, default=1)
    latest_ghsa_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latest_ghsa_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    # eligible | skipped | imported | dismissed
    status: Mapped[str] = mapped_column(String(32), default="eligible", index=True)
    project_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    skip_reason: Mapped[str | None] = mapped_column(String(256), nullable=True)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


REQUIRED_TABLES = (
    "app_settings",
    "custom_audit_modes",
    "projects",
    "file_weights",
    "sources",
    "sinks",
    "bypass_targets",
    "vulns",
    "phase_runs",
    "tool_logs",
    "token_usages",
    "github_candidates",
)

SQLITE_BUSY_TIMEOUT_MS = 30000
_schema_lock = threading.Lock()

# Windows: use forward slashes so sqlite3 does not mis-parse drive paths.
# NullPool: check_same_thread=False otherwise selects QueuePool(5+10). Nested
# SessionLocal (stale-claim release, ensure_schema inspect+begin) then deadlocks
# the pool — /api/projects hangs while in-memory routes like llm-threads still work.
engine = create_engine(
    f"sqlite:///{DB_PATH.resolve().as_posix()}",
    connect_args={
        "check_same_thread": False,
        "timeout": SQLITE_BUSY_TIMEOUT_MS / 1000,
    },
    poolclass=NullPool,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


@event.listens_for(engine, "connect")
def _set_sqlite_pragmas(dbapi_connection, _connection_record) -> None:
    cursor = dbapi_connection.cursor()
    try:
        cursor.execute(f"PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS}")
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA synchronous=NORMAL")
    finally:
        cursor.close()


def _ensure_columns() -> None:
    """SQLite create_all 不会给已有表加列。"""
    insp = inspect(engine)
    wanted = {
        "app_settings": {
            "fix_concurrency": "INTEGER DEFAULT 1",
            "llm_thread_limit": "INTEGER DEFAULT 6",
            "fofa_key": "TEXT",
            "fofa_base_url": "VARCHAR(1024)",
            "http_proxy": "VARCHAR(1024)",
            "chat_proxy": "VARCHAR(1024)",
            "cli_tools_dir": "VARCHAR(1024)",
            "jadx_path": "VARCHAR(1024)",
            "access_token_hash": "TEXT",
        },
        "file_weights": {
            "claimed_at": "DATETIME",
            "audit_attempts": "INTEGER DEFAULT 0",
        },
        "tool_logs": {"error_class": "VARCHAR(32)"},
        "phase_runs": {"file_path": "VARCHAR(1024)"},
        "projects": {
            "audit_mode": "VARCHAR(32) DEFAULT 'bounty'",
            "target_kind": "VARCHAR(32) DEFAULT 'web'",
            "custom_audit_mode_id": "INTEGER",
            "custom_audit_mode_name": "VARCHAR(128)",
            "custom_audit_prompt": "TEXT",
            "manual_lab": "BOOLEAN DEFAULT 0",
            "manual_lab_prompt": "TEXT",
            "verifier_enabled": "BOOLEAN DEFAULT 0",
            "attack_chain_enabled": "BOOLEAN DEFAULT 0",
            "attack_chain_done": "BOOLEAN DEFAULT 0",
            "dynamic_verify_enabled": "BOOLEAN DEFAULT 0",
            "dynamic_verify_mode": "VARCHAR(32) DEFAULT 'off'",
            "heuristic_enabled": "BOOLEAN DEFAULT 1",
            "heuristic_lite": "BOOLEAN DEFAULT 0",
            "fast_enabled": "BOOLEAN DEFAULT 0",
            "fast_queue_frozen": "BOOLEAN DEFAULT 0",
            "bypass_enabled": "BOOLEAN DEFAULT 0",
            "bypass_queue_frozen": "BOOLEAN DEFAULT 0",
            "unconstrained_enabled": "BOOLEAN DEFAULT 0",
            "unconstrained_done": "BOOLEAN DEFAULT 0",
            "llm_model": "VARCHAR(256)",
            "worker_hint": "TEXT",
            "recon_hint": "TEXT",
            "max_token_usage": "INTEGER DEFAULT 0",
        },
        "vulns": {
            "attack_surface": "VARCHAR(32)",
            "required_account": "VARCHAR(32)",
            "exposure_mode": "VARCHAR(32)",
            "upstream_chain_proven": "BOOLEAN DEFAULT 0",
            "severity_score": "INTEGER",
            "cvss_vector": "VARCHAR(128)",
            "cvss_score": "REAL",
            "submission_tier": "VARCHAR(64)",
            "submission_reason": "TEXT",
            "mining_path": "VARCHAR(32)",
            "rce_effect": "BOOLEAN",
            "config_premise": "VARCHAR(32)",
            "root_cause_key": "VARCHAR(256)",
            "merged_into_id": "INTEGER",
            "review_timeout_streak": "INTEGER DEFAULT 0",
            "fp_kind": "VARCHAR(32)",
            "tracking_status": "VARCHAR(32) DEFAULT 'none'",
            "verifier_status": "VARCHAR(32) DEFAULT 'none'",
            "verifier_verified_url": "VARCHAR(1024)",
            "verifier_poc": "TEXT",
            "verifier_response": "TEXT",
            "verifier_targets": "TEXT",
            "verifier_fofa_query": "TEXT",
            "verifier_ask_reason": "TEXT",
            "verifier_user_instruction": "TEXT",
            "verifier_consent": "BOOLEAN DEFAULT 0",
            "harness_depth": "VARCHAR(32)",
            "integration_runtime": "VARCHAR(32)",
        },
        "attack_chains": {
            "verify_status": "VARCHAR(32) DEFAULT 'static'",
            "script_path": "VARCHAR(1024)",
        },
    }
    with engine.begin() as conn:
        for table, cols in wanted.items():
            if table not in insp.get_table_names():
                continue
            existing = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))


def _migrate_submission_tiers() -> None:
    """Fold legacy hardening/advisory_only/needs_more_evidence rows into value tiers."""
    insp = inspect(engine)
    if "vulns" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("vulns")}
    if "submission_tier" not in existing:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE vulns SET submission_tier = 'low_impact' "
                "WHERE submission_tier IN ('hardening', 'advisory_only')"
            )
        )
        conn.execute(
            text(
                "UPDATE vulns SET submission_tier = 'cve_candidate' "
                "WHERE submission_tier = 'needs_more_evidence' "
                "AND COALESCE(severity_score, 0) >= 3"
            )
        )
        conn.execute(
            text(
                "UPDATE vulns SET submission_tier = 'low_impact' "
                "WHERE submission_tier = 'needs_more_evidence'"
            )
        )


def _backfill_tracking_status() -> None:
    insp = inspect(engine)
    if "vulns" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("vulns")}
    if "tracking_status" not in existing:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE vulns SET tracking_status = 'none' "
                "WHERE tracking_status IS NULL OR tracking_status = ''"
            )
        )


def _backfill_dynamic_verify_mode() -> None:
    insp = inspect(engine)
    if "projects" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("projects")}
    if "dynamic_verify_mode" not in existing:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE projects SET dynamic_verify_mode = 'lab' "
                "WHERE COALESCE(dynamic_verify_enabled, 0) = 1 "
                "AND COALESCE(dynamic_verify_mode, 'off') IN ('', 'off')"
            )
        )
        conn.execute(
            text(
                "UPDATE projects SET dynamic_verify_mode = 'off' "
                "WHERE COALESCE(dynamic_verify_enabled, 0) = 0 "
                "AND (dynamic_verify_mode IS NULL OR dynamic_verify_mode = '')"
            )
        )


def _backfill_verifier_status() -> None:
    insp = inspect(engine)
    if "vulns" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("vulns")}
    if "verifier_status" not in existing:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE vulns SET verifier_status = 'none' "
                "WHERE verifier_status IS NULL OR verifier_status = ''"
            )
        )


def _backfill_parent_root_cause_keys() -> None:
    """Copy duplicate_grouped keys onto matching parents that were confirmed without one."""
    insp = inspect(engine)
    if "vulns" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("vulns")}
    if "root_cause_key" not in existing or "submission_tier" not in existing:
        return
    from .services.root_cause import backfill_parent_root_cause_keys

    with SessionLocal() as db:
        if backfill_parent_root_cause_keys(db):
            db.commit()


def _backfill_fp_kind_timeout() -> None:
    """Label existing timeout give-ups so the UI can show 误报-审核超时."""
    insp = inspect(engine)
    if "vulns" not in insp.get_table_names():
        return
    existing = {c["name"] for c in insp.get_columns("vulns")}
    if "fp_kind" not in existing:
        return
    with engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE vulns SET fp_kind = 'timeout' "
                "WHERE status = 'false_positive' "
                "AND COALESCE(fp_kind, '') = '' "
                "AND return_reason LIKE '%审核连续超时%'"
            )
        )


def ensure_schema() -> None:
    """Idempotent: create missing tables/columns. Safe to call from worker threads."""
    with _schema_lock:
        DATA_DIR = DB_PATH.parent
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        Base.metadata.create_all(bind=engine)
        _ensure_columns()
        _migrate_submission_tiers()
        _backfill_tracking_status()
        _backfill_verifier_status()
        _backfill_dynamic_verify_mode()
        _backfill_parent_root_cause_keys()
        _backfill_fp_kind_timeout()
        existing = set(inspect(engine).get_table_names())
        missing = [t for t in REQUIRED_TABLES if t not in existing]
        if missing:
            # Retry once after create_all — handles rare SQLite lock races.
            Base.metadata.create_all(bind=engine)
            existing = set(inspect(engine).get_table_names())
            missing = [t for t in REQUIRED_TABLES if t not in existing]
            if missing:
                raise RuntimeError(f"数据库缺少表: {', '.join(missing)}（路径 {DB_PATH}）")


def init_db() -> None:
    ensure_schema()
    with SessionLocal() as db:
        if db.query(AppSettings).first() is None:
            db.add(AppSettings())
            db.commit()
    # Showcase project rows for the bundled data/projects/11 workspace.
    # Imported after schema + settings so a fresh clone can list the demo in the UI.
    try:
        from .services.demo_seed import seed_bundled_demo_project

        seed_bundled_demo_project()
    except Exception:
        # Never block startup on a bad/missing showcase bundle.
        import logging

        logging.getLogger("vulnhunter.demo_seed").exception("demo seed failed")
