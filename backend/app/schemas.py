from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class LlmProviderIn(BaseModel):
    id: str
    name: str = ""
    base_url: str = ""
    wire_api: str = "chat"
    env_key: str = "OPENAI_API_KEY"
    api_key: str | None = None


class LlmProviderOut(BaseModel):
    id: str
    name: str
    base_url: str
    wire_api: str
    env_key: str
    api_key_set: bool = False


class LlmRoleAssignment(BaseModel):
    provider_id: str = ""
    model: str = ""
    reasoning_effort: str = ""


class SettingsOut(BaseModel):
    llm_providers: list[LlmProviderOut] = Field(default_factory=list)
    llm_roles: dict[str, LlmRoleAssignment] = Field(default_factory=dict)
    llm_thread_limit: int = 6
    github_pat_set: bool = False
    fofa_key_set: bool = False
    fofa_base_url: str = "https://fofa.info"
    default_model: str = ""
    default_base_url: str = ""
    default_api_key_set: bool = False
    context_window: int = 128000


class SettingsUpdate(BaseModel):
    llm_providers: list[LlmProviderIn] | None = None
    llm_roles: dict[str, LlmRoleAssignment] | None = None
    llm_thread_limit: int | None = None
    github_pat: str | None = None
    fofa_key: str | None = None
    fofa_base_url: str | None = None
    default_model: str | None = None
    default_base_url: str | None = None
    default_api_key: str | None = None
    context_window: int | None = None


class LlmProbeIn(BaseModel):
    """Unsaved form values for listing models / connectivity test."""

    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None


class LlmModelListOut(BaseModel):
    ok: bool
    models: list[str] = Field(default_factory=list)
    count: int = 0
    latency_ms: int | None = None
    error: str | None = None


class LlmTestOut(BaseModel):
    ok: bool
    model: str = ""
    latency_ms: int | None = None
    error: str | None = None
    reply: str | None = None


class FofaProbeIn(BaseModel):
    """Unsaved form values for FOFA connectivity test."""

    key: str | None = None
    base_url: str | None = None


class FofaTestOut(BaseModel):
    ok: bool
    latency_ms: int | None = None
    username: str = ""
    fcoin: int | None = None  # FOFA F点（info/my 的 fofa_point，不是旧币 fcoin）
    isvip: bool | None = None
    error: str | None = None
    account_error: bool = False


class LiveLogPurgeIn(BaseModel):
    older_than_days: int = Field(ge=0, le=3650)


class LiveLogPurgeOut(BaseModel):
    ok: bool = True
    older_than_days: int
    projects: int = 0
    files: int = 0
    bytes: int = 0


MANUAL_LAB_PROMPT_MAX = 20000


def normalize_manual_lab_prompt(raw: Any) -> str:
    text = str(raw or "").strip()
    if len(text) > MANUAL_LAB_PROMPT_MAX:
        raise ValueError(f"人工靶场说明过长，最多 {MANUAL_LAB_PROMPT_MAX} 字")
    return text


class ProjectCreate(BaseModel):
    name: str = ""
    source_type: Literal["github", "zip"] = "github"
    source_url: str | None = None
    audit_mode: Literal["bounty", "full"] = "bounty"
    manual_lab: bool = False
    manual_lab_prompt: str = Field(default="", max_length=MANUAL_LAB_PROMPT_MAX)
    verifier_enabled: bool = False


class ProjectUpdate(BaseModel):
    audit_mode: Literal["bounty", "full"] | None = None
    manual_lab: bool | None = None
    manual_lab_prompt: str | None = Field(default=None, max_length=MANUAL_LAB_PROMPT_MAX)
    verifier_enabled: bool | None = None


class ProjectOut(BaseModel):
    id: int
    name: str
    source_type: str
    source_url: str | None = None
    identity: str | None = None
    status: str
    phase: str
    recon_done: bool
    audit_mode: str = "bounty"
    manual_lab: bool = False
    manual_lab_prompt: str = ""
    verifier_enabled: bool = False
    error: str | None = None
    worker_concurrency: int | None = None
    created_at: datetime
    updated_at: datetime
    vuln_confirmed: int = 0
    vuln_false_positive: int = 0
    vuln_pending: int = 0
    files_total: int = 0
    files_weighted: int = 0
    files_skipped: int = 0
    files_audited: int = 0
    worker_rounds: int = 0
    tokens_input: int = 0
    tokens_output: int = 0
    tokens_cached: int = 0
    tokens_total: int = 0
    phase_states: dict[str, Any] = Field(default_factory=dict)
    project_paused: bool = False
    recon_subphases: list[dict[str, Any]] = Field(default_factory=list)
    lab_setup_done: bool = False
    verifier_pending: int = 0

    model_config = {"from_attributes": True}


class VulnOut(BaseModel):
    id: int
    project_id: int
    project_name: str = ""
    title: str
    vuln_type: str
    severity: str
    severity_score: int | None = None
    cwe: str | None = None
    file_path: str | None = None
    line_no: int | None = None
    status: str
    tracking_status: str = "none"
    evidence_level: str | None = None
    attack_surface: str | None = None
    required_account: str | None = None
    submission_tier: str | None = None
    submission_reason: str | None = None
    root_cause_key: str | None = None
    merged_into_id: int | None = None
    review_rounds: int = 0
    return_reason: str | None = None
    intended_behavior: bool = False
    report_path: str | None = None
    verifier_status: str = "none"
    verifier_verified_url: str | None = None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class VulnDetail(VulnOut):
    source_sink: str | None = None
    auth_premise: str | None = None
    http_request: str | None = None
    poc_code: str | None = None
    expected_evidence: str | None = None
    report_md: str | None = None
    merged_from_ids: list[int] = Field(default_factory=list)
    verifier_poc: str | None = None
    verifier_response: str | None = None
    verifier_targets: list[dict[str, Any]] = Field(default_factory=list)
    verifier_fofa_query: str | None = None


class VulnTrackingIn(BaseModel):
    tracking_status: Literal["none", "submitted", "ignored"]


class VulnTrackingBatchIn(BaseModel):
    ids: list[int] = Field(min_length=1)
    tracking_status: Literal["none", "submitted", "ignored"]


class VulnFollowUpIn(BaseModel):
    question: str = Field(min_length=1, max_length=20000)


class VulnFollowUpMessage(BaseModel):
    id: str
    role: Literal["user", "assistant"]
    content: str
    created_at: str
    reviewer_phase_run_id: int | None = None


class VulnFollowUpThread(BaseModel):
    vuln_id: int
    project_id: int
    reviewer_phase_run_id: int | None = None
    reviewer_context_available: bool = False
    messages: list[VulnFollowUpMessage] = Field(default_factory=list)


class PhaseRunOut(BaseModel):
    id: int
    project_id: int
    phase: str
    role: str
    status: str
    worker_id: str | None = None
    vuln_id: int | None = None
    error: str | None = None
    tokens_input: int = 0
    tokens_output: int = 0
    tokens_cached: int = 0
    tokens_total: int = 0
    started_at: datetime
    finished_at: datetime | None = None

    model_config = {"from_attributes": True}


class FileWeightOut(BaseModel):
    id: int
    path: str
    weight: int | None = None
    skipped: bool = False
    audited: bool = False
    has_source: bool = False
    claimed_by: str | None = None
    audit_attempts: int = 0

    model_config = {"from_attributes": True}


class LogEvent(BaseModel):
    kind: str
    text: str | None = None
    ts: str | None = None
    source: str | None = None
    command: str | None = None
    output: str | None = None
    exit_code: int | None = None
    input: int | None = None
    output_tokens: int | None = None
    cached: int | None = None
    total: int | None = None
    phase: str | None = None
    phase_label: str | None = None
    tool: str | None = None
    role: str | None = None
    traceback: str | None = None
    duration_ms: float | None = None
    phase_run_id: int | None = None
    session: int | None = None
    session_start: bool | None = None


class EventsChunk(BaseModel):
    events: list[dict[str, Any]]
    offset: int
    done: bool = False
    oldest: int = 0
    has_older: bool = False
    total: int = 0
    file_end: int = 0
    session: int = 1
    session_count: int = 1


class PhaseReportItem(BaseModel):
    id: str
    phase: str
    phase_label: str
    subphase: str
    subphase_label: str
    kind: str
    kind_label: str
    round: int | None = None
    title: str
    preview: str = ""
    mtime: str
    size: int = 0


class PhaseReportGroup(BaseModel):
    phase: str
    label: str
    count: int = 0
    reports: list[PhaseReportItem] = Field(default_factory=list)


class PhaseReportList(BaseModel):
    phases: list[PhaseReportGroup] = Field(default_factory=list)
    count: int = 0


class PhaseReportDetail(PhaseReportItem):
    content: str = ""
