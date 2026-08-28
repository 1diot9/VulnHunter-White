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
    endpoints: list["LlmPoolEndpointIn"] | None = None


class LlmProviderOut(BaseModel):
    id: str
    name: str
    base_url: str
    wire_api: str
    env_key: str
    api_key_set: bool = False
    endpoints: list["LlmPoolEndpointOut"] = Field(default_factory=list)


class LlmPoolEndpointIn(BaseModel):
    id: str = ""
    base_url: str = ""
    api_key: str | None = None
    model: str = ""
    max_inflight: int = 6


class LlmPoolEndpointOut(BaseModel):
    id: str
    base_url: str
    api_key_set: bool = False
    model: str = ""
    max_inflight: int = 6


class LlmRoleAssignment(BaseModel):
    provider_id: str = ""
    model: str = ""
    reasoning_effort: str = ""


class SettingsOut(BaseModel):
    llm_providers: list[LlmProviderOut] = Field(default_factory=list)
    llm_roles: dict[str, LlmRoleAssignment] = Field(default_factory=dict)
    llm_endpoints: list[LlmPoolEndpointOut] = Field(default_factory=list)
    llm_thread_limit: int = 6
    github_pat_set: bool = False
    fofa_key_set: bool = False
    fofa_base_url: str = "https://fofa.info"
    default_model: str = ""
    default_base_url: str = ""
    default_api_key_set: bool = False
    context_window: int = 128000
    http_proxy: str = ""
    chat_proxy: str = ""
    cli_tools_dir: str = "tools/cli"
    jadx_path: str = ""
    access_token_set: bool = False


class LlmEndpointUsageOut(BaseModel):
    id: str
    base_url: str = ""
    used: int = 0
    limit: int = 6
    cooldown_sec: float = 0.0
    last_error: str = ""
    error_kind: str = ""
    disabled: bool = False


class LlmThreadUsageOut(BaseModel):
    used: int = 0
    limit: int = 6
    waiting: int = 0
    endpoints: list[LlmEndpointUsageOut] = Field(default_factory=list)


class SettingsUpdate(BaseModel):
    llm_providers: list[LlmProviderIn] | None = None
    llm_roles: dict[str, LlmRoleAssignment] | None = None
    llm_endpoints: list[LlmPoolEndpointIn] | None = None
    llm_thread_limit: int | None = None
    github_pat: str | None = None
    fofa_key: str | None = None
    fofa_base_url: str | None = None
    default_model: str | None = None
    default_base_url: str | None = None
    default_api_key: str | None = None
    context_window: int | None = None
    http_proxy: str | None = None
    chat_proxy: str | None = None
    cli_tools_dir: str | None = None
    jadx_path: str | None = None


class AccessTokenUpdate(BaseModel):
    current_token: str = ""
    new_token: str = ""


class AuthStatusOut(BaseModel):
    ok: bool = True
    required: bool = False


class AuthLoginIn(BaseModel):
    token: str = ""


class AuthLoginOut(BaseModel):
    ok: bool
    required: bool = False


class LlmProbeIn(BaseModel):
    """Unsaved form values for listing models / connectivity test."""

    endpoint_id: str | None = None
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
    wire_api: str | None = None


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


class GithubProbeIn(BaseModel):
    """Unsaved form values for GitHub connectivity test."""

    github_pat: str | None = None
    http_proxy: str | None = None  # None = saved/env proxy; "" = direct


class GithubTestOut(BaseModel):
    ok: bool
    latency_ms: int | None = None
    authenticated: bool = False
    login: str = ""
    rate_limit: int | None = None
    rate_remaining: int | None = None
    error: str | None = None


class JadxProbeIn(BaseModel):
    """Unsaved form values for jadx detection."""

    jadx_path: str | None = None  # None = use saved/env/PATH; "" same


class JadxTestOut(BaseModel):
    ok: bool
    path: str = ""
    version: str = ""
    latency_ms: int | None = None
    error: str | None = None


class LiveLogPurgeIn(BaseModel):
    older_than_days: int = Field(ge=0, le=3650)


class LiveLogPurgeOut(BaseModel):
    ok: bool = True
    older_than_days: int
    projects: int = 0
    files: int = 0
    bytes: int = 0


MANUAL_LAB_PROMPT_MAX = 20000
WORKER_HINT_MAX = 20000


def normalize_manual_lab_prompt(raw: Any) -> str:
    text = str(raw or "").strip()
    if len(text) > MANUAL_LAB_PROMPT_MAX:
        raise ValueError(f"人工靶场说明过长，最多 {MANUAL_LAB_PROMPT_MAX} 字")
    return text


def normalize_worker_hint(raw: Any) -> str:
    text = str(raw or "").strip()
    if "\x00" in text:
        raise ValueError("挖掘提示必须是文本，不能包含空字节")
    if len(text) > WORKER_HINT_MAX:
        raise ValueError(f"挖掘提示过长，最多 {WORKER_HINT_MAX} 字")
    return text


def normalize_lab_retry_message(raw: Any) -> str:
    text = str(raw or "").strip()
    if "\x00" in text:
        raise ValueError("续跑说明必须是文本，不能包含空字节")
    if len(text) > WORKER_HINT_MAX:
        raise ValueError(f"续跑说明过长，最多 {WORKER_HINT_MAX} 字")
    return text


def normalize_conversation_message(raw: Any) -> str:
    text = str(raw or "").strip()
    if "\x00" in text:
        raise ValueError("消息必须是文本，不能包含空字节")
    if len(text) > WORKER_HINT_MAX:
        raise ValueError(f"消息过长，最多 {WORKER_HINT_MAX} 字")
    return text


class ConversationBody(BaseModel):
    log_phase: str = Field(..., min_length=1, max_length=64)
    action: Literal["steer", "continue", "new"]
    message: str = Field(default="", max_length=WORKER_HINT_MAX)


class ConversationStateOut(BaseModel):
    log_phase: str
    running: bool
    can_continue: bool
    can_new: bool
    can_steer: bool
    has_archived: bool
    latest_session: int = 1


class LabSetupRetryBody(BaseModel):
    user_message: str = Field(default="", max_length=WORKER_HINT_MAX)


class ProjectLabOut(BaseModel):
    ok: bool = True
    has_env: bool = False
    can_start: bool = False
    can_stop: bool = False
    status: str = "absent"
    target_url: str | None = None
    host_port: int | None = None
    jdwp_host_port: int | None = None
    inspect_host_port: int | None = None
    debugpy_host_port: int | None = None
    container_name: str | None = None
    container_id: str | None = None
    image: str | None = None
    runtime: str | None = None
    ports_remapped: bool = False
    port_changes: list[str] = Field(default_factory=list)
    port_conflicts: list[int] = Field(default_factory=list)
    error: str | None = None


class ProjectLabPatch(BaseModel):
    host_port: int | None = Field(default=None, ge=1, le=65535)
    jdwp_host_port: int | None = Field(default=None, ge=1, le=65535)
    inspect_host_port: int | None = Field(default=None, ge=1, le=65535)
    debugpy_host_port: int | None = Field(default=None, ge=1, le=65535)


class CustomAuditModeCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    body: str = Field(..., min_length=1, max_length=16000)


class CustomAuditModeUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    body: str | None = Field(default=None, min_length=1, max_length=16000)


class CustomAuditModeOut(BaseModel):
    id: int
    name: str
    body: str
    created_at: datetime
    updated_at: datetime


class BuiltinAuditModeOut(BaseModel):
    id: Literal["bounty", "full"]
    label: str
    body: str


class ProjectCreate(BaseModel):
    name: str = ""
    source_type: Literal["github", "zip"] = "github"
    source_url: str | None = None
    audit_mode: Literal["bounty", "full", "custom"] = "bounty"
    target_kind: Literal["web", "library", "mixed"] = "web"
    custom_audit_mode_id: int | None = None
    manual_lab: bool = False
    manual_lab_prompt: str = Field(default="", max_length=MANUAL_LAB_PROMPT_MAX)
    verifier_enabled: bool = False
    attack_chain_enabled: bool = False
    dynamic_verify_enabled: bool = False
    dynamic_verify_mode: Literal["off", "lab", "harness"] | None = None
    heuristic_enabled: bool = True
    heuristic_lite: bool = False
    fast_enabled: bool = False
    bypass_enabled: bool = False
    llm_model: str = Field(default="", max_length=256)
    worker_hint: str = Field(default="", max_length=WORKER_HINT_MAX)
    max_token_usage: int = Field(default=0, ge=0, le=1_000_000_000_000)


class ProjectUpdate(BaseModel):
    audit_mode: Literal["bounty", "full", "custom"] | None = None
    target_kind: Literal["web", "library", "mixed"] | None = None
    custom_audit_mode_id: int | None = None
    manual_lab: bool | None = None
    manual_lab_prompt: str | None = Field(default=None, max_length=MANUAL_LAB_PROMPT_MAX)
    verifier_enabled: bool | None = None
    attack_chain_enabled: bool | None = None
    dynamic_verify_enabled: bool | None = None
    dynamic_verify_mode: Literal["off", "lab", "harness"] | None = None
    heuristic_enabled: bool | None = None
    heuristic_lite: bool | None = None
    fast_enabled: bool | None = None
    bypass_enabled: bool | None = None
    llm_model: str | None = Field(default=None, max_length=256)
    worker_hint: str | None = Field(default=None, max_length=WORKER_HINT_MAX)
    max_token_usage: int | None = Field(default=None, ge=0, le=1_000_000_000_000)


class WeightExtOut(BaseModel):
    ext: str
    agent_added: bool = False
    files: int = 0


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
    target_kind: str = "web"
    custom_audit_mode_id: int | None = None
    custom_audit_mode_name: str = ""
    custom_audit_prompt: str = ""
    manual_lab: bool = False
    manual_lab_prompt: str = ""
    verifier_enabled: bool = False
    attack_chain_enabled: bool = False
    attack_chain_done: bool = False
    dynamic_verify_enabled: bool = False
    dynamic_verify_mode: str = "off"
    heuristic_enabled: bool = True
    heuristic_lite: bool = False
    fast_enabled: bool = False
    fast_queue_frozen: bool = False
    bypass_enabled: bool = False
    bypass_queue_frozen: bool = False
    llm_model: str = ""
    worker_hint: str = ""
    max_token_usage: int = 0
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
    files_weight100: int = 0
    files_weight100_audited: int = 0
    sinks_queued: int = 0
    sinks_done: int = 0
    bypass_queued: int = 0
    bypass_done: int = 0
    weight_exts: list[WeightExtOut] = Field(default_factory=list)
    worker_rounds: int = 0
    tokens_input: int = 0
    tokens_output: int = 0
    tokens_cached: int = 0
    tokens_total: int = 0
    phase_states: dict[str, Any] = Field(default_factory=dict)
    project_paused: bool = False
    recon_subphases: list[dict[str, Any]] = Field(default_factory=list)
    lab_setup_done: bool = False
    lab_setup_retryable: bool = False
    verifier_pending: int = 0

    model_config = {"from_attributes": True}


class ProjectRunStatusCounts(BaseModel):
    all: int = 0
    running: int = 0
    paused: int = 0
    completed: int = 0


class ProjectListOut(BaseModel):
    items: list[ProjectOut] = Field(default_factory=list)
    total: int = 0
    limit: int = 5
    offset: int = 0
    status_counts: ProjectRunStatusCounts = Field(default_factory=ProjectRunStatusCounts)


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
    # heuristic | fast | bypass
    mining_path: str | None = None
    root_cause_key: str | None = None
    merged_into_id: int | None = None
    review_rounds: int = 0
    return_reason: str | None = None
    # timeout — closed after review timeouts; empty/null — reviewer-judged FP
    fp_kind: str | None = None
    intended_behavior: bool = False
    # default | specific
    config_premise: str | None = None
    report_path: str | None = None
    verifier_status: str = "none"
    verifier_verified_url: str | None = None
    verifier_ask_reason: str | None = None
    verifier_user_instruction: str | None = None
    verifier_consent: bool = False
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
    advisory_md: str | None = None
    cve_json: str | None = None
    merged_from_ids: list[int] = Field(default_factory=list)
    verifier_poc: str | None = None
    verifier_response: str | None = None
    verifier_targets: list[dict[str, Any]] = Field(default_factory=list)
    verifier_fofa_query: str | None = None
    can_dynamic_verify: bool = False
    dynamic_verify_queued: bool = False


class VulnCalendarDay(BaseModel):
    date: str
    confirmed: int = 0
    false_positive: int = 0


class VulnCalendarOut(BaseModel):
    year: int
    month: int
    days: list[VulnCalendarDay] = Field(default_factory=list)


class VerifierConsentItem(BaseModel):
    id: int
    project_id: int
    project_name: str = ""
    title: str
    vuln_type: str | None = None
    severity: str | None = None
    severity_score: int | None = None
    verifier_ask_reason: str | None = None
    verifier_status: str = "awaiting_user"
    updated_at: datetime


class VerifierConsentIn(BaseModel):
    action: Literal["skip", "continue"]
    instruction: str | None = None


class VerifierConsentOut(BaseModel):
    ok: bool
    action: str | None = None
    vuln_id: int | None = None
    verifier_status: str | None = None
    instruction: str | None = None
    message: str | None = None
    error: str | None = None


class VulnTrackingIn(BaseModel):
    tracking_status: Literal["none", "submitted", "ignored"]


class VulnTrackingBatchIn(BaseModel):
    ids: list[int] = Field(min_length=1)
    tracking_status: Literal["none", "submitted", "ignored"]


class VulnFollowUpIn(BaseModel):
    question: str = Field(min_length=1, max_length=20000)


class VulnReportRevisionIn(BaseModel):
    kind: Literal["report", "advisory", "cve"] = "report"
    instruction: str = Field(min_length=1, max_length=20000)


class VulnReportRevisionOut(BaseModel):
    vuln_id: int
    project_id: int
    kind: Literal["report", "advisory", "cve"]
    reviewer_phase_run_id: int | None = None
    reviewer_context_available: bool = False
    original_text: str
    revised_text: str
    summary: str = ""


class VulnReportApplyIn(BaseModel):
    kind: Literal["report", "advisory", "cve"] = "report"
    content: str = Field(min_length=1, max_length=200000)
    note: str | None = Field(default=None, max_length=20000)


class VulnReportApplyOut(BaseModel):
    ok: bool
    vuln_id: int
    project_id: int
    kind: Literal["report", "advisory", "cve"]
    content: str
    message: str = ""


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
    selected_count: int = 0
    limit: int | None = None
    offset: int = 0
    phase: str = ""
    subphase: str = ""


class PhaseReportDetail(PhaseReportItem):
    content: str = ""


class DockerContainerOut(BaseModel):
    id: str
    short_id: str
    name: str
    status: str
    image: str
    ports: list[str] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    kind: str = "lab"
    project_id: int | None = None
    project_name: str | None = None
    created: str | None = None


class DockerImageOut(BaseModel):
    id: str
    short_id: str
    tags: list[str] = Field(default_factory=list)
    label: str
    status: str
    size_bytes: int = 0
    size_mb: float = 0.0
    kind: str = "lab"
    project_id: int | None = None
    project_name: str | None = None
    deletable: bool = False
    in_use: bool = False
    dangling: bool = False
    created: str | None = None


class DockerImageUsageOut(BaseModel):
    image_count: int = 0
    dangling_count: int = 0
    total_bytes: int = 0
    total_mb: float = 0.0
    total_gb: float = 0.0


class DockerIdList(BaseModel):
    ids: list[str] = Field(min_length=1, max_length=200)


class DockerActionItemOut(BaseModel):
    id: str
    status: str
    error: str | None = None


class DockerActionBatchOut(BaseModel):
    results: list[DockerActionItemOut]


class DockerImagePruneRequest(BaseModel):
    remove_stopped: bool = False


class DockerImagePruneResult(BaseModel):
    skipped: bool = False
    reason: str | None = None
    containers_removed: int = 0
    images_deleted: int = 0
    freed_bytes: int = 0
    freed_mb: float = 0.0
    errors: list[str] = Field(default_factory=list)


class GithubCandidateOut(BaseModel):
    id: int
    full_name: str
    html_url: str
    description: str | None = None
    language: str | None = None
    stars: int = 0
    pushed_at: datetime | None = None
    target_kind: str = "web"
    target_kind_reason: str | None = None
    advisory_count: int = 0
    latest_ghsa_id: str | None = None
    latest_ghsa_url: str | None = None
    status: str = "eligible"
    project_id: int | None = None
    skip_reason: str | None = None
    discovered_at: datetime
    updated_at: datetime | None = None


class GithubCandidateListOut(BaseModel):
    items: list[GithubCandidateOut]
    total: int
    limit: int
    offset: int


class GithubDiscoverSearchIn(BaseModel):
    limit: int = Field(default=5, ge=1, le=20)


class GithubDiscoverSearchOut(BaseModel):
    ok: bool = True
    error: str | None = None
    added: int = 0
    items: list[GithubCandidateOut] = Field(default_factory=list)
    scanned_advisories: int = 0
    scanned_repos: int = 0
    skipped_seen: int = 0
    pages: int = 0
    authenticated: bool = False
    warning: str | None = None
    limit: int = 5
