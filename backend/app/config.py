from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
PROJECTS_DIR = DATA_DIR / "projects"
DB_PATH = DATA_DIR / "app.db"
TEMPLATES_DIR = ROOT_DIR / "templates"


def resolve_repo_path(value: str, *, fallback: str = "") -> Path:
    """Resolve a repo-relative path, or keep an absolute override."""
    raw = (value or "").strip() or (fallback or "").strip()
    path = Path(raw)
    if not path.is_absolute():
        path = ROOT_DIR / path
    return path


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNHUNTER_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8000

    # Timeouts (seconds) — aligned with AutoPoc scale
    timeout_recon: int = 3600
    timeout_recon_mark_round: int = 1800
    recon_mark_batch_size: int = 150
    timeout_worker_round: int = 7200
    timeout_reviewer_static: int = 1800
    timeout_verifier: int = 1800
    timeout_docker: int = 1800
    timeout_semgrep: int = 1800
    timeout_sink_triage: int = 1800
    timeout_conclude: int = 300
    timeout_conclude_rescue: int = 1800

    # LLM error handling (AutoPoc-aligned)
    rate_limit_sleep_sec: int = 90
    rate_limit_max_retries: int = 20
    request_backoff_retries: int = 3
    phase_max_resumes: int = 2
    recon_max_resumes: int = 8
    claim_stale_sec: int = 7260  # timeout_worker_round + 60
    chat_connect_timeout: float = 30.0
    chat_read_timeout_min: float = 180.0
    chat_read_timeout_max: float = 600.0

    # Context compression: rewrite history with a summary when prompt exceeds this ratio of the window.
    context_compress_ratio: float = 0.85
    default_context_window: int = 128000

    # Agent defaults
    worker_concurrency: int = 1
    fix_concurrency: int = 1
    llm_thread_limit: int = 6
    max_review_rejects: int = 2
    file_inject_max_bytes: int = 80 * 1024
    worker_round_history: int = 10
    recon_doc_inject_max_chars: int = 32 * 1024
    round_report_inject_max_chars: int = 8 * 1024
    temperature: float = 0.2

    # Debug MCP directories (relative to repo root; env can override)
    mcp_java: str = "tools/mcp/java-debug"
    mcp_node: str = "tools/mcp/node-debug"
    mcp_python: str = "tools/mcp/python-debug"

    # Outbound HTTP for tools (WebSearch / GHSA / GitHub Issues / FOFA). Empty = direct.
    # Prefer Settings page; these env values are fallbacks when DB has never saved a proxy.
    http_proxy: str = ""
    https_proxy: str = ""
    # Chat Completions: empty = direct (does not use the tool proxy).
    chat_proxy: str = ""

    # FOFA (Verifier). Key can also be saved in Settings; env is fallback.
    fofa_key: str = ""
    fofa_base_url: str = "https://fofa.info"


settings = Settings()
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
