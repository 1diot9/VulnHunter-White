from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT_DIR / "data"
PROJECTS_DIR = DATA_DIR / "projects"
DB_PATH = DATA_DIR / "app.db"
TEMPLATES_DIR = ROOT_DIR / "templates"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNHUNTER_", env_file=".env", extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8000

    # Timeouts (seconds) — aligned with AutoPoc scale
    timeout_recon: int = 3600
    timeout_recon_mark_round: int = 1800
    recon_mark_batch_size: int = 40
    timeout_worker_round: int = 7200
    timeout_reviewer_static: int = 1800
    timeout_docker: int = 1800
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

    # Context compression
    tool_result_keep_rounds: int = 50
    tool_result_truncate_chars: int = 3000
    tool_result_keep_max_chars: int = 12000
    # Newest N tool results stay large enough for one Read page (see Read offset/limit).
    tool_result_keep_full_rounds: int = 4
    tool_result_keep_full_max_chars: int = 48000
    tool_result_drop_rounds: int = 200
    context_compress_ratio: float = 0.85
    default_context_window: int = 128000

    # Agent defaults
    worker_concurrency: int = 1
    fix_concurrency: int = 1
    max_review_rejects: int = 2
    file_inject_max_bytes: int = 80 * 1024
    temperature: float = 0.2

    # Debug MCP paths (optional)
    mcp_java: str = r"D:\AI\MCP_Tools\Java-debug-mcp"
    mcp_node: str = r"D:\AI\MCP_Tools\Node-debug-mcp-main"
    mcp_python: str = r"D:\AI\MCP_Tools\Python-debug-mcp-main"

    # Outbound HTTP proxy for tools (WebSearch / GHSA). Chat ignores these.
    http_proxy: str = "http://127.0.0.1:10808"
    https_proxy: str = "http://127.0.0.1:10808"
    # Chat Completions: empty = direct (no env HTTPS_PROXY / no http_proxy above)
    chat_proxy: str = ""


settings = Settings()
DATA_DIR.mkdir(parents=True, exist_ok=True)
PROJECTS_DIR.mkdir(parents=True, exist_ok=True)
