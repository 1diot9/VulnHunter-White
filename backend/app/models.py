from __future__ import annotations

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
    github_pat: Mapped[str | None] = mapped_column(Text, nullable=True)
    default_model: Mapped[str | None] = mapped_column(String(256), nullable=True)
    default_base_url: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    default_api_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    context_window: Mapped[int] = mapped_column(Integer, default=128000)
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
    # pending | recon | worker | reviewer | done
    recon_done: Mapped[bool] = mapped_column(Boolean, default=False)
    # bounty | full — set at create time; change only while paused
    audit_mode: Mapped[str] = mapped_column(String(32), default="bounty")
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_concurrency: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    files: Mapped[list[FileWeight]] = relationship(back_populates="project", cascade="all, delete-orphan")
    sources: Mapped[list[Source]] = relationship(back_populates="project", cascade="all, delete-orphan")
    vulns: Mapped[list[Vuln]] = relationship(back_populates="project", cascade="all, delete-orphan")
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


class Vuln(Base):
    __tablename__ = "vulns"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    vuln_type: Mapped[str] = mapped_column(String(64), default="other")
    severity: Mapped[str] = mapped_column(String(32), default="low")
    severity_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    # Reviewer 校准得分，pending_review 阶段可为空
    cwe: Mapped[str | None] = mapped_column(String(64), nullable=True)
    file_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    line_no: Mapped[int | None] = mapped_column(Integer, nullable=True)
    source_sink: Mapped[str | None] = mapped_column(Text, nullable=True)
    auth_premise: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_request: Mapped[str | None] = mapped_column(Text, nullable=True)
    poc_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_evidence: Mapped[str | None] = mapped_column(Text, nullable=True)
    intended_behavior: Mapped[bool] = mapped_column(Boolean, default=False)
    # pending_review | returned | confirmed | false_positive | static_only
    status: Mapped[str] = mapped_column(String(64), default="pending_review")
    evidence_level: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # dynamic | static_only | mcp
    attack_surface: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # frontend | backend — Reviewer 确认时标注
    required_account: Mapped[str | None] = mapped_column(String(32), nullable=True)
    # user | admin — 仅后台漏洞需要
    submission_tier: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # cve_candidate | low_impact | duplicate_grouped | needs_more_evidence
    submission_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    root_cause_key: Mapped[str | None] = mapped_column(String(256), nullable=True)
    # 同根因合并键，如 idor:SysCommentController / ssrf:checkSsrfHttpUrl
    review_rounds: Mapped[int] = mapped_column(Integer, default=0)
    return_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_path: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    project: Mapped[Project] = relationship(back_populates="vulns")


class PhaseRun(Base):
    __tablename__ = "phase_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), nullable=False, index=True)
    phase: Mapped[str] = mapped_column(String(64), nullable=False)
    # recon | worker | reviewer | fix | env
    role: Mapped[str] = mapped_column(String(64), default="worker")
    status: Mapped[str] = mapped_column(String(64), default="running")
    # running | completed | failed | cancelled | paused
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


REQUIRED_TABLES = (
    "app_settings",
    "projects",
    "file_weights",
    "sources",
    "vulns",
    "phase_runs",
    "tool_logs",
    "token_usages",
)

SQLITE_BUSY_TIMEOUT_MS = 30000

# Windows: use forward slashes so sqlite3 does not mis-parse drive paths.
engine = create_engine(
    f"sqlite:///{DB_PATH.resolve().as_posix()}",
    connect_args={
        "check_same_thread": False,
        "timeout": SQLITE_BUSY_TIMEOUT_MS / 1000,
    },
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
        "app_settings": {"fix_concurrency": "INTEGER DEFAULT 1"},
        "file_weights": {
            "claimed_at": "DATETIME",
            "audit_attempts": "INTEGER DEFAULT 0",
        },
        "tool_logs": {"error_class": "VARCHAR(32)"},
        "phase_runs": {"file_path": "VARCHAR(1024)"},
        "projects": {"audit_mode": "VARCHAR(32) DEFAULT 'bounty'"},
        "vulns": {
            "attack_surface": "VARCHAR(32)",
            "required_account": "VARCHAR(32)",
            "severity_score": "INTEGER",
            "submission_tier": "VARCHAR(64)",
            "submission_reason": "TEXT",
            "root_cause_key": "VARCHAR(256)",
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
    """Fold legacy hardening/advisory_only rows into low_impact."""
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


def ensure_schema() -> None:
    """Idempotent: create missing tables/columns. Safe to call from worker threads."""
    DATA_DIR = DB_PATH.parent
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    _ensure_columns()
    _migrate_submission_tiers()
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
