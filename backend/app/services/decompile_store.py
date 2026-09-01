"""Sidecar SQLite for jadx job snapshots and pending FileWeight ingest.

Isolated from data/app.db so collecting decompiled paths never holds the
audit write lock. FileWeight drip still writes app.db, but only when idle
and in small batches.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from sqlalchemy import (
    Integer,
    String,
    UniqueConstraint,
    create_engine,
    event,
    inspect,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker
from sqlalchemy.pool import NullPool

_BUSY_TIMEOUT_MS = 5000
_DRIP_BATCH = 50

_engine = None
_engine_path: Path | None = None
_Session = None
_schema_ready = False
_engine_lock = threading.Lock()

_write_busy_lock = threading.Lock()
_write_busy = 0


class Base(DeclarativeBase):
    pass


class DecompileJobRow(Base):
    __tablename__ = "jobs"

    job_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    index_key: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    source: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    output_root: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="queued", index=True)
    error: Mapped[str] = mapped_column(String(1024), nullable=False, default="")
    class_name: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    package: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    class_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class PendingIngest(Base):
    __tablename__ = "pending_ingest"
    __table_args__ = (UniqueConstraint("project_id", "path", name="uq_pending_project_path"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    project_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    source_rel: Mapped[str] = mapped_column(String(1024), nullable=False, default="", index=True)
    path: Mapped[str] = mapped_column(String(1024), nullable=False)


def db_path() -> Path:
    from .. import config

    return Path(config.DATA_DIR) / "decompile.db"


def _bind() -> None:
    global _engine, _engine_path, _Session, _schema_ready
    path = db_path()
    if _engine is not None and _engine_path == path:
        return
    if _engine is not None:
        try:
            _engine.dispose()
        except Exception:  # noqa: BLE001
            pass
    path.parent.mkdir(parents=True, exist_ok=True)
    url = "sqlite:///" + path.resolve().as_posix()
    engine = create_engine(
        url,
        connect_args={"check_same_thread": False, "timeout": _BUSY_TIMEOUT_MS / 1000},
        poolclass=NullPool,
    )

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_connection, _record) -> None:  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT_MS}")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()

    Base.metadata.create_all(bind=engine)
    _engine = engine
    _engine_path = path
    _Session = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    _schema_ready = inspect(engine).has_table("pending_ingest")


def SessionLocal():
    with _engine_lock:
        _bind()
    assert _Session is not None
    return _Session()


def reset_engine() -> None:
    """Tests: drop the cached engine so the next call follows patched DATA_DIR."""
    global _engine, _engine_path, _Session, _schema_ready
    with _engine_lock:
        if _engine is not None:
            try:
                _engine.dispose()
            except Exception:  # noqa: BLE001
                pass
        _engine = None
        _engine_path = None
        _Session = None
        _schema_ready = False
    with _write_busy_lock:
        global _write_busy
        _write_busy = 0


def acquire_app_db_write() -> None:
    global _write_busy
    with _write_busy_lock:
        _write_busy += 1


def release_app_db_write() -> None:
    global _write_busy
    with _write_busy_lock:
        _write_busy = max(0, _write_busy - 1)


def is_app_db_write_busy() -> bool:
    with _write_busy_lock:
        return _write_busy > 0


@contextmanager
def app_db_write() -> Iterator[None]:
    acquire_app_db_write()
    try:
        yield
    finally:
        release_app_db_write()


def upsert_job(payload: dict[str, Any]) -> None:
    job_id = str(payload.get("job_id") or "").strip()
    if not job_id:
        return
    with SessionLocal() as db:
        row = db.get(DecompileJobRow, job_id)
        if row is None:
            row = DecompileJobRow(job_id=job_id, project_id=int(payload.get("project_id") or 0))
            db.add(row)
        row.project_id = int(payload.get("project_id") or row.project_id)
        row.index_key = str(payload.get("index_key") or "")
        row.source = str(payload.get("source") or "").replace("\\", "/")
        row.output_root = str(payload.get("output_root") or "").replace("\\", "/")
        row.status = str(payload.get("status") or "queued")
        row.error = str(payload.get("error") or "")[:1024]
        row.class_name = str(payload.get("class_name") or "")
        row.package = str(payload.get("package") or "")
        row.class_count = int(payload.get("class_count") or 0)
        db.commit()


def enqueue_pending(project_id: int, source_rel: str, paths: list[str]) -> int:
    from sqlalchemy.exc import IntegrityError

    source = str(source_rel or "").replace("\\", "/")
    rels = [str(p or "").replace("\\", "/") for p in paths if str(p or "").strip()]
    if not rels:
        return 0
    added = 0
    with SessionLocal() as db:
        existing = {
            r.path
            for r in db.query(PendingIngest.path)
            .filter(PendingIngest.project_id == project_id, PendingIngest.path.in_(rels))
            .all()
        }
        for rel in rels:
            if rel in existing:
                continue
            db.add(PendingIngest(project_id=project_id, source_rel=source, path=rel))
            existing.add(rel)
            added += 1
        if added:
            try:
                db.commit()
            except IntegrityError:
                db.rollback()
                return 0
    return added


def pending_count(project_id: int, source_rel: str | None = None) -> int:
    with SessionLocal() as db:
        q = db.query(PendingIngest.id).filter(PendingIngest.project_id == project_id)
        if source_rel:
            q = q.filter(PendingIngest.source_rel == str(source_rel).replace("\\", "/"))
        return q.count()


def peek_pending(
    project_id: int, *, limit: int = _DRIP_BATCH, source_rel: str | None = None
) -> list[PendingIngest]:
    cap = max(1, int(limit))
    with SessionLocal() as db:
        q = db.query(PendingIngest).filter(PendingIngest.project_id == project_id)
        if source_rel:
            q = q.filter(PendingIngest.source_rel == str(source_rel).replace("\\", "/"))
        rows = q.order_by(PendingIngest.id.asc()).limit(cap).all()
        for row in rows:
            db.expunge(row)
        return rows


def delete_pending(ids: list[int]) -> None:
    if not ids:
        return
    with SessionLocal() as db:
        db.query(PendingIngest).filter(PendingIngest.id.in_(ids)).delete(synchronize_session=False)
        db.commit()


def drop_project(project_id: int) -> None:
    with SessionLocal() as db:
        db.query(PendingIngest).filter(PendingIngest.project_id == project_id).delete(
            synchronize_session=False
        )
        db.query(DecompileJobRow).filter(DecompileJobRow.project_id == project_id).delete(
            synchronize_session=False
        )
        db.commit()


def drip_batch_size() -> int:
    return _DRIP_BATCH
