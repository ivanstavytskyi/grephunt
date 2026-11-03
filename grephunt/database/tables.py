"""Tables for one installation. tenant_id is on every table from day one. The default tenant is local."""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, create_engine, event, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from grephunt.config import DATA_DIR, database_url


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="local", index=True)
    target_label: Mapped[str] = mapped_column(String(512))
    target_path: Mapped[str] = mapped_column(String(1024))
    status: Mapped[str] = mapped_column(String(32), default="running")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    raw_total: Mapped[int] = mapped_column(Integer, default=0)
    excluded: Mapped[int] = mapped_column(Integer, default=0)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    partial: Mapped[int] = mapped_column(Integer, default=0)
    run_params: Mapped[str | None] = mapped_column(Text, nullable=True)
    """JSON: per-tool validated parameters used for this scan."""
    source_repo_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    source_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)


class TaskRow(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="local", index=True)
    tool: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    duration_sec: Mapped[float] = mapped_column(default=0.0)
    tool_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    image: Mapped[str | None] = mapped_column(String(256), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="local", index=True)
    fingerprint: Mapped[str] = mapped_column(String(512), index=True)
    correlation_key: Mapped[str] = mapped_column(String(512))
    severity: Mapped[str] = mapped_column(String(16), index=True)
    category: Mapped[str] = mapped_column(String(32), index=True)
    tool: Mapped[str] = mapped_column(String(64))
    body: Mapped[str] = mapped_column(Text)


class DismissedFindingRow(Base):
    """Findings a person removed from a scan. Later pipeline writes must not put them back."""

    __tablename__ = "dismissed_findings"
    __table_args__ = (UniqueConstraint("scan_id", "fingerprint", "correlation_key", name="uq_dismissed_finding"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="local", index=True)
    fingerprint: Mapped[str] = mapped_column(String(512))
    correlation_key: Mapped[str] = mapped_column(String(512), default="")


class EventRow(Base):
    __tablename__ = "events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(String(64), default="local", index=True)
    seq: Mapped[int] = mapped_column(Integer, index=True)
    type: Mapped[str] = mapped_column(String(64))
    payload: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


def make_engine(url: str | None = None):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    target = url or database_url()
    connect_args = {"check_same_thread": False, "timeout": 5} if target.startswith("sqlite") else {}
    engine = create_engine(target, connect_args=connect_args)
    if target.startswith("sqlite"):

        @event.listens_for(engine, "connect")
        def _sqlite_pragmas(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA busy_timeout=5000")
            cursor.close()

    return engine


def _migrate_schema(engine) -> None:
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as conn:
        rows = conn.execute(text("PRAGMA table_info(scans)")).fetchall()
        names = {row[1] for row in rows}
        if "run_params" not in names:
            conn.execute(text("ALTER TABLE scans ADD COLUMN run_params TEXT"))
        if "source_repo_url" not in names:
            conn.execute(text("ALTER TABLE scans ADD COLUMN source_repo_url TEXT"))
        if "source_ref" not in names:
            conn.execute(text("ALTER TABLE scans ADD COLUMN source_ref TEXT"))


def make_session_factory(engine=None):
    bound = engine or make_engine()
    Base.metadata.create_all(bound)
    _migrate_schema(bound)
    return sessionmaker(bound, expire_on_commit=False)
