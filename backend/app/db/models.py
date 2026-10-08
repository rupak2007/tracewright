"""Database schema (architecture §15). Portable: JSON columns become JSONB on PostgreSQL, so
the same models run on SQLite in unit tests. Schema changes go through Alembic only."""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy.types import TypeDecorator

JsonType = JSON().with_variant(JSONB(), "postgresql")


class UtcDateTime(TypeDecorator[datetime]):
    """Timezone-aware datetimes on every backend (SQLite drops tzinfo; this puts UTC back)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)  # uuid4, also the upload name
    original_name: Mapped[str] = mapped_column(String(255), default="")  # metadata only
    upload_name: Mapped[str] = mapped_column(String(64))  # "<uuid>.pcap|.pcapng" under uploads/
    sha256: Mapped[str] = mapped_column(String(64))
    size_bytes: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(24), default="queued")
    stage: Mapped[str] = mapped_column(String(32), default="queued")
    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    profile: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    warnings: Mapped[list[Any] | None] = mapped_column(JsonType, nullable=True)
    manifest: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    stage_ms: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)

    incidents: Mapped[list["Incident"]] = relationship(
        cascade="all, delete-orphan", back_populates="investigation"
    )


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    type: Mapped[str] = mapped_column(String(16))  # analyze | slice
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    lease_until: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    params: Mapped[dict[str, Any]] = mapped_column(JsonType, default=dict)
    worker_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)


class Incident(Base):
    __tablename__ = "incidents"
    __table_args__ = (UniqueConstraint("investigation_id", "local_id"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    local_id: Mapped[str] = mapped_column(String(16))  # "I-3"
    rank: Mapped[int] = mapped_column(Integer)  # 1 = most severe
    primary_entity: Mapped[str] = mapped_column(String(255))
    start_ts: Mapped[datetime] = mapped_column(UtcDateTime())
    end_ts: Mapped[datetime] = mapped_column(UtcDateTime())
    severity_score: Mapped[float] = mapped_column(Float)
    severity_label: Mapped[str] = mapped_column(String(16))
    template_summary: Mapped[str] = mapped_column(Text)
    detail: Mapped[dict[str, Any]] = mapped_column(JsonType)  # the full IncidentDetail

    investigation: Mapped[Investigation] = relationship(back_populates="incidents")
    findings: Mapped[list["Finding"]] = relationship(
        cascade="all, delete-orphan", back_populates="incident"
    )


class IncidentLink(Base):
    __tablename__ = "incident_links"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    from_incident: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    to_incident: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    type: Mapped[str] = mapped_column(String(32))
    reason: Mapped[str] = mapped_column(Text)


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    local_id: Mapped[str] = mapped_column(String(16))  # "F-2"
    type: Mapped[str] = mapped_column(String(32))
    detector_id: Mapped[str] = mapped_column(String(32))
    detector_version: Mapped[str] = mapped_column(String(16))
    primary_entity: Mapped[str] = mapped_column(String(255))
    secondary_entities: Mapped[list[Any]] = mapped_column(JsonType)
    start_ts: Mapped[datetime] = mapped_column(UtcDateTime())
    end_ts: Mapped[datetime] = mapped_column(UtcDateTime())
    metrics: Mapped[dict[str, Any]] = mapped_column(JsonType)
    thresholds: Mapped[dict[str, Any]] = mapped_column(JsonType)
    confidence: Mapped[str] = mapped_column(String(8))
    severity_score: Mapped[float] = mapped_column(Float)
    benign_causes: Mapped[list[Any]] = mapped_column(JsonType)
    evidence_refs: Mapped[list[Any]] = mapped_column(JsonType)  # sampled Zeek uids
    evidence_total: Mapped[int] = mapped_column(Integer)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)

    incident: Mapped[Incident] = relationship(back_populates="findings")


class EvidenceRecord(Base):
    __tablename__ = "evidence_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"))
    local_id: Mapped[str] = mapped_column(String(16))  # "E-4"
    seq: Mapped[int] = mapped_column(Integer)  # position inside the incident, for stable paging
    kind: Mapped[str] = mapped_column(String(16))
    zeek_uid: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ts: Mapped[datetime | None] = mapped_column(UtcDateTime(), nullable=True)
    fields: Mapped[dict[str, Any]] = mapped_column(JsonType)


class TechniqueRefRow(Base):
    __tablename__ = "technique_refs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    technique_id: Mapped[str] = mapped_column(String(16))
    phrase: Mapped[str] = mapped_column(Text)


class AnomalyScoreRow(Base):
    __tablename__ = "anomaly_scores"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True
    )
    host: Mapped[str] = mapped_column(String(255))
    window_start: Mapped[datetime] = mapped_column(UtcDateTime())
    scorer: Mapped[str] = mapped_column(String(16))
    score: Mapped[float] = mapped_column(Float)
    rank: Mapped[int] = mapped_column(Integer)
    rule_explained: Mapped[bool] = mapped_column(Boolean)
    top_features: Mapped[list[Any]] = mapped_column(JsonType)


class Narrative(Base):
    """Optional LLM narrative for an incident (P8); the template summary is always there."""

    __tablename__ = "narratives"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), unique=True
    )
    status: Mapped[str] = mapped_column(String(16))  # pending|validated|rejected|unavailable
    output: Mapped[dict[str, Any] | None] = mapped_column(JsonType, nullable=True)
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    reasons: Mapped[list[Any]] = mapped_column(JsonType, default=list)
    provider: Mapped[str] = mapped_column(String(32), default="")
    model: Mapped[str] = mapped_column(String(64), default="")
    prompt_hash: Mapped[str] = mapped_column(String(64), default="")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)


class Feedback(Base):
    __tablename__ = "feedback"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    label: Mapped[str] = mapped_column(String(24))  # true_positive|false_positive|expected_benign
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)


class SliceRow(Base):
    __tablename__ = "slices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(String(16), default="queued")  # queued|running|done|failed
    filename: Mapped[str | None] = mapped_column(String(64), nullable=True)
    size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    packets: Mapped[int | None] = mapped_column(Integer, nullable=True)
    bpf: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)


class WorkerHeartbeat(Base):
    __tablename__ = "worker_heartbeat"

    worker_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    beat_at: Mapped[datetime] = mapped_column(UtcDateTime(), default=utcnow)
