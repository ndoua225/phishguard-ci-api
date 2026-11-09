"""Database models for PhishGuard CI."""

from __future__ import annotations

import enum
from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import (
    JSON,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""


class UserRole(enum.StrEnum):
    """User roles."""

    USER = "USER"
    ADMIN = "ADMIN"
    SUPER_ADMIN = "SUPER_ADMIN"


class AnalysisStatusEnum(enum.StrEnum):
    """Analysis status."""

    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class ClassificationEnum(enum.StrEnum):
    """Risk classification."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class ReliabilityLevelEnum(enum.StrEnum):
    """Reliability level."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AssessmentStatusEnum(enum.StrEnum):
    """Assessment status."""

    CONCLUSIVE = "CONCLUSIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class ExplanationSourceEnum(enum.StrEnum):
    """Source of explanation."""

    HERMES = "HERMES"
    TEMPLATE = "TEMPLATE"


class ContentTypeEnum(enum.StrEnum):
    """Content type."""

    SMS = "SMS"
    MESSAGE = "MESSAGE"
    EMAIL = "EMAIL"
    URL = "URL"


class User(Base):
    """User account."""

    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        SQLEnum(UserRole), default=UserRole.USER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    is_test_account: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    failed_login_attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    locked_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # MFA fields
    totp_secret: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    analyses: Mapped[list[Analysis]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[list[Session]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    api_usage: Mapped[list[ApiUsage]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    """User session."""

    __tablename__ = "sessions"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    session_token: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    csrf_token: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    is_mfa_verified: Mapped[bool] = mapped_column(default=False, nullable=False)

    # Relationships
    user: Mapped[User] = relationship(back_populates="sessions")


class Analysis(Base):
    """Analysis record (minimal data per privacy requirements)."""

    __tablename__ = "analyses"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    analysis_ref: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    content_type: Mapped[ContentTypeEnum] = mapped_column(
        SQLEnum(ContentTypeEnum), nullable=False
    )
    status: Mapped[AnalysisStatusEnum] = mapped_column(
        SQLEnum(AnalysisStatusEnum), nullable=False
    )
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    classification: Mapped[ClassificationEnum] = mapped_column(
        SQLEnum(ClassificationEnum), nullable=False
    )
    reliability_level: Mapped[ReliabilityLevelEnum] = mapped_column(
        SQLEnum(ReliabilityLevelEnum), nullable=False
    )
    assessment_status: Mapped[AssessmentStatusEnum] = mapped_column(
        SQLEnum(AssessmentStatusEnum), nullable=False
    )
    scoring_version: Mapped[str] = mapped_column(String(32), nullable=False)
    template_version: Mapped[str] = mapped_column(String(32), nullable=False)
    explanation_source: Mapped[ExplanationSourceEnum] = mapped_column(
        SQLEnum(ExplanationSourceEnum), nullable=False
    )
    indicators: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    verification_facts: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    verifications_attempted: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    disabled_controls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    providers_configured: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    url_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    # Relationships
    user: Mapped[User] = relationship(back_populates="analyses")
    urls: Mapped[list[AnalysisUrl]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )
    results: Mapped[list[AnalysisResult]] = relationship(
        back_populates="analysis", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_analyses_user_created", "user_id", "created_at"),
    )


class AnalysisUrl(Base):
    """URL structural indicators only (no full URL or domain)."""

    __tablename__ = "analysis_urls"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    analysis_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Structural indicators only
    is_ip_literal: Mapped[bool] = mapped_column(default=False, nullable=False)
    tld: Mapped[str | None] = mapped_column(String(16), nullable=True)
    subdomain_count: Mapped[int] = mapped_column(default=0, nullable=False)
    has_non_standard_port: Mapped[bool] = mapped_column(default=False, nullable=False)
    is_shortener: Mapped[bool] = mapped_column(default=False, nullable=False)
    entropy: Mapped[float | None] = mapped_column(nullable=True)
    url_hmac: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    analysis: Mapped[Analysis] = relationship(back_populates="urls")


class AnalysisResult(Base):
    """Structured analysis result (no free text)."""

    __tablename__ = "analysis_results"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    analysis_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Full deterministic result as JSON
    deterministic_result: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False)
    indicators: Mapped[list[dict[str, str]]] = mapped_column(JSON, nullable=False, default=list)
    explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    explanation_source: Mapped[ExplanationSourceEnum] = mapped_column(
        SQLEnum(ExplanationSourceEnum), nullable=False
    )
    template_version: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    analysis: Mapped[Analysis] = relationship(back_populates="results")


class ApiUsage(Base):
    """API usage counters for quotas."""

    __tablename__ = "api_usage"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    analysis_count: Mapped[int] = mapped_column(default=0, nullable=False)
    analysis_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    user: Mapped[User] = relationship(back_populates="api_usage")

    __table_args__ = (
        Index("ix_api_usage_user_date", "user_id", "date"),
    )


class ActivityLog(Base):
    """Audit log (non-sensitive metadata only)."""

    __tablename__ = "activity_logs"

    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid4
    )
    user_id: Mapped[UUID | None] = mapped_column(
        PG_UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    event_metadata: Mapped[dict[str, str]] = mapped_column(JSON, nullable=False, default=dict)
    ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_activity_logs_user_created", "user_id", "created_at"),
    )