"""Analysis schemas for PhishGuard CI."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints


class ContentType(StrEnum):
    """Type of content being analyzed."""

    SMS = "SMS"
    MESSAGE = "MESSAGE"
    EMAIL = "EMAIL"
    URL = "URL"


class AnalysisStatus(StrEnum):
    """Status of the analysis pipeline execution."""

    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class Classification(StrEnum):
    """Risk classification based on score."""

    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    CRITICAL = "CRITICAL"


class ReliabilityLevel(StrEnum):
    """Reliability level of the analysis."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class AssessmentStatus(StrEnum):
    """Assessment status: CONCLUSIVE or INCONCLUSIVE."""

    CONCLUSIVE = "CONCLUSIVE"
    INCONCLUSIVE = "INCONCLUSIVE"


class IndicatorNature(StrEnum):
    """Nature of the indicator."""

    PROVIDER_SIGNAL = "PROVIDER_SIGNAL"
    STRUCTURAL_SIGNAL = "STRUCTURAL_SIGNAL"
    HEURISTIC_DETECTION = "HEURISTIC_DETECTION"
    INFORMATIVE_SIGNAL = "INFORMATIVE_SIGNAL"


class RuleValidationStatus(StrEnum):
    """Validation status of a scoring rule."""

    VALIDEE = "VALIDEE"
    PROPOSITION_NON_VALIDEE = "PROPOSITION_NON_VALIDEE"


class VerificationOutcome(StrEnum):
    """Outcome of a reputation verification."""

    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    CLEAN = "CLEAN"
    UNDETERMINED = "UNDETERMINED"
    FAILED = "FAILED"
    DISABLED = "DISABLED"
    NO_PROVIDER_CONFIGURED = "NO_PROVIDER_CONFIGURED"


class ScoringVariant(StrEnum):
    """Scoring variant applied."""

    VARIANTE_A = "VARIANTE_A"
    VARIANTE_B = "VARIANTE_B"


class Indicator(BaseModel):
    """Structured indicator from analysis."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., description="Unique normalized indicator code")
    category: str = Field(..., description="Risk family/category")
    nature: IndicatorNature = Field(..., description="Nature of the indicator")
    label: str = Field(..., description="Product label for the indicator")
    points_awarded: int = Field(..., ge=0, description="Points contributed to score")
    evidence_snippet: str | None = Field(
        None,
        description="Masked excerpt if C7 enabled, never on PROVIDER_SIGNAL",
    )
    validation_status: RuleValidationStatus = Field(
        ..., description="Rule validation status"
    )


class AppliedRule(BaseModel):
    """Applied scoring rule with its contribution."""

    model_config = ConfigDict(extra="forbid")

    category: str = Field(..., description="Risk family/category")
    category_score: int = Field(..., ge=0, description="Score for this category")
    category_cap: int = Field(..., ge=0, description="Maximum score for this category")
    rule_validation_status: RuleValidationStatus = Field(
        ..., description="Rule validation status"
    )


class VerificationFact(BaseModel):
    """Aggregated verification outcome."""

    model_config = ConfigDict(extra="forbid")

    outcome: VerificationOutcome = Field(..., description="Verification outcome")
    count: int = Field(..., ge=0, description="Number of providers with this outcome")


class DeterministicResult(BaseModel):
    """Complete deterministic result from FastAPI analysis."""

    model_config = ConfigDict(extra="forbid")

    score: int = Field(..., ge=0, le=100, description="Final risk score 0-100")
    classification: Classification = Field(..., description="Risk classification")
    pipeline_status: AnalysisStatus = Field(..., description="Pipeline execution status")
    reliability_level: ReliabilityLevel = Field(..., description="Reliability level")
    assessment_status: AssessmentStatus = Field(..., description="Assessment status")
    scoring_variant: ScoringVariant = Field(..., description="Scoring variant applied")
    scoring_version: str = Field(..., description="Scoring rules version")
    applied_rules: list[AppliedRule] = Field(
        ..., description="Applied scoring rules with contributions"
    )
    triggered_floors: list[str] = Field(
        default_factory=list, description="Triggered floor identifiers"
    )
    effective_floors: list[str] = Field(
        default_factory=list, description="Effective floor identifiers after precedence"
    )


class ExplainRequest(BaseModel):
    """Request sent to Hermes for explanation (contract v1.3)."""

    model_config = ConfigDict(extra="forbid")

    contract_version: Literal["1.3"] = Field(..., description="Contract version")
    analysis_ref: UUID = Field(..., description="Internal analysis reference")
    content_type: ContentType = Field(..., description="Type of content analyzed")
    language: str = Field(default="fr", description="Language for explanation")
    deterministic_result: DeterministicResult = Field(
        ..., description="Complete deterministic result"
    )
    indicators: list[Indicator] = Field(..., description="Structured indicators")
    verification_facts: list[VerificationFact] = Field(
        ..., description="Aggregated verification outcomes"
    )
    verifications_attempted: int = Field(
        ..., ge=0, description="Total verification attempts"
    )
    disabled_controls: int = Field(
        ..., ge=0, description="Number of disabled controls"
    )
    providers_configured: int = Field(
        ..., ge=0, description="Number of configured providers"
    )
    url_count: int = Field(..., ge=0, description="Number of URLs in content")


class ExplainResponseStatus(StrEnum):
    """Hermes response status."""

    OK = "OK"
    CANNOT_EXPLAIN = "CANNOT_EXPLAIN"


class ExplainResponse(BaseModel):
    """Response from Hermes (contract v1.3)."""

    model_config = ConfigDict(extra="forbid")

    status: ExplainResponseStatus = Field(..., description="Response status")
    summary: str | None = Field(None, description="Concise French summary")
    explanations: list[dict[str, str]] | None = Field(
        None, description="Per-indicator explanations"
    )
    limitations: list[str] | None = Field(None, description="Limitations of analysis")
    recommendations: list[str] | None = Field(None, description="Recommendations")
    reason_code: str | None = Field(
        None, description="Reason code if CANNOT_EXPLAIN"
    )


class AnalysisRequest(BaseModel):
    """Request to submit content for analysis."""

    model_config = ConfigDict(extra="forbid")

    content: Annotated[
        str,
        StringConstraints(min_length=1, max_length=10000, strip_whitespace=True),
    ] = Field(..., description="Content to analyze")
    content_type: ContentType = Field(default=ContentType.MESSAGE, description="Content type")


class AnalysisResponse(BaseModel):
    """Response from analysis endpoint."""

    model_config = ConfigDict(extra="forbid")

    analysis_ref: UUID = Field(..., description="Analysis reference")
    status: AnalysisStatus = Field(..., description="Pipeline status")
    score: int = Field(..., ge=0, le=100, description="Risk score")
    classification: Classification = Field(..., description="Risk classification")
    reliability_level: ReliabilityLevel = Field(..., description="Reliability level")
    assessment_status: AssessmentStatus = Field(..., description="Assessment status")
    indicators: list[Indicator] = Field(..., description="Detected indicators")
    explanation: str = Field(..., description="Explanation text")
    explanation_source: Literal["HERMES", "TEMPLATE"] = Field(
        ..., description="Source of explanation"
    )
    template_version: str = Field(..., description="Template version used")
    scoring_version: str = Field(..., description="Scoring version used")