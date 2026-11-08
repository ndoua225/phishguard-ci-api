"""Deterministic scoring engine for PhishGuard CI."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from app.schemas.analysis import (
    AnalysisStatus,
    AppliedRule,
    AssessmentStatus,
    Classification,
    Indicator,
    ReliabilityLevel,
    RuleValidationStatus,
    VerificationFact,
    VerificationOutcome,
)

# Scoring configuration (Modèle 2)
CATEGORY_CAPS: Final[dict[str, int]] = {
    "REPUTATION_URL_DOMAIN": 30,
    "URL_STRUCTURE_ANOMALIES": 20,
    "SENSITIVE_DATA_REQUEST": 20,
    "BRAND_IMPERSONATION_MISMATCH": 15,
    "URGENCY_MANIPULATION": 15,
}

TOTAL_CAP: Final[int] = 100

# Floor thresholds (candidates - not activated)
F1_THRESHOLD: Final[int] = 70  # MALICIOUS URL
F2_THRESHOLD: Final[int] = 45  # OTP/PIN + technical impersonation


@dataclass(slots=True)
class ScoringResult:
    """Result of scoring calculation."""

    score: int
    classification: Classification
    applied_rules: list[AppliedRule]
    triggered_floors: list[str]
    effective_floors: list[str]
    category_scores: dict[str, int]


def calculate_score(
    indicators: list[Indicator],
    verification_facts: list[VerificationFact],
    url_count: int,
) -> ScoringResult:
    """Calculate deterministic risk score from indicators.

    Args:
        indicators: Extracted indicators from analysis.
        verification_facts: Aggregated verification outcomes.
        url_count: Number of URLs in the content.

    Returns:
        ScoringResult with score, classification, and rule details.
    """
    # Calculate category scores (sum of indicators per category, capped)
    category_scores: dict[str, int] = {cat: 0 for cat in CATEGORY_CAPS}

    for indicator in indicators:
        cat = indicator.category
        if cat in category_scores:
            category_scores[cat] += indicator.points_awarded

    # Apply caps
    for cat, cap in CATEGORY_CAPS.items():
        category_scores[cat] = min(category_scores[cat], cap)

    # Base score is sum of capped category scores
    base_score = sum(category_scores.values())
    base_score = min(base_score, TOTAL_CAP)

    # Determine triggered floors (candidates only, not applied by default)
    triggered_floors: list[str] = []
    effective_floors: list[str] = []

    # Check F1: MALICIOUS URL reputation
    has_malicious = any(
        f.outcome == VerificationOutcome.MALICIOUS for f in verification_facts
    )
    if has_malicious:
        triggered_floors.append("F1_MALICIOUS_URL")

    # Check F2: OTP/PIN request + brand impersonation technical mismatch
    any(i.code == "OTP_PIN_REQUEST" for i in indicators)
    any(
        i.code == "BRAND_MENTION_INFORMATIVE" and i.points_awarded == 0
        for i in indicators
    )
    # Technical impersonation would require domain mismatch analysis
    # For now, F2 is not automatically triggered without domain verification
    # This is a candidate threshold requiring explicit decision

    # Build applied rules list
    applied_rules: list[AppliedRule] = []
    for cat, cap in CATEGORY_CAPS.items():
        # Determine validation status for this category
        cat_indicators = [i for i in indicators if i.category == cat]
        if cat_indicators:
            # If any indicator in category is PROPOSITION_NON_VALIDEE
            statuses = {i.validation_status for i in cat_indicators}
            rule_status = (
                RuleValidationStatus.PROPOSITION_NON_VALIDEE
                if RuleValidationStatus.PROPOSITION_NON_VALIDEE in statuses
                else RuleValidationStatus.VALIDEE
            )
        else:
            rule_status = RuleValidationStatus.VALIDEE

        applied_rules.append(AppliedRule(
            category=cat,
            category_score=category_scores[cat],
            category_cap=cap,
            rule_validation_status=rule_status,
        ))

    # Effective floors are empty by default (floors are candidates)
    effective_floors = []

    # Final score is base score (floors not applied)
    final_score = base_score

    # Classification
    if final_score >= 70:
        classification = Classification.CRITICAL
    elif final_score >= 40:
        classification = Classification.SUSPICIOUS
    else:
        classification = Classification.CLEAN

    return ScoringResult(
        score=final_score,
        classification=classification,
        applied_rules=applied_rules,
        triggered_floors=triggered_floors,
        effective_floors=effective_floors,
        category_scores=category_scores,
    )


def calculate_reliability_level(
    url_count: int,
    providers_configured: int,
    applicable_controls: int,
    attempted_controls: int,
    disabled_controls: int,
    failed_controls: int,
    pipeline_status: AnalysisStatus,
) -> ReliabilityLevel:
    """Calculate reliability level per L1-L8 decision tree (v1.2s).

    Args:
        url_count: Number of URLs in content.
        providers_configured: Number of configured reputation providers.
        applicable_controls: Number of applicable reputation controls.
        attempted_controls: Number of controls actually attempted.
        disabled_controls: Number of disabled controls.
        failed_controls: Number of failed controls.
        pipeline_status: Pipeline execution status.

    Returns:
        ReliabilityLevel (LOW, MEDIUM, HIGH).
    """
    if pipeline_status == AnalysisStatus.FAILED:
        return ReliabilityLevel.LOW  # Not used per contract, but safe default

    # L1: No URLs in content
    if url_count == 0:
        return ReliabilityLevel.MEDIUM

    # L2: No providers configured
    if providers_configured == 0:
        return ReliabilityLevel.LOW

    # L3: Providers configured but no applicable controls
    if providers_configured >= 1 and applicable_controls == 0:
        return ReliabilityLevel.MEDIUM

    # L4: Applicable controls exist, none attempted, some disabled
    if applicable_controls >= 1 and attempted_controls == 0 and disabled_controls > 0:
        return ReliabilityLevel.LOW

    # L5: Applicable controls exist, none attempted, none disabled -> BLOCKING ERROR
    if applicable_controls >= 1 and attempted_controls == 0 and disabled_controls == 0:
        # This is a CONTROL_OMITTED error - should not happen in normal operation
        return ReliabilityLevel.LOW

    # L6: Some attempted, all failed
    if attempted_controls > 0 and failed_controls == attempted_controls:
        return ReliabilityLevel.LOW

    # L7: Some attempted, at least one failed and at least one succeeded
    if attempted_controls > 0 and failed_controls > 0 and failed_controls < attempted_controls:
        return ReliabilityLevel.MEDIUM

    # L8: No failures, but some disabled
    if failed_controls == 0 and disabled_controls > 0:
        return ReliabilityLevel.MEDIUM

    # L9: No failures, no disabled, all applicable attempted -> HIGH
    if failed_controls == 0 and disabled_controls == 0 and attempted_controls == applicable_controls:
        return ReliabilityLevel.HIGH

    # Fallback
    return ReliabilityLevel.MEDIUM


def calculate_assessment_status(
    url_count: int,
    indicators: list[Indicator],
    verification_facts: list[VerificationFact],
    reliability_level: ReliabilityLevel,
    pipeline_status: AnalysisStatus,
) -> AssessmentStatus:
    """Calculate assessment status (CONCLUSIVE vs INCONCLUSIVE).

    Independent of reliability_level per contract v1.3.

    Args:
        url_count: Number of URLs in content.
        indicators: Extracted indicators.
        verification_facts: Verification outcomes.
        reliability_level: Calculated reliability level.
        pipeline_status: Pipeline execution status.

    Returns:
        AssessmentStatus.
    """
    if pipeline_status == AnalysisStatus.FAILED:
        return AssessmentStatus.INCONCLUSIVE

    # No URLs -> CONCLUSIVE (analysis based on content only)
    if url_count == 0:
        return AssessmentStatus.CONCLUSIVE

    # Check for risk signals
    has_provider_signal = any(
        i.nature.value == "PROVIDER_SIGNAL" and i.points_awarded > 0
        for i in indicators
    )
    has_structural_signal = any(
        i.nature.value == "STRUCTURAL_SIGNAL" for i in indicators
    )
    has_heuristic_signal = any(
        i.nature.value == "HEURISTIC_DETECTION" for i in indicators
    )

    risk_signal_observed = has_provider_signal or has_structural_signal or has_heuristic_signal

    # Check for determining verdict
    verdict_outcomes = {f.outcome for f in verification_facts}
    has_determining_verdict = any(
        v in verdict_outcomes
        for v in (VerificationOutcome.CLEAN, VerificationOutcome.SUSPICIOUS, VerificationOutcome.MALICIOUS)
    )

    # Convergence check: OTP/PIN + urgency + brand impersonation
    has_otp = any(i.code == "OTP_PIN_REQUEST" for i in indicators)
    has_urgency = any(i.code == "URGENCY_PRESSURE" for i in indicators)
    has_brand_mention = any(i.code == "BRAND_MENTION_INFORMATIVE" for i in indicators)
    convergence = has_otp and has_urgency and has_brand_mention

    if risk_signal_observed:
        return AssessmentStatus.CONCLUSIVE
    if has_determining_verdict:
        return AssessmentStatus.CONCLUSIVE
    if convergence:
        return AssessmentStatus.CONCLUSIVE
    if reliability_level == ReliabilityLevel.HIGH and has_structural_signal:
        return AssessmentStatus.CONCLUSIVE

    return AssessmentStatus.INCONCLUSIVE


def determine_pipeline_status(
    url_count: int,
    providers_configured: int,
    verification_facts: list[VerificationFact],
) -> AnalysisStatus:
    """Determine overall pipeline execution status."""
    if url_count == 0:
        return AnalysisStatus.COMPLETED

    if providers_configured == 0:
        return AnalysisStatus.COMPLETED  # No providers to call

    # Check if any provider failed
    has_failed = any(f.outcome == VerificationOutcome.FAILED for f in verification_facts)
    has_succeeded = any(
        f.outcome in (VerificationOutcome.MALICIOUS, VerificationOutcome.SUSPICIOUS, VerificationOutcome.CLEAN)
        for f in verification_facts
    )

    if has_failed and not has_succeeded:
        return AnalysisStatus.FAILED
    if has_failed and has_succeeded:
        return AnalysisStatus.PARTIAL

    return AnalysisStatus.COMPLETED