"""Tests for deterministic scoring engine."""

from __future__ import annotations

from app.pipeline.scoring import (
    calculate_assessment_status,
    calculate_reliability_level,
    calculate_score,
    determine_pipeline_status,
)
from app.schemas.analysis import (
    AnalysisStatus,
    AssessmentStatus,
    Classification,
    Indicator,
    IndicatorNature,
    ReliabilityLevel,
    RuleValidationStatus,
    VerificationFact,
    VerificationOutcome,
)


def create_indicator(
    code: str,
    category: str,
    nature: IndicatorNature,
    points: int,
    validation_status: RuleValidationStatus = RuleValidationStatus.VALIDEE,
) -> Indicator:
    """Helper to create test indicators."""
    return Indicator(
        code=code,
        category=category,
        nature=nature,
        label=f"Test {code}",
        points_awarded=points,
        evidence_snippet=None,
        validation_status=validation_status,
    )


class TestScoring:
    """Tests for score calculation."""

    def test_clean_score_no_indicators(self):
        """Test score with no indicators."""
        indicators = []
        verification_facts = []
        url_count = 0

        result = calculate_score(indicators, verification_facts, url_count)

        assert result.score == 0
        assert result.classification == Classification.CLEAN
        assert len(result.applied_rules) == 5  # All 5 categories

    def test_suspicious_score_multiple_categories(self):
        """Test score with indicators from multiple categories."""
        indicators = [
            create_indicator(
                "TEST_1", "REPUTATION_URL_DOMAIN",
                IndicatorNature.PROVIDER_SIGNAL, 30
            ),
            create_indicator(
                "TEST_2", "URL_STRUCTURE_ANOMALIES",
                IndicatorNature.STRUCTURAL_SIGNAL, 15
            ),
            create_indicator(
                "TEST_3", "URGENCY_MANIPULATION",
                IndicatorNature.HEURISTIC_DETECTION, 15
            ),
        ]
        verification_facts = []
        url_count = 1

        result = calculate_score(indicators, verification_facts, url_count)

        # 30 + 15 + 15 = 60
        assert result.score == 60
        assert result.classification == Classification.SUSPICIOUS

    def test_critical_score_high(self):
        """Test critical classification at 70+."""
        indicators = [
            create_indicator(
                "TEST_1", "REPUTATION_URL_DOMAIN",
                IndicatorNature.PROVIDER_SIGNAL, 30
            ),
            create_indicator(
                "TEST_2", "SENSITIVE_DATA_REQUEST",
                IndicatorNature.HEURISTIC_DETECTION, 20
            ),
            create_indicator(
                "TEST_3", "URGENCY_MANIPULATION",
                IndicatorNature.HEURISTIC_DETECTION, 15
            ),
            create_indicator(
                "TEST_4", "URL_STRUCTURE_ANOMALIES",
                IndicatorNature.STRUCTURAL_SIGNAL, 10
            ),
        ]
        verification_facts = []
        url_count = 1

        result = calculate_score(indicators, verification_facts, url_count)

        # 30 + 20 + 15 + 10 = 75
        assert result.score == 75
        assert result.classification == Classification.CRITICAL

    def test_category_cap_enforced(self):
        """Test that category caps are enforced."""
        # Create many indicators in same category exceeding cap
        indicators = [
            create_indicator(f"TEST_{i}", "REPUTATION_URL_DOMAIN",
                           IndicatorNature.PROVIDER_SIGNAL, 10)
            for i in range(5)  # 50 points, cap is 30
        ]
        verification_facts = []
        url_count = 1

        result = calculate_score(indicators, verification_facts, url_count)

        # Should be capped at 30
        assert result.score == 30
        rep_rule = next(r for r in result.applied_rules if r.category == "REPUTATION_URL_DOMAIN")
        assert rep_rule.category_score == 30
        assert rep_rule.category_cap == 30

    def test_total_cap_enforced(self):
        """Test that total score is capped at 100."""
        indicators = [
            create_indicator("T1", "REPUTATION_URL_DOMAIN", IndicatorNature.PROVIDER_SIGNAL, 30),
            create_indicator("T2", "URL_STRUCTURE_ANOMALIES", IndicatorNature.STRUCTURAL_SIGNAL, 20),
            create_indicator("T3", "SENSITIVE_DATA_REQUEST", IndicatorNature.HEURISTIC_DETECTION, 20),
            create_indicator("T4", "BRAND_IMPERSONATION_MISMATCH", IndicatorNature.INFORMATIVE_SIGNAL, 15),
            create_indicator("T5", "URGENCY_MANIPULATION", IndicatorNature.HEURISTIC_DETECTION, 15),
            # Extra points that would push over 100
            create_indicator("T6", "REPUTATION_URL_DOMAIN", IndicatorNature.PROVIDER_SIGNAL, 50),
        ]
        verification_facts = []
        url_count = 1

        result = calculate_score(indicators, verification_facts, url_count)

        assert result.score == 100  # Capped at 100

    def test_floor_triggered_malicious(self):
        """Test F1 floor triggered by MALICIOUS reputation."""
        indicators = []
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.MALICIOUS, count=1)
        ]
        url_count = 1

        result = calculate_score(indicators, verification_facts, url_count)

        assert "F1_MALICIOUS_URL" in result.triggered_floors
        # Floors are not applied by default
        assert len(result.effective_floors) == 0

    def test_floor_not_triggered_suspicious(self):
        """Test F1 not triggered by SUSPICIOUS reputation."""
        indicators = []
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.SUSPICIOUS, count=1)
        ]
        url_count = 1

        result = calculate_score(indicators, verification_facts, url_count)

        assert "F1_MALICIOUS_URL" not in result.triggered_floors


class TestReliabilityLevel:
    """Tests for reliability level calculation (L1-L9)."""

    def test_l1_no_urls(self):
        """L1: No URLs -> MEDIUM."""
        level = calculate_reliability_level(
            url_count=0,
            providers_configured=3,
            applicable_controls=10,
            attempted_controls=5,
            disabled_controls=0,
            failed_controls=0,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert level == ReliabilityLevel.MEDIUM

    def test_l2_no_providers_configured(self):
        """L2: No providers configured -> LOW."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=0,
            applicable_controls=0,
            attempted_controls=0,
            disabled_controls=0,
            failed_controls=0,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert level == ReliabilityLevel.LOW

    def test_l3_providers_but_no_applicable_controls(self):
        """L3: Providers configured but no applicable controls -> MEDIUM."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=3,
            applicable_controls=0,
            attempted_controls=0,
            disabled_controls=0,
            failed_controls=0,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert level == ReliabilityLevel.MEDIUM

    def test_l4_applicable_controls_disabled(self):
        """L4: Applicable controls exist, none attempted, some disabled -> LOW."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=3,
            applicable_controls=6,
            attempted_controls=0,
            disabled_controls=2,
            failed_controls=0,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert level == ReliabilityLevel.LOW

    def test_l5_applicable_controls_none_disabled_error(self):
        """L5: Applicable controls exist, none attempted, none disabled -> LOW (CONTROL_OMITTED)."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=3,
            applicable_controls=6,
            attempted_controls=0,
            disabled_controls=0,
            failed_controls=0,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert level == ReliabilityLevel.LOW

    def test_l6_all_attempted_failed(self):
        """L6: Some attempted, all failed -> LOW."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=3,
            applicable_controls=6,
            attempted_controls=4,
            disabled_controls=0,
            failed_controls=4,
            pipeline_status=AnalysisStatus.PARTIAL,
        )
        assert level == ReliabilityLevel.LOW

    def test_l7_some_failed_some_succeeded(self):
        """L7: Some attempted, at least one failed and one succeeded -> MEDIUM."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=3,
            applicable_controls=6,
            attempted_controls=4,
            disabled_controls=0,
            failed_controls=2,
            pipeline_status=AnalysisStatus.PARTIAL,
        )
        assert level == ReliabilityLevel.MEDIUM

    def test_l8_no_failures_some_disabled(self):
        """L8: No failures, but some disabled -> MEDIUM."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=3,
            applicable_controls=6,
            attempted_controls=4,
            disabled_controls=2,
            failed_controls=0,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert level == ReliabilityLevel.MEDIUM

    def test_l9_all_applicable_succeeded(self):
        """L9: No failures, no disabled, all applicable attempted -> HIGH."""
        level = calculate_reliability_level(
            url_count=2,
            providers_configured=3,
            applicable_controls=6,
            attempted_controls=6,
            disabled_controls=0,
            failed_controls=0,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert level == ReliabilityLevel.HIGH


class TestAssessmentStatus:
    """Tests for assessment status (CONCLUSIVE vs INCONCLUSIVE)."""

    def test_conclusive_no_urls(self):
        """No URLs -> CONCLUSIVE."""
        indicators = []
        verification_facts = []
        status = calculate_assessment_status(
            url_count=0,
            indicators=indicators,
            verification_facts=verification_facts,
            reliability_level=ReliabilityLevel.MEDIUM,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert status == AssessmentStatus.CONCLUSIVE

    def test_conclusive_risk_signal_observed(self):
        """Risk signal observed -> CONCLUSIVE."""
        indicators = [
            create_indicator("TEST", "URL_STRUCTURE_ANOMALIES",
                           IndicatorNature.STRUCTURAL_SIGNAL, 10)
        ]
        verification_facts = []
        status = calculate_assessment_status(
            url_count=1,
            indicators=indicators,
            verification_facts=verification_facts,
            reliability_level=ReliabilityLevel.LOW,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert status == AssessmentStatus.CONCLUSIVE

    def test_conclusive_determining_verdict(self):
        """Determining verdict (CLEAN/SUSPICIOUS/MALICIOUS) -> CONCLUSIVE."""
        indicators = []
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.CLEAN, count=1)
        ]
        status = calculate_assessment_status(
            url_count=1,
            indicators=indicators,
            verification_facts=verification_facts,
            reliability_level=ReliabilityLevel.LOW,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert status == AssessmentStatus.CONCLUSIVE

    def test_conclusive_high_reliability_structural(self):
        """HIGH reliability + structural signal -> CONCLUSIVE."""
        indicators = [
            create_indicator("TEST", "URL_STRUCTURE_ANOMALIES",
                           IndicatorNature.STRUCTURAL_SIGNAL, 10)
        ]
        verification_facts = []
        status = calculate_assessment_status(
            url_count=1,
            indicators=indicators,
            verification_facts=verification_facts,
            reliability_level=ReliabilityLevel.HIGH,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert status == AssessmentStatus.CONCLUSIVE

    def test_inconclusive_no_signals(self):
        """No signals, no determining verdict -> INCONCLUSIVE."""
        indicators = [
            create_indicator("BRAND_MENTION_INFORMATIVE", "BRAND_IMPERSONATION_MISMATCH",
                           IndicatorNature.INFORMATIVE_SIGNAL, 0)
        ]
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.UNDETERMINED, count=1)
        ]
        status = calculate_assessment_status(
            url_count=1,
            indicators=indicators,
            verification_facts=verification_facts,
            reliability_level=ReliabilityLevel.MEDIUM,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert status == AssessmentStatus.INCONCLUSIVE

    def test_conclusive_convergence_otp_urgency_brand(self):
        """Convergence: OTP + urgency + brand mention -> CONCLUSIVE."""
        indicators = [
            create_indicator("OTP_PIN_REQUEST", "SENSITIVE_DATA_REQUEST",
                           IndicatorNature.HEURISTIC_DETECTION, 20),
            create_indicator("URGENCY_PRESSURE", "URGENCY_MANIPULATION",
                           IndicatorNature.HEURISTIC_DETECTION, 15),
            create_indicator("BRAND_MENTION_INFORMATIVE", "BRAND_IMPERSONATION_MISMATCH",
                           IndicatorNature.INFORMATIVE_SIGNAL, 0),
        ]
        verification_facts = []
        status = calculate_assessment_status(
            url_count=1,
            indicators=indicators,
            verification_facts=verification_facts,
            reliability_level=ReliabilityLevel.LOW,
            pipeline_status=AnalysisStatus.COMPLETED,
        )
        assert status == AssessmentStatus.CONCLUSIVE


class TestPipelineStatus:
    """Tests for pipeline status determination."""

    def test_completed_no_urls(self):
        """No URLs -> COMPLETED."""
        status = determine_pipeline_status(
            url_count=0,
            providers_configured=3,
            verification_facts=[],
        )
        assert status == AnalysisStatus.COMPLETED

    def test_completed_no_providers(self):
        """No providers configured -> COMPLETED."""
        status = determine_pipeline_status(
            url_count=2,
            providers_configured=0,
            verification_facts=[],
        )
        assert status == AnalysisStatus.COMPLETED

    def test_failed_all_failed(self):
        """All providers failed -> FAILED."""
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.FAILED, count=2)
        ]
        status = determine_pipeline_status(
            url_count=2,
            providers_configured=2,
            verification_facts=verification_facts,
        )
        assert status == AnalysisStatus.FAILED

    def test_partial_some_failed_some_succeeded(self):
        """Some failed, some succeeded -> PARTIAL."""
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.FAILED, count=1),
            VerificationFact(outcome=VerificationOutcome.MALICIOUS, count=1),
        ]
        status = determine_pipeline_status(
            url_count=2,
            providers_configured=2,
            verification_facts=verification_facts,
        )
        assert status == AnalysisStatus.PARTIAL

    def test_completed_all_succeeded(self):
        """All succeeded -> COMPLETED."""
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.MALICIOUS, count=1),
            VerificationFact(outcome=VerificationOutcome.CLEAN, count=1),
        ]
        status = determine_pipeline_status(
            url_count=2,
            providers_configured=2,
            verification_facts=verification_facts,
        )
        assert status == AnalysisStatus.COMPLETED