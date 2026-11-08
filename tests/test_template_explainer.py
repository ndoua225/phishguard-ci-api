"""Tests for TemplateExplainer."""

from __future__ import annotations

from uuid import uuid4

from app.agent.template_explainer import (
    TEMPLATE_VERSION,
    generate_explanation,
)
from app.schemas.analysis import (
    AnalysisStatus,
    AssessmentStatus,
    Classification,
    DeterministicResult,
    ExplainRequest,
    ExplainResponseStatus,
    Indicator,
    IndicatorNature,
    ReliabilityLevel,
    RuleValidationStatus,
    ScoringVariant,
    VerificationFact,
    VerificationOutcome,
)


def create_test_request(
    score: int = 85,
    classification: Classification = Classification.CRITICAL,
    pipeline_status: AnalysisStatus = AnalysisStatus.PARTIAL,
    reliability_level: ReliabilityLevel = ReliabilityLevel.MEDIUM,
    assessment_status: AssessmentStatus = AssessmentStatus.CONCLUSIVE,
    indicators: list[Indicator] | None = None,
    verification_facts: list[VerificationFact] | None = None,
) -> ExplainRequest:
    """Create a test ExplainRequest."""
    if indicators is None:
        indicators = [
            Indicator(
                code="REPUTATION_MALICIOUS_EXTERNAL",
                category="REPUTATION_URL_DOMAIN",
                nature=IndicatorNature.PROVIDER_SIGNAL,
                label="Lien signalé malveillant par un service de réputation",
                points_awarded=30,
                evidence_snippet=None,
                validation_status=RuleValidationStatus.VALIDEE,
            ),
            Indicator(
                code="OTP_PIN_REQUEST",
                category="SENSITIVE_DATA_REQUEST",
                nature=IndicatorNature.HEURISTIC_DETECTION,
                label="Formulation explicite de demande de code PIN",
                points_awarded=20,
                evidence_snippet="code PIN",
                validation_status=RuleValidationStatus.VALIDEE,
            ),
        ]
    if verification_facts is None:
        verification_facts = [
            VerificationFact(outcome=VerificationOutcome.MALICIOUS, count=1),
            VerificationFact(outcome=VerificationOutcome.FAILED, count=1),
        ]

    return ExplainRequest(
        contract_version="1.3",
        analysis_ref=uuid4(),
        content_type="SMS",
        language="fr",
        deterministic_result=DeterministicResult(
            score=score,
            classification=classification,
            pipeline_status=pipeline_status,
            reliability_level=reliability_level,
            assessment_status=assessment_status,
            scoring_variant=ScoringVariant.VARIANTE_B,
            scoring_version="1.2.0",
            applied_rules=[],
            triggered_floors=["F1_MALICIOUS_URL"],
            effective_floors=[],
        ),
        indicators=indicators,
        verification_facts=verification_facts,
        verifications_attempted=2,
        disabled_controls=1,
        providers_configured=3,
        url_count=2,
    )


class TestTemplateExplainer:
    """Tests for deterministic TemplateExplainer."""

    def test_generate_explanation_ok_status(self):
        """Test that explanation generation returns OK status."""
        request = create_test_request()
        response = generate_explanation(request)

        assert response.status == ExplainResponseStatus.OK
        assert response.reason_code is None

    def test_summary_contains_key_info(self):
        """Test that summary contains score, classification, pipeline status, reliability, assessment."""
        request = create_test_request(
            score=85,
            classification=Classification.CRITICAL,
            pipeline_status=AnalysisStatus.PARTIAL,
            reliability_level=ReliabilityLevel.MEDIUM,
            assessment_status=AssessmentStatus.CONCLUSIVE,
        )
        response = generate_explanation(request)

        summary = response.summary
        assert "85" in summary
        assert "CRITICAL" in summary
        assert "PARTIELLE" in summary or "PARTIAL" in summary
        assert "MOYENNE" in summary or "MEDIUM" in summary
        assert "CONCLUSIVE" in summary

    def test_explanations_per_indicator(self):
        """Test that explanations are generated for each indicator."""
        request = create_test_request()
        response = generate_explanation(request)

        assert response.explanations is not None
        assert len(response.explanations) == len(request.indicators)

        for explanation in response.explanations:
            assert "indicator_code" in explanation
            assert "text" in explanation
            assert len(explanation["text"]) > 0

    def test_explanation_content_for_known_indicators(self):
        """Test that known indicators get proper French explanations."""
        request = create_test_request()
        response = generate_explanation(request)

        explanations_by_code = {
            e["indicator_code"]: e["text"] for e in response.explanations
        }

        # Check REPUTATION_MALICIOUS_EXTERNAL
        assert "REPUTATION_MALICIOUS_EXTERNAL" in explanations_by_code
        text = explanations_by_code["REPUTATION_MALICIOUS_EXTERNAL"]
        assert "Google Web Risk" in text
        assert "30 points" in text

        # Check OTP_PIN_REQUEST
        assert "OTP_PIN_REQUEST" in explanations_by_code
        text = explanations_by_code["OTP_PIN_REQUEST"]
        assert "code PIN" in text
        assert "20 points" in text

    def test_limitations_generated(self):
        """Test that limitations are generated based on context."""
        request = create_test_request(
            pipeline_status=AnalysisStatus.PARTIAL,
        )
        response = generate_explanation(request)

        assert response.limitations is not None
        assert len(response.limitations) > 0

        # Should mention simulation
        limitations_text = " ".join(response.limitations)
        assert "simulation" in limitations_text.lower()

        # Should mention partial pipeline
        assert any("PARTIAL" in lim or "partiel" in lim.lower() for lim in response.limitations)

    def test_recommendations_generated(self):
        """Test that standard recommendations are included."""
        request = create_test_request()
        response = generate_explanation(request)

        assert response.recommendations is not None
        assert len(response.recommendations) >= 3

        recs_text = " ".join(response.recommendations)
        assert "cliquez" in recs_text.lower()
        assert "code secret PIN" in recs_text
        assert "application officielle" in recs_text.lower()

    def test_different_classifications(self):
        """Test explanations for different classifications."""
        for classification, expected_fr in [
            (Classification.CLEAN, "FAIBLE"),
            (Classification.SUSPICIOUS, "MODÉRÉ"),
            (Classification.CRITICAL, "CRITICAL"),
        ]:
            request = create_test_request(classification=classification)
            response = generate_explanation(request)
            assert expected_fr in response.summary

    def test_different_reliability_levels(self):
        """Test explanations for different reliability levels."""
        for reliability, expected_fr in [
            (ReliabilityLevel.LOW, "FAIBLE"),
            (ReliabilityLevel.MEDIUM, "MOYENNE"),
            (ReliabilityLevel.HIGH, "FORTE"),
        ]:
            request = create_test_request(reliability_level=reliability)
            response = generate_explanation(request)
            assert expected_fr in response.summary

    def test_different_assessment_statuses(self):
        """Test explanations for different assessment statuses."""
        for assessment, expected_fr in [
            (AssessmentStatus.CONCLUSIVE, "CONCLUSIVE"),
            (AssessmentStatus.INCONCLUSIVE, "INCONCLUSIVE"),
        ]:
            request = create_test_request(assessment_status=assessment)
            response = generate_explanation(request)
            assert expected_fr in response.summary

    def test_template_version_constant(self):
        """Test that TEMPLATE_VERSION constant is defined."""
        assert TEMPLATE_VERSION == "1.0.0"

    def test_explanation_source_not_in_output(self):
        """Test that explanation_source is not in TemplateExplainer output (FastAPI adds it)."""
        request = create_test_request()
        response = generate_explanation(request)

        # TemplateExplainer doesn't include explanation_source
        assert not hasattr(response, "explanation_source")

    def test_french_language_output(self):
        """Test that output is in French."""
        request = create_test_request()
        response = generate_explanation(request)

        # Check for French words
        full_text = response.summary + " " + " ".join(response.limitations or []) + " " + " ".join(response.recommendations or [])
        french_words = ["est", "un", "le", "la", "les", "de", "du", "et", "ou", "pour", "avec", "sur", "dans"]
        assert any(word in full_text.lower() for word in french_words)

    def test_no_prohibited_content_in_output(self):
        """Test that output doesn't contain prohibited content (scores, URLs, etc.)."""
        request = create_test_request()
        response = generate_explanation(request)

        full_text = response.summary
        if response.explanations:
            for exp in response.explanations:
                full_text += " " + exp["text"]
        if response.limitations:
            full_text += " " + " ".join(response.limitations)
        if response.recommendations:
            full_text += " " + " ".join(response.recommendations)

        # Should not contain detailed scoring numbers beyond what's in summary
        # Should not contain URLs or domains
        assert "http://" not in full_text
        assert "https://" not in full_text
        # Should not contain "sûr", "légitime", "garanti" etc.
        prohibited = ["sûr", "légitime", "sans danger", "garanti"]
        for word in prohibited:
            assert word not in full_text.lower()


class TestTemplateExplainerEdgeCases:
    """Tests for edge cases in TemplateExplainer."""

    def test_empty_indicators(self):
        """Test with empty indicators list."""
        request = create_test_request(indicators=[])
        response = generate_explanation(request)

        assert response.status == ExplainResponseStatus.OK
        assert response.explanations == []

    def test_many_indicators(self):
        """Test with many indicators of known types."""
        indicators = [
            Indicator(
                code="REPUTATION_MALICIOUS_EXTERNAL",
                category="REPUTATION_URL_DOMAIN",
                nature=IndicatorNature.PROVIDER_SIGNAL,
                label="Test indicator",
                points_awarded=5,
                evidence_snippet=None,
                validation_status=RuleValidationStatus.VALIDEE,
            )
            for i in range(10)
        ]
        request = create_test_request(indicators=indicators)
        response = generate_explanation(request)

        assert len(response.explanations) == 10

    def test_all_pipeline_statuses(self):
        """Test all pipeline status values."""
        for status in [AnalysisStatus.COMPLETED, AnalysisStatus.PARTIAL, AnalysisStatus.FAILED]:
            request = create_test_request(pipeline_status=status)
            response = generate_explanation(request)
            assert response.status == ExplainResponseStatus.OK

    def test_all_reliability_levels(self):
        """Test all reliability level values."""
        for level in [ReliabilityLevel.LOW, ReliabilityLevel.MEDIUM, ReliabilityLevel.HIGH]:
            request = create_test_request(reliability_level=level)
            response = generate_explanation(request)
            assert response.status == ExplainResponseStatus.OK