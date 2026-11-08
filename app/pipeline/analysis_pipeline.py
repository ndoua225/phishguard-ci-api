"""Main analysis pipeline orchestrating all components."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import uuid4

from app.config import settings
from app.pipeline.indicators import extract_indicators
from app.pipeline.scoring import (
    calculate_assessment_status,
    calculate_reliability_level,
    calculate_score,
    determine_pipeline_status,
)
from app.pipeline.url_extraction import ExtractedURL, extract_urls
from app.schemas.analysis import (
    AnalysisStatus,
    DeterministicResult,
    Indicator,
    ScoringVariant,
    VerificationFact,
    VerificationOutcome,
)


@dataclass(slots=True)
class PipelineResult:
    """Complete result of the analysis pipeline."""

    analysis_ref: str
    deterministic_result: DeterministicResult
    indicators: list[Indicator]
    verification_facts: list[VerificationFact]
    verifications_attempted: int
    disabled_controls: int
    providers_configured: int
    url_count: int
    pipeline_status: AnalysisStatus
    scoring_version: str
    template_version: str


class ReputationProvider:
    """Base class for reputation providers (disabled by default)."""

    def __init__(self, name: str, enabled: bool = False):
        self.name = name
        self.enabled = enabled

    async def check(self, urls: list[ExtractedURL]) -> list[VerificationFact]:
        """Check URLs against reputation service."""
        if not self.enabled:
            return [
                VerificationFact(
                    outcome=VerificationOutcome.DISABLED,
                    count=len(urls),
                )
            ]
        raise NotImplementedError("Provider not implemented")


class MockProvider(ReputationProvider):
    """Mock provider for testing (returns UNKNOWN)."""

    def __init__(self) -> None:
        super().__init__("mock", enabled=False)

    async def check(self, urls: list[ExtractedURL]) -> list[VerificationFact]:
        return [
            VerificationFact(
                outcome=VerificationOutcome.UNDETERMINED,
                count=len(urls),
            )
        ]


# Provider registry (all disabled by default)
PROVIDERS: dict[str, ReputationProvider] = {
    "web_risk": ReputationProvider("web_risk", enabled=False),
    "urlhaus": ReputationProvider("urlhaus", enabled=False),
    "mock": MockProvider(),
}


async def run_analysis_pipeline(
    content: str,
    content_type: str,
) -> PipelineResult:
    """Run the complete deterministic analysis pipeline.

    Args:
        content: Normalized input text.
        content_type: Type of content (SMS, MESSAGE, EMAIL, URL).

    Returns:
        PipelineResult with all analysis outputs.
    """
    analysis_ref = str(uuid4())

    # 1. Extract URLs (passive, no network)
    urls = extract_urls(content, max_urls=settings.max_urls_per_analysis)
    url_count = len(urls)

    # 2. Run reputation checks (all disabled by default)
    verification_facts: list[VerificationFact] = []
    verifications_attempted = 0
    disabled_controls = 0
    providers_configured = sum(1 for p in PROVIDERS.values() if p.enabled)

    for provider in PROVIDERS.values():
        if provider.enabled:
            facts = await provider.check(urls)
            verification_facts.extend(facts)
            verifications_attempted += sum(f.count for f in facts)
        else:
            # Count as disabled
            disabled_controls += len(urls)

    # If no providers configured, add NO_PROVIDER_CONFIGURED fact
    if providers_configured == 0 and url_count > 0:
        verification_facts.append(
            VerificationFact(
                outcome=VerificationOutcome.NO_PROVIDER_CONFIGURED,
                count=0,
            )
        )

    # 3. Extract indicators
    verification_facts_list: list[dict[str, str]] = [
        {"outcome": f.outcome.value} for f in verification_facts
    ]
    extraction_result = extract_indicators(content, urls, verification_facts_list)
    indicators = extraction_result.indicators

    # 4. Calculate score and classification
    scoring_result = calculate_score(indicators, verification_facts, url_count)

    # 5. Determine pipeline status
    pipeline_status = determine_pipeline_status(
        url_count, providers_configured, verification_facts
    )

    # 6. Calculate reliability level
    applicable_controls = sum(
        1 for p in PROVIDERS.values() if p.enabled
    ) * url_count if url_count > 0 else 0
    attempted_controls = verifications_attempted
    failed_controls = sum(
        1 for f in verification_facts
        if f.outcome == VerificationOutcome.FAILED
    )

    reliability_level = calculate_reliability_level(
        url_count=url_count,
        providers_configured=providers_configured,
        applicable_controls=applicable_controls,
        attempted_controls=attempted_controls,
        disabled_controls=disabled_controls,
        failed_controls=failed_controls,
        pipeline_status=pipeline_status,
    )

    # 7. Calculate assessment status
    assessment_status = calculate_assessment_status(
        url_count=url_count,
        indicators=indicators,
        verification_facts=verification_facts,
        reliability_level=reliability_level,
        pipeline_status=pipeline_status,
    )

    # 8. Build deterministic result
    deterministic_result = DeterministicResult(
        score=scoring_result.score,
        classification=scoring_result.classification,
        pipeline_status=pipeline_status,
        reliability_level=reliability_level,
        assessment_status=assessment_status,
        scoring_variant=ScoringVariant.VARIANTE_B,
        scoring_version="1.2.0",
        applied_rules=scoring_result.applied_rules,
        triggered_floors=scoring_result.triggered_floors,
        effective_floors=scoring_result.effective_floors,
    )

    return PipelineResult(
        analysis_ref=analysis_ref,
        deterministic_result=deterministic_result,
        indicators=indicators,
        verification_facts=verification_facts,
        verifications_attempted=verifications_attempted,
        disabled_controls=disabled_controls,
        providers_configured=providers_configured,
        url_count=url_count,
        pipeline_status=pipeline_status,
        scoring_version="1.2.0",
        template_version="1.0.0",
    )