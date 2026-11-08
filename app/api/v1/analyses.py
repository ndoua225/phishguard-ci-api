"""Analysis API routes."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent.template_explainer import TEMPLATE_VERSION, generate_explanation
from app.api.v1.auth import get_current_user
from app.config import settings
from app.db.session import get_session_dependency
from app.models import Analysis, AnalysisResult, User
from app.pipeline.analysis_pipeline import run_analysis_pipeline
from app.schemas.analysis import (
    AnalysisRequest,
    AnalysisResponse,
    ContentType,
    ExplainRequest,
    Indicator,
)
from app.services.quota_service import check_analysis_quota, record_analysis_usage

router = APIRouter(prefix="/analyses", tags=["analyses"])


@router.post("", response_model=AnalysisResponse, status_code=status.HTTP_201_CREATED)
async def create_analysis(
    request: AnalysisRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> AnalysisResponse:
    """Submit content for phishing/fraud analysis."""
    # Validate content length
    if len(request.content) > settings.max_input_chars:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Content exceeds maximum length of {settings.max_input_chars} characters",
        )

    # Check quota
    allowed, remaining, retry_after = await check_analysis_quota(
        db, current_user, settings.max_analyses_per_day
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Daily analysis quota exceeded",
            headers={"Retry-After": str(retry_after)} if retry_after else None,
        )

    # Run analysis pipeline
    pipeline_result = await run_analysis_pipeline(
        content=request.content,
        content_type=request.content_type.value,
    )

    # Generate explanation (TemplateExplainer by default)
    explain_request = ExplainRequest(
        contract_version="1.3",
        analysis_ref=UUID(pipeline_result.analysis_ref),
        content_type=ContentType(request.content_type),
        language="fr",
        deterministic_result=pipeline_result.deterministic_result,
        indicators=pipeline_result.indicators,
        verification_facts=pipeline_result.verification_facts,
        verifications_attempted=pipeline_result.verifications_attempted,
        disabled_controls=pipeline_result.disabled_controls,
        providers_configured=pipeline_result.providers_configured,
        url_count=pipeline_result.url_count,
    )

    # Hermes integration would go here (behind D16/D21 gates)
    # For now, always use TemplateExplainer
    explain_response = generate_explanation(explain_request)
    explanation_source = "TEMPLATE"
    explanation = explain_response.summary or ""

    # Record quota usage
    await record_analysis_usage(db, current_user, UUID(pipeline_result.analysis_ref))

    # Persist analysis
    analysis = Analysis(
        user_id=current_user.id,
        analysis_ref=pipeline_result.analysis_ref,
        content_type=ContentType(request.content_type),
        status=pipeline_result.pipeline_status,
        score=pipeline_result.deterministic_result.score,
        classification=pipeline_result.deterministic_result.classification,
        reliability_level=pipeline_result.deterministic_result.reliability_level,
        assessment_status=pipeline_result.deterministic_result.assessment_status,
        scoring_version=pipeline_result.scoring_version,
        template_version=pipeline_result.template_version,
        explanation_source=explanation_source,
        indicators=[i.model_dump() for i in pipeline_result.indicators],
        verification_facts=[f.model_dump() for f in pipeline_result.verification_facts],
        verifications_attempted=pipeline_result.verifications_attempted,
        disabled_controls=pipeline_result.disabled_controls,
        providers_configured=pipeline_result.providers_configured,
        url_count=pipeline_result.url_count,
    )

    db.add(analysis)
    await db.flush()

    # Persist analysis result with explanation
    result = AnalysisResult(
        analysis_id=analysis.id,
        deterministic_result=pipeline_result.deterministic_result.model_dump(),
        indicators=[i.model_dump() for i in pipeline_result.indicators],
        explanation=explanation,
        explanation_source=explanation_source,
        template_version=pipeline_result.template_version,
    )

    db.add(result)
    await db.commit()

    return AnalysisResponse(
        analysis_ref=UUID(pipeline_result.analysis_ref),
        status=pipeline_result.pipeline_status,
        score=pipeline_result.deterministic_result.score,
        classification=pipeline_result.deterministic_result.classification,
        reliability_level=pipeline_result.deterministic_result.reliability_level,
        assessment_status=pipeline_result.deterministic_result.assessment_status,
        indicators=pipeline_result.indicators,
        explanation=explanation,
        explanation_source=explanation_source,
        template_version=pipeline_result.template_version,
        scoring_version=pipeline_result.scoring_version,
    )


@router.get("", response_model=list[AnalysisResponse])
async def list_analyses(
    http_request: Request,
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> list[AnalysisResponse]:
    """List user's analyses."""
    result = await db.execute(
        select(Analysis)
        .where(Analysis.user_id == current_user.id)
        .order_by(desc(Analysis.created_at))
        .limit(limit)
        .offset(offset)
    )
    analyses = result.scalars().all()

    return [
        AnalysisResponse(
            analysis_ref=UUID(a.analysis_ref),
            status=a.status,
            score=a.score,
            classification=a.classification,
            reliability_level=a.reliability_level,
            assessment_status=a.assessment_status,
            indicators=[Indicator.model_validate(i) for i in a.indicators],
            explanation=a.results[0].explanation if a.results else "",
            explanation_source=a.explanation_source,
            template_version=a.template_version,
            scoring_version=a.scoring_version,
        )
        for a in analyses
    ]


@router.get("/{analysis_ref}", response_model=AnalysisResponse)
async def get_analysis(
    analysis_ref: UUID,
    http_request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> AnalysisResponse:
    """Get a specific analysis by reference."""
    result = await db.execute(
        select(Analysis).where(
            Analysis.analysis_ref == str(analysis_ref),
            Analysis.user_id == current_user.id,
        )
    )
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )

    # Regenerate explanation with current template version (per D20)
    from app.agent.template_explainer import generate_explanation
    from app.schemas.analysis import DeterministicResult, ExplainRequest

    explain_request = ExplainRequest(
        contract_version="1.3",
        analysis_ref=analysis_ref,
        content_type=analysis.content_type,
        language="fr",
        deterministic_result=DeterministicResult.model_validate(analysis.results[0].deterministic_result)
        if analysis.results
        else DeterministicResult(
            score=analysis.score,
            classification=analysis.classification,
            pipeline_status=analysis.status,
            reliability_level=analysis.reliability_level,
            assessment_status=analysis.assessment_status,
            scoring_variant="VARIANTE_B",
            scoring_version=analysis.scoring_version,
            applied_rules=[],
            triggered_floors=[],
            effective_floors=[],
        ),
        indicators=[Indicator.model_validate(i) for i in analysis.indicators],
        verification_facts=analysis.verification_facts,
        verifications_attempted=analysis.verifications_attempted,
        disabled_controls=analysis.disabled_controls,
        providers_configured=analysis.providers_configured,
        url_count=analysis.url_count,
    )

    explain_response = generate_explanation(explain_request)
    explanation = explain_response.summary or ""
    explanation_source = "TEMPLATE"  # Regenerated with TemplateExplainer

    return AnalysisResponse(
        analysis_ref=analysis_ref,
        status=analysis.status,
        score=analysis.score,
        classification=analysis.classification,
        reliability_level=analysis.reliability_level,
        assessment_status=analysis.assessment_status,
        indicators=[Indicator.model_validate(i) for i in analysis.indicators],
        explanation=explanation,
        explanation_source=explanation_source,
        template_version=TEMPLATE_VERSION,
        scoring_version=analysis.scoring_version,
    )


@router.delete("/{analysis_ref}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_analysis(
    analysis_ref: UUID,
    http_request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> None:
    """Delete an analysis (user can only delete own)."""
    result = await db.execute(
        select(Analysis).where(
            Analysis.analysis_ref == str(analysis_ref),
            Analysis.user_id == current_user.id,
        )
    )
    analysis = result.scalar_one_or_none()

    if not analysis:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Analysis not found",
        )

    await db.delete(analysis)
    await db.commit()