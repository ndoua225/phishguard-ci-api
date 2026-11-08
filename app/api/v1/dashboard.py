"""Dashboard API routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.auth import get_current_user, require_admin
from app.db.session import get_session_dependency
from app.models import ActivityLog, Analysis, ApiUsage, User, UserRole

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/user/stats")
async def get_user_stats(
    request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Get current user's dashboard statistics."""
    # Total analyses
    total_result = await db.execute(
        select(func.count(Analysis.id)).where(Analysis.user_id == current_user.id)
    )
    total_analyses = total_result.scalar_one() or 0

    # Analyses by classification
    class_result = await db.execute(
        select(Analysis.classification, func.count(Analysis.id))
        .where(Analysis.user_id == current_user.id)
        .group_by(Analysis.classification)
    )
    by_classification = {row[0].value: row[1] for row in class_result.all()}

    # Analyses by content type
    type_result = await db.execute(
        select(Analysis.content_type, func.count(Analysis.id))
        .where(Analysis.user_id == current_user.id)
        .group_by(Analysis.content_type)
    )
    by_content_type = {row[0].value: row[1] for row in type_result.all()}

    # Recent analyses count (last 7 days)
    week_ago = datetime.now(UTC) - timedelta(days=7)
    recent_result = await db.execute(
        select(func.count(Analysis.id)).where(
            Analysis.user_id == current_user.id,
            Analysis.created_at >= week_ago,
        )
    )
    recent_count = recent_result.scalar_one() or 0

    return {
        "total_analyses": total_analyses,
        "by_classification": by_classification,
        "by_content_type": by_content_type,
        "recent_7_days": recent_count,
    }


@router.get("/user/recent")
async def get_user_recent_analyses(
    request: Request,
    limit: int = Query(10, ge=1, le=100),
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    """Get current user's recent analyses."""
    result = await db.execute(
        select(Analysis)
        .where(Analysis.user_id == current_user.id)
        .order_by(Analysis.created_at.desc())
        .limit(limit)
    )
    analyses = result.scalars().all()

    return [
        {
            "analysis_ref": str(a.analysis_ref),
            "content_type": a.content_type.value,
            "status": a.status.value,
            "score": a.score,
            "classification": a.classification.value,
            "reliability_level": a.reliability_level.value,
            "created_at": a.created_at.isoformat(),
        }
        for a in analyses
    ]


@router.get("/admin/stats")
async def get_admin_stats(
    request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Get admin dashboard statistics."""
    # Total users
    total_users_result = await db.execute(select(func.count(User.id)))
    total_users = total_users_result.scalar_one() or 0

    # Active users
    active_users_result = await db.execute(
        select(func.count(User.id)).where(User.is_active)
    )
    active_users = active_users_result.scalar_one() or 0

    # Total analyses
    total_analyses_result = await db.execute(select(func.count(Analysis.id)))
    total_analyses = total_analyses_result.scalar_one() or 0

    # Analyses today
    today = datetime.now(UTC).date()
    today_start = datetime.combine(today, datetime.min.time(), tzinfo=UTC)
    today_end = datetime.combine(today, datetime.max.time(), tzinfo=UTC)
    analyses_today_result = await db.execute(
        select(func.count(Analysis.id)).where(
            Analysis.created_at >= today_start,
            Analysis.created_at <= today_end,
        )
    )
    analyses_today = analyses_today_result.scalar_one() or 0

    # Analyses by classification
    class_result = await db.execute(
        select(Analysis.classification, func.count(Analysis.id))
        .group_by(Analysis.classification)
    )
    by_classification = {row[0].value: row[1] for row in class_result.all()}

    # Average score
    avg_score_result = await db.execute(select(func.avg(Analysis.score)))
    avg_score: float = round(avg_score_result.scalar_one() or 0, 1)

    # Quota usage
    quota_result = await db.execute(
        select(
            func.sum(ApiUsage.analysis_count).label("total"),
            func.count(func.distinct(ApiUsage.user_id)).label("active_users"),
        ).where(ApiUsage.date >= today_start)
    )
    quota_row = quota_result.one()
    quota_usage: dict[str, int] = {
        "total_analyses_today": quota_row.total or 0,
        "active_users_today": quota_row.active_users or 0,
    }

    return {
        "users": {
            "total": total_users,
            "active": active_users,
        },
        "analyses": {
            "total": total_analyses,
            "today": analyses_today,
            "by_classification": by_classification,
            "average_score": avg_score,
        },
        "quota_usage": quota_usage,
    }


@router.get("/admin/users")
async def list_users(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    role: UserRole | None = Query(None),
    is_active: bool | None = Query(None),
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(require_admin),
) -> list[dict[str, Any]]:
    """List users (admin only)."""
    query = select(User).order_by(User.created_at.desc())

    if role:
        query = query.where(User.role == role)
    if is_active is not None:
        query = query.where(User.is_active == is_active)

    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    users = result.scalars().all()

    return [
        {
            "id": str(u.id),
            "email": u.email,
            "role": u.role.value,
            "is_active": u.is_active,
            "is_test_account": u.is_test_account,
            "created_at": u.created_at.isoformat(),
            "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "failed_login_attempts": u.failed_login_attempts,
        }
        for u in users
    ]


@router.get("/admin/users/{user_id}")
async def get_user_detail(
    user_id: UUID,
    request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Get user detail (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get user's analyses count
    analyses_count_result = await db.execute(
        select(func.count(Analysis.id)).where(Analysis.user_id == user.id)
    )
    analyses_count = analyses_count_result.scalar_one() or 0

    # Get quota usage
    quota_result = await db.execute(
        select(func.sum(ApiUsage.analysis_count)).where(ApiUsage.user_id == user.id)
    )
    total_quota_used = quota_result.scalar_one() or 0

    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
        "is_test_account": user.is_test_account,
        "created_at": user.created_at.isoformat(),
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
        "failed_login_attempts": user.failed_login_attempts,
        "analyses_count": analyses_count,
        "total_quota_used": total_quota_used,
    }


@router.patch("/admin/users/{user_id}")
async def update_user(
    user_id: UUID,
    request: Request,
    data: dict[str, Any],
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Update user (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent self-demotion for super admin
    if user.id == current_user.id and current_user.role == UserRole.SUPER_ADMIN:
        if "role" in data and data["role"] != UserRole.SUPER_ADMIN.value:
            raise HTTPException(
                status_code=400, detail="Cannot demote self from super admin"
            )

    # Update fields
    if "is_active" in data:
        user.is_active = data["is_active"]
    if "role" in data and current_user.role == UserRole.SUPER_ADMIN:
        user.role = UserRole(data["role"])

    await db.commit()
    await db.refresh(user)

    return {
        "id": str(user.id),
        "email": user.email,
        "role": user.role.value,
        "is_active": user.is_active,
    }


@router.get("/admin/activity")
async def get_activity_logs(
    request: Request,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: str | None = Query(None),
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(require_admin),
) -> list[dict[str, Any]]:
    """Get activity logs (admin only)."""
    query = select(ActivityLog).order_by(ActivityLog.created_at.desc())

    if event_type:
        query = query.where(ActivityLog.event_type == event_type)

    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    logs = result.scalars().all()

    return [
        {
            "id": str(log.id),
            "user_id": str(log.user_id) if log.user_id else None,
            "event_type": log.event_type,
            "event_metadata": log.event_metadata,
            "ip_hash": log.ip_hash,
            "created_at": log.created_at.isoformat(),
        }
        for log in logs
    ]