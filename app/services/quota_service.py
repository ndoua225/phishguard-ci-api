"""Quota management service."""

from __future__ import annotations

from datetime import UTC, date, datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiUsage, User


class QuotaExceeded(Exception):
    """Raised when quota is exceeded."""

    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.retry_after = retry_after


async def check_analysis_quota(
    db: AsyncSession,
    user: User,
    max_per_day: int,
) -> tuple[bool, int, int | None]:
    """Check if user has remaining analysis quota for today.

    Returns:
        (allowed, remaining, retry_after_seconds)
    """
    today = date.today()
    today_start = datetime.combine(today, datetime.min.time(), tzinfo=UTC)
    today_end = datetime.combine(today, datetime.max.time(), tzinfo=UTC)

    result = await db.execute(
        select(func.coalesce(func.sum(ApiUsage.analysis_count), 0)).where(
            ApiUsage.user_id == user.id,
            ApiUsage.date >= today_start,
            ApiUsage.date <= today_end,
        )
    )
    used_today = result.scalar_one() or 0

    remaining = max_per_day - used_today

    if remaining <= 0:
        # Calculate seconds until midnight
        now = datetime.now(UTC)
        seconds_until_midnight = int((today_end - now).total_seconds()) + 1
        return False, 0, seconds_until_midnight

    return True, remaining, None


async def record_analysis_usage(
    db: AsyncSession,
    user: User,
    analysis_id: UUID,
) -> None:
    """Record an analysis usage for quota tracking."""
    today = date.today()
    today_start = datetime.combine(today, datetime.min.time(), tzinfo=UTC)

    # Try to find existing record for today
    result = await db.execute(
        select(ApiUsage).where(
            ApiUsage.user_id == user.id,
            ApiUsage.date >= today_start,
        )
    )
    usage = result.scalar_one_or_none()

    if usage:
        usage.analysis_count += 1
        usage.analysis_id = analysis_id
    else:
        usage = ApiUsage(
            user_id=user.id,
            date=today_start,
            analysis_count=1,
            analysis_id=analysis_id,
        )
        db.add(usage)

    await db.flush()


async def get_user_quota_status(
    db: AsyncSession,
    user: User,
    max_per_day: int,
) -> dict[str, int | str]:
    """Get user's current quota status."""
    today = date.today()
    today_start = datetime.combine(today, datetime.min.time(), tzinfo=UTC)
    today_end = datetime.combine(today, datetime.max.time(), tzinfo=UTC)

    result = await db.execute(
        select(func.coalesce(func.sum(ApiUsage.analysis_count), 0)).where(
            ApiUsage.user_id == user.id,
            ApiUsage.date >= today_start,
            ApiUsage.date <= today_end,
        )
    )
    used_today = result.scalar_one() or 0

    return {
        "max_per_day": max_per_day,
        "used_today": used_today,
        "remaining": max(0, max_per_day - used_today),
        "reset_at": today_end.isoformat(),
    }