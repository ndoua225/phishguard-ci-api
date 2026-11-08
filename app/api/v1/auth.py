"""Authentication API routes."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import (
    clear_auth_cookies,
    create_access_token,
    create_refresh_token,
    create_user_session,
    delete_all_user_sessions,
    delete_session,
    get_current_user,
    hash_password,
    require_admin,
    set_auth_cookies,
    verify_password,
)
from app.db.session import get_session_dependency
from app.models import User, UserRole
from app.services.quota_service import get_user_quota_status

__all__ = [
    "get_current_user",
    "require_admin",
    "router",
]

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: UUID
    email: str
    role: UserRole
    is_active: bool
    is_test_account: bool
    created_at: datetime
    last_login_at: datetime | None

    class Config:
        from_attributes = True


class QuotaStatusResponse(BaseModel):
    max_per_day: int
    used_today: int
    remaining: int
    reset_at: str


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    request: RegisterRequest,
    db: AsyncSession = Depends(get_session_dependency),
) -> UserResponse:
    """Register a new user account."""
    # Check if email already exists
    result = await db.execute(select(User).where(User.email == request.email))
    if result.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    # Create user
    user = User(
        email=request.email,
        password_hash=hash_password(request.password),
        role=UserRole.USER,
    )

    db.add(user)
    await db.commit()
    await db.refresh(user)

    return UserResponse.model_validate(user)


@router.post("/login")
async def login(
    request: LoginRequest,
    response: Response,
    http_request: Request,
    db: AsyncSession = Depends(get_session_dependency),
) -> dict[str, str | UserResponse]:
    """Login with email and password, return tokens and set cookies."""
    # Find user
    result = await db.execute(select(User).where(User.email == request.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(request.password, user.password_hash):
        # Increment failed attempts
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(UTC)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # MFA check for admins (placeholder - implement TOTP if needed)
    mfa_verified = True
    if user.role in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        if not request.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA code required for admin accounts",
            )
        # TODO: Verify TOTP code
        mfa_verified = True  # Placeholder

    # Create session
    session_token, csrf_token = await create_user_session(
        db, user, http_request, mfa_verified=mfa_verified
    )

    # Create JWT tokens
    access_token = create_access_token(user.id, user.role)
    refresh_token = create_refresh_token(user.id)

    # Set cookies
    secure = http_request.url.scheme == "https"
    set_auth_cookies(response, session_token, csrf_token, secure=secure)

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
    }


@router.post("/logout")
async def logout(
    response: Response,
    http_request: Request,
    db: AsyncSession = Depends(get_session_dependency),
) -> dict[str, str]:
    """Logout and clear session."""
    # Get session from cookie
    session_token = http_request.cookies.get("session")
    if session_token:
        await delete_session(db, session_token)

    clear_auth_cookies(response)
    return {"message": "Logged out successfully"}


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    request: Request,
    db: AsyncSession = Depends(get_session_dependency),
) -> TokenResponse:
    """Refresh access token using refresh token."""
    # Get refresh token from cookie or header
    refresh_token = request.cookies.get("refresh_token")
    if not refresh_token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            refresh_token = auth_header[7:]

    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token required",
        )

    from app.core.auth import decode_token

    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    user_id = UUID(payload["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    access_token = create_access_token(user.id, user.role)
    new_refresh_token = create_refresh_token(user.id)

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    """Get current user information."""
    return UserResponse.model_validate(current_user)


@router.get("/me/quota", response_model=QuotaStatusResponse)
async def get_quota_status(
    request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> QuotaStatusResponse:
    """Get current user's quota status."""
    from app.config import settings

    quota = await get_user_quota_status(db, current_user, settings.max_analyses_per_day)
    return QuotaStatusResponse(**quota)


@router.delete("/me/sessions")
async def revoke_all_sessions(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Revoke all sessions for current user."""
    count = await delete_all_user_sessions(db, current_user.id)
    clear_auth_cookies(response)
    return {"message": f"Revoked {count} sessions"}