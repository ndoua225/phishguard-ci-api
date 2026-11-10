"""Authentication API routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import (
    AuthMode,
    RefreshResult,
    clear_auth_cookies,
    clear_login_csrf_cookie,
    create_access_token,
    create_refresh_token,
    create_user_session,
    delete_all_user_sessions,
    delete_session,
    detect_auth_mode,
    generate_csrf_token,
    generate_totp_secret,
    get_current_user,
    get_totp_provisioning_uri,
    hash_password,
    hash_token,
    require_admin,
    require_super_admin,
    rotate_refresh_token,
    set_auth_cookies,
    set_login_csrf_cookie,
    validate_csrf_token,
    validate_login_csrf,
    verify_password,
    verify_totp_code,
)
from app.db.session import get_session_dependency
from app.models import Session, User, UserRole
from app.services.quota_service import get_user_quota_status

__all__ = [
    "get_current_user",
    "require_admin",
    "require_super_admin",
    "validate_csrf_token",
    "generate_totp_secret",
    "get_totp_provisioning_uri",
    "verify_totp_code",
    "router",
]

router = APIRouter(tags=["auth"])


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str
    mfa_code: str | None = None


class MFASetupRequest(BaseModel):
    """Request to initiate MFA setup."""
    pass


class MFASetupResponse(BaseModel):
    """Response with TOTP secret and provisioning URI."""
    secret: str
    provisioning_uri: str


class MFAVerifyRequest(BaseModel):
    """Request to verify MFA code."""
    code: str


class MFAVerifyResponse(BaseModel):
    """Response after MFA verification."""
    mfa_enabled: bool
    message: str


class MFADisableRequest(BaseModel):
    """Request to disable MFA."""
    code: str


class MFADisableResponse(BaseModel):
    """Response after MFA disable."""
    mfa_enabled: bool
    message: str


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

    # Check if account is locked due to failed login attempts
    if user and user.locked_until and user.locked_until > datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed login attempts. Please try again later.",
        )

    if not user or not verify_password(request.password, user.password_hash):
        # Increment failed attempts
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.now(UTC) + timedelta(minutes=15)
            await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    # Reset failed attempts on successful login
    user.failed_login_attempts = 0
    user.locked_until = None

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is disabled",
        )

    # MFA check for admins with TOTP
    mfa_verified = True
    if user.role in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        if not user.mfa_enabled:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="MFA not configured for admin account. Contact super admin.",
            )
        if not request.mfa_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="MFA code required for admin accounts",
            )
        if not user.totp_secret or not verify_totp_code(user.totp_secret, request.mfa_code):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA code",
            )
        mfa_verified = True
    elif user.role == UserRole.USER:
        # Regular users don't need MFA
        mfa_verified = True
    else:
        mfa_verified = True

    # Detect auth mode
    mode = detect_auth_mode(http_request, "login")

    # Validate login CSRF for cookie mode
    if mode == AuthMode.COOKIE:
        await validate_login_csrf(http_request)

    # Create session
    session_token, csrf_token = await create_user_session(
        db, user, http_request, mfa_verified=mfa_verified
    )

    # Create JWT tokens
    access_token = create_access_token(user.id, user.role)
    refresh_token = create_refresh_token(user.id)

    # Update session with refresh token hash
    refresh_token_hash = hash_token(refresh_token)
    result = await db.execute(
        select(Session).where(Session.user_id == user.id, Session.session_token_hash == hash_token(session_token))
    )
    session_obj = cast("Session | None", result.scalar_one_or_none())
    if session_obj:
        session_obj.refresh_token_hash = hash_token(refresh_token)
        await db.commit()

    # Set cookies based on mode
    secure = http_request.url.scheme == "https"
    if mode == AuthMode.COOKIE:
        # Cookie mode: set all cookies, don't return refresh_token in JSON
        set_auth_cookies(response, session_token, csrf_token, refresh_token, secure=secure)
        # Clear login CSRF cookie after successful login
        clear_login_csrf_cookie(response)
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": UserResponse.model_validate(user),
        }
    else:
        # Bearer mode: return refresh_token in JSON, don't set cookies
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "user": UserResponse.model_validate(user),
        }

    # Should never reach here, but safeguard
    raise HTTPException(status_code=500, detail="Login failed unexpectedly")


@router.get("/login/csrf")
async def get_login_csrf(
    response: Response,
    http_request: Request,
) -> dict[str, str]:
    """Get a login CSRF token for the login form."""
    csrf_token = generate_csrf_token()
    secure = http_request.url.scheme == "https"
    set_login_csrf_cookie(response, csrf_token, secure=secure)
    return {"csrf_token": csrf_token}


@router.post("/logout")
async def logout(
    response: Response,
    http_request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    _csrf: None = Depends(validate_csrf_token),
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
    response: Response,
    db: AsyncSession = Depends(get_session_dependency),
) -> TokenResponse:
    """Refresh access token using refresh token with rotation."""
    mode = detect_auth_mode(request, "refresh")

    if mode == AuthMode.COOKIE:
        refresh_token = request.cookies.get("refresh_token")
        if not refresh_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token required in cookie",
            )
        await validate_csrf_token(request, db)

    elif mode == AuthMode.BEARER:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token required in Authorization header",
            )
        refresh_token = auth_header[7:]
        if not refresh_token.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Empty Bearer token",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: provide Bearer header or refresh_token cookie",
        )

    # Validate token
    from app.core.auth import decode_token

    payload = decode_token(refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
        )

    # Verify exp claim
        exp_timestamp = payload.get("exp")
        if exp_timestamp is None or datetime.fromtimestamp(float(exp_timestamp), UTC) < datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token expired",
            )

    user_id = UUID(payload["sub"])
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Find session by refresh token hash
    from app.core.auth import hash_token

    result = await db.execute(
        select(Session).where(
        Session.user_id == user_id, Session.refresh_token_hash == hash_token(refresh_token)
    )
    )
    session = cast("Session | None", result.scalar_one_or_none())
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session not found for refresh token",
        )

    # Rotate refresh token
    rotate_result, access_token, new_refresh_token, new_session_token, new_csrf_token = await rotate_refresh_token(
    db, refresh_token, user, session.family_id
    )

    if rotate_result != RefreshResult.SUCCESS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Refresh failed: {rotate_result.value}",
        )

    # Set new cookies for cookie mode
    if detect_auth_mode(request, "refresh") == AuthMode.COOKIE:
        secure = request.url.scheme == "https"
        # These are guaranteed non-None when result == SUCCESS
        new_session_token_str = new_session_token or ""
        new_csrf_token_str = new_csrf_token or ""
        new_refresh_token_str = new_refresh_token or ""
        set_auth_cookies(response, new_session_token_str, new_csrf_token_str, new_refresh_token_str, secure=secure)

    return TokenResponse(access_token=access_token, refresh_token="", token_type="bearer")


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
    _csrf: None = Depends(validate_csrf_token),
) -> dict[str, str]:
    """Revoke all sessions for current user."""
    count = await delete_all_user_sessions(db, current_user.id)
    clear_auth_cookies(response)
    return {"message": f"Revoked {count} sessions"}


# MFA endpoints for admin accounts

@router.post("/mfa/setup", response_model=MFASetupResponse)
async def mfa_setup(
    request: Request,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> MFASetupResponse:
    """Initiate MFA setup for admin account. Returns secret and provisioning URI."""
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA setup only available for admin accounts",
        )

    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA already enabled",
        )

    # Generate new TOTP secret
    secret = generate_totp_secret()
    provisioning_uri = get_totp_provisioning_uri(current_user.email, secret)

    # Store secret temporarily (not enabled until verified)
    current_user.totp_secret = secret
    await db.commit()

    return MFASetupResponse(secret=secret, provisioning_uri=provisioning_uri)


@router.post("/mfa/verify", response_model=MFAVerifyResponse)
async def mfa_verify(
    request: MFAVerifyRequest,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> MFAVerifyResponse:
    """Verify MFA code and enable MFA."""
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA only available for admin accounts",
        )

    if not current_user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup not initiated",
        )

    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA already enabled",
        )

    # Check if account is locked due to too many failed MFA attempts
    if current_user.mfa_locked_until and current_user.mfa_locked_until > datetime.now(UTC):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed MFA attempts. Please try again later.",
        )

    if not verify_totp_code(current_user.totp_secret or "", request.code):
        # Increment failed attempts
        current_user.failed_mfa_attempts += 1
        if current_user.failed_mfa_attempts >= 5:
            current_user.mfa_locked_until = datetime.now(UTC) + timedelta(minutes=15)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Enable MFA and reset failed attempts
    current_user.mfa_enabled = True
    current_user.failed_mfa_attempts = 0
    current_user.mfa_locked_until = None
    await db.commit()

    return MFAVerifyResponse(mfa_enabled=True, message="MFA enabled successfully")


@router.post("/mfa/disable", response_model=MFADisableResponse)
async def mfa_disable(
    request: MFADisableRequest,
    db: AsyncSession = Depends(get_session_dependency),
    current_user: User = Depends(get_current_user),
) -> MFADisableResponse:
    """Disable MFA after verifying code."""
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA only available for admin accounts",
        )

    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA not enabled",
        )

    if not verify_totp_code(current_user.totp_secret or "", request.code):
        # Increment failed attempts
        current_user.failed_mfa_attempts += 1
        if current_user.failed_mfa_attempts >= 5:
            current_user.mfa_locked_until = datetime.now(UTC) + timedelta(minutes=15)
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA code",
        )

    # Disable MFA and clear secret
    current_user.mfa_enabled = False
    current_user.totp_secret = None
    current_user.failed_mfa_attempts = 0
    current_user.mfa_locked_until = None
    await db.commit()

    return MFADisableResponse(mfa_enabled=False, message="MFA disabled successfully")