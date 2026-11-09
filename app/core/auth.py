"""Authentication and authorization utilities."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated
from uuid import UUID

import pyotp
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.session import get_session_dependency
from app.models import Session, User, UserRole

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT token handling
security = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(user_id: UUID, role: UserRole) -> str:
    """Create JWT access token."""
    expire = datetime.now(UTC) + timedelta(
        minutes=settings.access_token_expire_minutes
    )
    to_encode = {
        "sub": str(user_id),
        "role": role.value,
        "exp": expire,
        "type": "access",
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def create_refresh_token(user_id: UUID) -> str:
    """Create JWT refresh token."""
    expire = datetime.now(UTC) + timedelta(
        days=settings.refresh_token_expire_days
    )
    to_encode = {
        "sub": str(user_id),
        "exp": expire,
        "type": "refresh",
    }
    return jwt.encode(to_encode, settings.secret_key, algorithm=settings.algorithm)


def decode_token(token: str) -> dict[str, str] | None:
    """Decode and validate JWT token."""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except JWTError:
        return None


def generate_csrf_token() -> str:
    """Generate CSRF token."""
    return secrets.token_urlsafe(32)


def generate_session_token() -> str:
    """Generate session token."""
    return secrets.token_urlsafe(32)


def hash_ip(ip: str) -> str:
    """Hash IP address for privacy."""
    import hashlib

    return hashlib.sha256(ip.encode()).hexdigest()[:64]


async def get_current_user(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_session_dependency)],
) -> User:
    """Get current authenticated user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception

    payload = decode_token(credentials.credentials)
    if not payload or payload.get("type") != "access":
        raise credentials_exception

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise credentials_exception

    try:
        user_id = UUID(user_id_str)
    except ValueError:
        raise credentials_exception

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise credentials_exception

    # Attach user to request state for convenience
    request.state.user = user
    return user


async def get_current_user_optional(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    db: Annotated[AsyncSession, Depends(get_session_dependency)],
) -> User | None:
    """Get current user if authenticated, otherwise None."""
    if not credentials:
        return None

    try:
        return await get_current_user(request, credentials, db)
    except HTTPException:
        return None


async def require_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require admin role."""
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


async def require_super_admin(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Require super admin role."""
    if current_user.role != UserRole.SUPER_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required",
        )
    return current_user


async def create_user_session(
    db: AsyncSession,
    user: User,
    request: Request,
    mfa_verified: bool = False,
) -> tuple[str, str]:
    """Create a new session for user, return (session_token, csrf_token)."""
    session_token = generate_session_token()
    csrf_token = generate_csrf_token()

    # Get client IP
    client_ip = request.client.host if request.client else "unknown"
    ip_hash = hash_ip(client_ip)

    # Create session
    expires_at = datetime.now(UTC) + timedelta(
        minutes=settings.access_token_expire_minutes
    )

    session = Session(
        user_id=user.id,
        session_token=session_token,
        csrf_token=csrf_token,
        ip_hash=ip_hash,
        user_agent=request.headers.get("user-agent"),
        expires_at=expires_at,
        is_mfa_verified=mfa_verified,
    )

    db.add(session)
    await db.flush()

    # Update user last login
    user.last_login_at = datetime.now(UTC)
    user.failed_login_attempts = 0

    await db.commit()

    return session_token, csrf_token


async def validate_session(
    db: AsyncSession,
    session_token: str,
    csrf_token: str | None = None,
) -> Session | None:
    """Validate session token and optionally CSRF token."""
    result = await db.execute(
        select(Session).where(
            Session.session_token == session_token,
            Session.expires_at > datetime.now(UTC),
        )
    )
    session = result.scalar_one_or_none()

    if not session:
        return None

    if csrf_token and session.csrf_token != csrf_token:
        return None

    # Update last activity
    session.last_activity_at = datetime.now(UTC)
    await db.commit()

    return session


async def delete_session(db: AsyncSession, session_token: str) -> bool:
    """Delete a session."""
    result = await db.execute(
        select(Session).where(Session.session_token == session_token)
    )
    session = result.scalar_one_or_none()

    if session:
        await db.delete(session)
        await db.commit()
        return True

    return False


async def delete_all_user_sessions(db: AsyncSession, user_id: UUID) -> int:
    """Delete all sessions for a user."""
    result = await db.execute(select(Session).where(Session.user_id == user_id))
    sessions = result.scalars().all()

    for session in sessions:
        await db.delete(session)

    await db.commit()
    return len(sessions)


# TOTP (Time-based One-Time Password) for Admin MFA

def generate_totp_secret() -> str:
    """Generate a new TOTP secret for MFA enrollment."""
    return pyotp.random_base32()


def get_totp_provisioning_uri(email: str, secret: str) -> str:
    """Generate TOTP provisioning URI for QR code."""
    return pyotp.totp.TOTP(secret).provisioning_uri(
        name=email,
        issuer_name="PhishGuard CI",
    )


def verify_totp_code(secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code.

    Args:
        secret: The user's TOTP secret
        code: The code provided by the user
        valid_window: Number of time steps (30s each) to check before/after current

    Returns:
        True if code is valid, False otherwise
    """
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=valid_window)


def set_auth_cookies(
    response: Response,
    session_token: str,
    csrf_token: str,
    secure: bool = False,
) -> None:
    """Set authentication cookies."""
    # Session cookie (HttpOnly, Secure, SameSite=Lax)
    response.set_cookie(
        key="session",
        value=session_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )

    # CSRF cookie (not HttpOnly so JS can read it for headers)
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=secure,
        samesite="lax",
        max_age=settings.access_token_expire_minutes * 60,
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    """Clear authentication cookies."""
    response.delete_cookie(key="session", path="/")
    response.delete_cookie(key="csrf_token", path="/")


async def validate_csrf_token(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_session_dependency)],
) -> None:
    """
    Validate CSRF token from request header against session cookie.

    This dependency should be used on all state-changing endpoints that
    authenticate via session cookies (not Bearer tokens).

    If the request uses Bearer token authentication, CSRF validation is skipped.
    """
    # Check if request uses Bearer token authentication
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        # Bearer token auth - CSRF not needed
        return

    # Get session token from cookie
    session_token = request.cookies.get("session")
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session required for CSRF validation",
        )

    # Get CSRF token from header (set by frontend from csrf_token cookie)
    csrf_token = request.headers.get("X-CSRF-Token")
    if not csrf_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="CSRF token required (X-CSRF-Token header)",
        )

    # Validate session and CSRF token
    session = await validate_session(db, session_token, csrf_token)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid or expired CSRF token",
        )

    # Attach session to request state for convenience
    request.state.session = session