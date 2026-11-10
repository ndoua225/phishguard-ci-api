"""Authentication and authorization utilities."""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Annotated
from uuid import UUID, uuid4

import pyotp
from cryptography.fernet import Fernet
from fastapi import Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import insert, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.session import get_session_dependency
from app.models import RevokedRefreshToken, Session, User, UserRole

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# TOTP secret encryption
_totp_fernet: Fernet | None = None


def _get_totp_fernet() -> Fernet:
    """Get or create the Fernet instance for TOTP secret encryption."""
    global _totp_fernet
    if _totp_fernet is None:
        key_b64 = settings.totp_encryption_key
        # Fernet expects the key as a url-safe base64-encoded string (44 chars)
        # Validate it's a valid Fernet key
        if len(key_b64) != 44:
            raise ValueError("TOTP encryption key must be 44-character url-safe base64")
        try:
            # Validate it's valid base64
            base64.urlsafe_b64decode(key_b64.encode() + b"=" * (-len(key_b64) % 4))
        except Exception:
            raise ValueError("TOTP encryption key must be valid url-safe base64")
        _totp_fernet = Fernet(key_b64.encode())
    return _totp_fernet


def encrypt_totp_secret(secret: str) -> str:
    """Encrypt a TOTP secret for storage.
    
    Args:
        secret: The plaintext TOTP secret (base32 encoded)
        
    Returns:
        The encrypted secret as a url-safe base64 string
    """
    fernet = _get_totp_fernet()
    encrypted = fernet.encrypt(secret.encode())
    return encrypted.decode()


def decrypt_totp_secret(encrypted_secret: str) -> str:
    """Decrypt a TOTP secret from storage.
    
    Args:
        encrypted_secret: The encrypted secret from storage
        
    Returns:
        The decrypted plaintext TOTP secret
        
    Raises:
        ValueError: If decryption fails (invalid key or corrupted data)
    """
    fernet = _get_totp_fernet()
    try:
        decrypted = fernet.decrypt(encrypted_secret.encode())
        return decrypted.decode()
    except Exception as e:
        raise ValueError(f"Failed to decrypt TOTP secret: {e}")


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


def hash_ip(ip: str) -> str:
    """Hash IP address for privacy."""
    return hashlib.sha256(ip.encode()).hexdigest()[:64]


def hash_token(token: str) -> str:
    """Hash a token using SHA-256 for storage."""
    return hashlib.sha256(token.encode()).hexdigest()


def generate_opaque_token() -> str:
    """Generate a cryptographically secure opaque token."""
    return secrets.token_urlsafe(32)


class AuthMode(Enum):
    """Authentication mode for requests."""
    BEARER = "bearer"
    COOKIE = "cookie"
    NONE = "none"


def detect_auth_mode(request: Request, endpoint: str) -> AuthMode:
    """
    Detect authentication mode based on endpoint and request.

    Priority:
    1. Explicit X-Auth-Mode header (cookie or bearer)
    2. Authorization: Bearer ***
    3. Endpoint-specific cookie detection
    """
    # 1. Explicit mode override via header
    x_auth_mode = request.headers.get("X-Auth-Mode", "").lower()
    if x_auth_mode == "cookie":
        return AuthMode.COOKIE
    if x_auth_mode == "bearer":
        return AuthMode.BEARER

    # 2. Bearer token takes priority
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return AuthMode.BEARER

    # 3. Endpoint-specific cookie detection
    if endpoint == "login":
        # Login defaults to cookie mode for Lovable
        origin = request.headers.get("Origin", "")
        if origin and origin in settings.cors_origins:
            return AuthMode.COOKIE
        return AuthMode.COOKIE

    elif endpoint == "refresh":
        # Refresh via cookie if refresh_token cookie present
        if request.cookies.get("refresh_token"):
            return AuthMode.COOKIE
        if auth_header.startswith("Bearer "):
            return AuthMode.BEARER
        return AuthMode.NONE

    elif endpoint == "logout":
        # Logout via cookie if session cookie + CSRF header present
        if request.cookies.get("session") and request.headers.get("X-CSRF-Token"):
            return AuthMode.COOKIE
        if auth_header.startswith("Bearer "):
            return AuthMode.BEARER
        return AuthMode.NONE

    # Other authenticated endpoints: Bearer priority, then cookie fallback
    if auth_header.startswith("Bearer "):
        return AuthMode.BEARER
    if request.cookies.get("session"):
        return AuthMode.COOKIE

    return AuthMode.NONE


def generate_csrf_token() -> str:
    """Generate CSRF token."""
    return generate_opaque_token()


def generate_session_token() -> str:
    """Generate session token."""
    return generate_opaque_token()


def set_login_csrf_cookie(response: Response, csrf_token: str, secure: bool) -> None:
    """Set login CSRF cookie (pre-session)."""
    response.set_cookie(
        key="login_csrf",
        value=csrf_token,
        httponly=False,
        secure=secure,
        samesite="lax",
        max_age=300,  # 5 minutes for login flow
        path="/",
    )


def clear_login_csrf_cookie(response: Response) -> None:
    """Clear login CSRF cookie after successful login."""
    response.delete_cookie(key="login_csrf", path="/")


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
    now = datetime.now(UTC)
    family_id = uuid4()
    family_expires_at = now + timedelta(days=settings.refresh_token_expire_days)

    session = Session(
        user_id=user.id,
        session_token_hash=hash_token(session_token),
        csrf_token=csrf_token,
        ip_hash=ip_hash,
        user_agent=request.headers.get("user-agent"),
        expires_at=expires_at,
        is_mfa_verified=mfa_verified,
        family_id=family_id,
        family_created_at=now,
        family_expires_at=family_expires_at,
    )

    db.add(session)
    await db.flush()

    # Update user last login
    user.last_login_at = datetime.now(UTC)
    user.failed_login_attempts = 0

    await db.commit()

    return session_token, csrf_token


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
    """Generate a new TOTP secret for MFA enrollment (encrypted for storage)."""
    plaintext_secret = pyotp.random_base32()
    return encrypt_totp_secret(plaintext_secret)


def get_totp_provisioning_uri(email: str, encrypted_secret: str) -> str:
    """Generate TOTP provisioning URI for QR code.
    
    Args:
        email: User's email
        encrypted_secret: The encrypted TOTP secret from storage
        
    Returns:
        Provisioning URI for QR code generation
    """
    plaintext_secret = decrypt_totp_secret(encrypted_secret)
    return pyotp.totp.TOTP(plaintext_secret).provisioning_uri(
        name=email,
        issuer_name="PhishGuard CI",
    )


def verify_totp_code(encrypted_secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a TOTP code.

    Args:
        encrypted_secret: The user's encrypted TOTP secret from storage
        code: The code provided by the user
        valid_window: Number of time steps (30s each) to check before/after current

    Returns:
        True if code is valid, False otherwise
    """
    plaintext_secret = decrypt_totp_secret(encrypted_secret)
    totp = pyotp.TOTP(plaintext_secret)
    return totp.verify(code, valid_window=valid_window)


class RefreshResult(Enum):
    """Result of refresh token rotation."""
    SUCCESS = "success"
    ALREADY_CONSUMED = "already_consumed"
    REPLAY_DETECTED = "replay_detected"
    LOCK_ERROR = "lock_error"
    FAMILY_EXPIRED = "family_expired"
    SESSION_EXPIRED = "session_expired"
    INVALID_TOKEN = "invalid_token"


async def validate_session(
    db: AsyncSession,
    session_token: str,
    csrf_token: str | None = None,
) -> Session | None:
    """Validate session token and optionally CSRF token."""
    token_hash = hash_token(session_token)
    result = await db.execute(
        select(Session).where(
            Session.session_token_hash == token_hash,
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


async def validate_login_csrf(request: Request) -> None:
    """
    Validate CSRF token for login without pre-existing session.

    Uses the login_csrf cookie and X-CSRF-Token header.
    """
    # Bearer token auth - CSRF not needed
    if request.headers.get("Authorization", "").startswith("Bearer "):
        return

    # Get login_csrf cookie
    login_csrf = request.cookies.get("login_csrf")
    if not login_csrf:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Login CSRF token required (login_csrf cookie)",
        )

    # Get CSRF token from header
    header_csrf = request.headers.get("X-CSRF-Token")
    if not header_csrf:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Login CSRF token required (X-CSRF-Token header)",
        )

    # Constant-time comparison
    if not secrets.compare_digest(login_csrf, header_csrf):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid login CSRF token",
        )


async def revoke_family(db: AsyncSession, family_id: UUID, reason: str) -> int:
    """Revoke all tokens in a family (used for replay detection)."""
    result = await db.execute(select(Session).where(Session.family_id == family_id))
    sessions = result.scalars().all()

    count = 0
    for session in sessions:
        if session.refresh_token_hash:
            # Use try/except for cross-database unique constraint handling
            try:
                await db.execute(
                    insert(RevokedRefreshToken).values(
                        token_hash=session.refresh_token_hash,
                        user_id=session.user_id,
                        family_id=family_id,
                        revoked_reason=reason,
                        original_expires_at=session.family_expires_at,
                    )
                )
                await db.flush()
                count += 1
            except IntegrityError:
                # Already revoked - skip
                await db.rollback()
    await db.flush()
    return count


async def detect_and_revoke_replay(
    db: AsyncSession, presented_token: str, user: User
) -> bool:
    """
    Detect replay attack and revoke the entire token family.

    Returns True if replay was detected and handled.
    """
    token_hash = hash_token(presented_token)

    result = await db.execute(
        select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == token_hash)
    )
    revoked = result.scalar_one_or_none()

    if not revoked:
        return False

    # Replay confirmed - revoke entire family
    await revoke_family(db, revoked.family_id, "REPLAY")
    return True


async def rotate_refresh_token(
    db: AsyncSession,
    old_refresh_token: str,
    user: User,
    family_id: UUID,
) -> tuple[RefreshResult, str | None, str | None, str | None, str | None]:
    """
    Atomically rotate a refresh token.

    Returns: (result, new_access_token, new_refresh_token, new_session_token, new_csrf_token)
    """
    old_hash = hash_token(old_refresh_token)

    # 1. Check blacklist first (fast path)
    existing = await db.execute(
        select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == hash_token(old_refresh_token))
    )
    if existing.scalar_one_or_none():
        # Already revoked - replay detected
        revoked_result = await db.execute(
            select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == hash_token(old_refresh_token))
        )
        existing_revoked_entry = revoked_result.scalar_one()
        await revoke_family(db, existing_revoked_entry.family_id, "REPLAY")
        return RefreshResult.REPLAY_DETECTED, None, None, None, None

    # 2. Lock the session row (NOWAIT to fail fast on contention)
    try:
        result = await db.execute(
            select(Session)
            .where(Session.family_id == family_id)
            .with_for_update(nowait=True)
        )
    except Exception as e:
        if "LockNotAvailable" in str(type(e)) or "nowait" in str(e).lower():
            return RefreshResult.LOCK_ERROR, None, None, None, None
        raise

    session = result.scalar_one_or_none()
    if not session:
        return RefreshResult.INVALID_TOKEN, None, None, None, None

    # 3. Verify the refresh token matches
    if session.refresh_token_hash != hash_token(old_refresh_token):
        return RefreshResult.ALREADY_CONSUMED, None, None, None, None

    # 4. Check expiration
    now = datetime.now(UTC)
    # Ensure session datetimes are timezone-aware for comparison
    family_expires_at = session.family_expires_at
    if family_expires_at.tzinfo is None:
        family_expires_at = family_expires_at.replace(tzinfo=UTC)
    if now > family_expires_at:
        return RefreshResult.FAMILY_EXPIRED, None, None, None, None
    session_expires_at = session.expires_at
    if session_expires_at.tzinfo is None:
        session_expires_at = session_expires_at.replace(tzinfo=UTC)
    if now > session_expires_at:
        return RefreshResult.SESSION_EXPIRED, None, None, None, None

    # 5. Atomic rotation (use existing transaction)
    # a) Blacklist old refresh token (idempotent with unique constraint)
    # Use try/except IntegrityError for cross-database portability (SQLite + PostgreSQL)
    
    # Check if already revoked (replay detection) - this is the fast path
    existing = await db.execute(
        select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == hash_token(old_refresh_token))
    )
    if existing.scalar_one_or_none():
        # Already revoked - replay detected, revoke entire family
        await revoke_family(db, family_id, "REPLAY")
        return RefreshResult.REPLAY_DETECTED, None, None, None, None

    # Insert into blacklist with idempotent upsert
    # Use try/except for cross-database unique constraint handling
    try:
        await db.execute(
            insert(RevokedRefreshToken).values(
                token_hash=hash_token(old_refresh_token),
                user_id=user.id,
                family_id=family_id,
                revoked_reason="ROTATION",
                original_expires_at=session.family_expires_at,
            )
        )
        await db.flush()
    except IntegrityError:
        # Unique constraint violation - another request beat us to it
        await db.rollback()
        # Check if it was a ROTATION (legitimate race) or REPLAY (attack)
        check = await db.execute(
            select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == hash_token(old_refresh_token))
        )
        revoked_entry: RevokedRefreshToken | None = check.scalar_one_or_none()
        if revoked_entry and revoked_entry.revoked_reason == "ROTATION":
            # Another request just rotated this token - legitimate race
            return RefreshResult.ALREADY_CONSUMED, None, None, None, None
        elif revoked_entry and revoked_entry.revoked_reason == "REPLAY":
            # Actual replay attack detected
            await revoke_family(db, family_id, "REPLAY")
            return RefreshResult.REPLAY_DETECTED, None, None, None, None
        # Unknown state - treat as already consumed
        return RefreshResult.ALREADY_CONSUMED, None, None, None, None

    # Verify the insert succeeded
    check = await db.execute(
        select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == hash_token(old_refresh_token))
    )
    revoked_after_insert: RevokedRefreshToken | None = check.scalar_one_or_none()
    if revoked_after_insert and revoked_after_insert.revoked_reason == "ROTATION":
        # Insert succeeded
        pass
    elif revoked_after_insert and revoked_after_insert.revoked_reason == "REPLAY":
        # Shouldn't happen but handle it
        await revoke_family(db, family_id, "REPLAY")
        return RefreshResult.REPLAY_DETECTED, None, None, None, None

    # b) Generate new tokens
    new_access_token = create_access_token(user.id, user.role)
    new_refresh_token = create_refresh_token(user.id)
    new_session_token = generate_opaque_token()
    new_csrf_token = generate_csrf_token()

    # c) Update session (SAME family_id)
    session.session_token_hash = hash_token(new_session_token)
    session.refresh_token_hash = hash_token(new_refresh_token)
    session.csrf_token = generate_csrf_token()
    session.expires_at = datetime.now(UTC) + timedelta(minutes=settings.access_token_expire_minutes)
    session.last_activity_at = datetime.now(UTC)
    # family_id STAYS THE SAME
    await db.flush()

    return RefreshResult.SUCCESS, new_access_token, new_refresh_token, new_session_token, new_csrf_token


def set_auth_cookies(
    response: Response,
    session_token: str,
    csrf_token: str,
    refresh_token: str,
    secure: bool = False,
) -> None:
    """Set authentication cookies including refresh_token."""
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

    # Refresh token cookie (HttpOnly, Secure, SameSite=Lax)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=secure,
        samesite="lax",
        max_age=settings.refresh_token_expire_days * 24 * 60 * 60,
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    """Clear all authentication cookies."""
    response.delete_cookie(key="session", path="/")
    response.delete_cookie(key="csrf_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")


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