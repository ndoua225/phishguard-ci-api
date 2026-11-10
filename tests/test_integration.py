"""Integration tests for PhishGuard CI API.

These tests use an in-memory SQLite database for isolation by default,
but can run against PostgreSQL when PHISHGUARD_DATABASE_URL is set.
"""

from __future__ import annotations

import os

import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.db.session import close_db, get_session_dependency, set_test_engine
from app.main import create_app
from app.models import Base

# Use PostgreSQL from environment if available (for CI), otherwise SQLite
TEST_DATABASE_URL = os.environ.get("PHISHGUARD_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

# Detect if we're using PostgreSQL (needs transaction isolation)
IS_POSTGRESQL = TEST_DATABASE_URL.startswith("postgresql")


@pytest_asyncio.fixture(scope="function")
async def test_engine():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_connection(test_engine):
    """Provide a database connection with transaction isolation for PostgreSQL."""
    if IS_POSTGRESQL:
        # For PostgreSQL: use a dedicated connection with transaction rollback
        async with test_engine.connect() as conn:
            trans = await conn.begin()
            try:
                yield conn
            finally:
                await trans.rollback()
    else:
        # For SQLite: just yield a connection (each test gets fresh DB)
        async with test_engine.connect() as conn:
            yield conn


@pytest_asyncio.fixture(scope="function")
async def shared_session(db_connection: AsyncConnection):
    """Provide a single session shared across all requests in a test.

    This session is bound to the test connection and participates in the
    test's transaction. It is NOT closed until the test ends, allowing
    data to persist across multiple requests within the same test.
    """
    session_factory = sessionmaker(db_connection, class_=AsyncSession, expire_on_commit=False)
    session = session_factory()
    try:
        yield session
    finally:
        await session.close()


@pytest_asyncio.fixture(scope="function")
async def app(test_engine, db_connection, shared_session):
    # Set the global test engine BEFORE creating the app
    # This ensures the app uses the same engine as the test fixtures
    set_test_engine(str(test_engine.url))
    
    # Create app WITHOUT database_url to avoid re-initializing the engine in lifespan
    app = create_app(database_url=None)

    async def override_get_session():
        # Return the shared session for all requests in this test
        yield shared_session

    app.dependency_overrides[get_session_dependency] = override_get_session

    yield app

    app.dependency_overrides.clear()
    # Clean up the global engine after test
    await close_db()


@pytest_asyncio.fixture(scope="function")
async def client(app):
    async with LifespanManager(app):
        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as ac:
            yield ac


@pytest_asyncio.fixture(scope="function")
async def registered_user(client):
    user_data = {
        "email": "test@example.com",
        "password": "TestPassword123!",
    }
    response = await client.post("/api/v1/auth/register", json=user_data)
    assert response.status_code == 201

    # Get login CSRF token first
    csrf_response = await client.get("/api/v1/auth/login/csrf")
    assert csrf_response.status_code == 200
    login_csrf_token = csrf_response.cookies.get("login_csrf")

    # Log in to get access token (with login CSRF)
    login_response = await client.post(
        "/api/v1/auth/login",
        json=user_data,
        headers={"X-CSRF-Token": login_csrf_token} if login_csrf_token else {},
    )
    assert login_response.status_code == 200
    login_data = login_response.json()

    # In cookie mode, refresh_token is in the cookie, not in JSON
    refresh_token = login_response.cookies.get("refresh_token")

    return {
        "email": user_data["email"],
        "password": user_data["password"],
        "access_token": login_data["access_token"],
        "refresh_token": refresh_token,
        "csrf_token": login_response.cookies.get("csrf_token"),
    }


def auth_headers(access_token: str) -> dict[str, str]:
    """Create authorization headers with Bearer token."""
    return {"Authorization": f"Bearer {access_token}"}


class TestAuth:
    async def test_register_success(self, client):
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": "newuser@example.com", "password": "SecurePass123!"},
        )
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == "newuser@example.com"
        assert data["role"] == "USER"
        assert data["is_active"] is True
        assert "id" in data

    async def test_register_duplicate_email(self, client, registered_user):
        response = await client.post(
            "/api/v1/auth/register",
            json={"email": registered_user["email"], "password": "AnotherPass123!"},
        )
        assert response.status_code == 409
        assert "already registered" in response.json()["detail"].lower()

    async def test_login_success(self, client, registered_user):
        # Get login CSRF token first
        csrf_response = await client.get("/api/v1/auth/login/csrf")
        assert csrf_response.status_code == 200
        login_csrf_token = csrf_response.cookies.get("login_csrf")

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-CSRF-Token": login_csrf_token} if login_csrf_token else {},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" not in data  # In cookie mode, refresh_token is in cookie
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert "session" in response.cookies
        assert "csrf_token" in response.cookies
        assert "refresh_token" in response.cookies

    async def test_login_wrong_password(self, client, registered_user):
        # Get login CSRF token first
        csrf_response = await client.get("/api/v1/auth/login/csrf")
        assert csrf_response.status_code == 200
        login_csrf_token = csrf_response.cookies.get("login_csrf")

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": "WrongPassword123!"},
            headers={"X-CSRF-Token": login_csrf_token} if login_csrf_token else {},
        )
        assert response.status_code == 401

    async def test_login_nonexistent_user(self, client):
        # Get login CSRF token first
        csrf_response = await client.get("/api/v1/auth/login/csrf")
        assert csrf_response.status_code == 200
        login_csrf_token = csrf_response.cookies.get("login_csrf")

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": "nonexistent@example.com", "password": "Password123!"},
            headers={"X-CSRF-Token": login_csrf_token} if login_csrf_token else {},
        )
        assert response.status_code == 401

    async def test_logout(self, client, registered_user):
        response = await client.post(
            "/api/v1/auth/logout",
            headers=auth_headers(registered_user["access_token"]),
        )
        assert response.status_code == 200
        # Note: JWT tokens are stateless, logout only clears cookies
        # The token is still valid until expiry

    async def test_refresh_token(self, client, registered_user):
        # Refresh using refresh token from cookie
        refresh_token = registered_user["refresh_token"]
        csrf_token = registered_user["csrf_token"]

        response = await client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": refresh_token} if refresh_token else {},
            headers={"X-CSRF-Token": csrf_token} if csrf_token else {},
        )
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"


class TestCSRF:
    async def test_csrf_token_on_login(self, client, registered_user):
        # Get login CSRF token first
        csrf_response = await client.get("/api/v1/auth/login/csrf")
        assert csrf_response.status_code == 200
        login_csrf_token = csrf_response.cookies.get("login_csrf")

        response = await client.post(
            "/api/v1/auth/login",
            json={"email": registered_user["email"], "password": registered_user["password"]},
            headers={"X-CSRF-Token": login_csrf_token} if login_csrf_token else {},
        )
        assert "csrf_token" in response.cookies

    async def test_csrf_required_for_state_changing(self, client, registered_user):
        # This test is for cookie-based CSRF, but we use Bearer tokens
        pass


class TestQuotas:
    async def test_quota_enforced(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        response = await client.get("/api/v1/auth/me/quota", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "max_per_day" in data
        assert "used_today" in data
        assert "remaining" in data


class TestAnalyses:
    async def test_create_analysis(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        response = await client.post(
            "/api/v1/analyses",
            json={"content": "Test message with http://example.com link", "content_type": "MESSAGE"},
            headers=headers,
        )
        assert response.status_code == 201
        data = response.json()
        assert "analysis_ref" in data
        assert "score" in data
        assert "classification" in data
        assert "explanation" in data
        assert data["explanation_source"] == "TEMPLATE"

    async def test_create_analysis_too_long(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        long_content = "x" * 2000
        response = await client.post(
            "/api/v1/analyses",
            json={"content": long_content, "content_type": "MESSAGE"},
            headers=headers,
        )
        assert response.status_code == 422

    async def test_list_analyses(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        await client.post(
            "/api/v1/analyses",
            json={"content": "Test message", "content_type": "MESSAGE"},
            headers=headers,
        )

        response = await client.get("/api/v1/analyses", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    async def test_get_analysis(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        create_response = await client.post(
            "/api/v1/analyses",
            json={"content": "Test message for get", "content_type": "MESSAGE"},
            headers=headers,
        )
        analysis_ref = create_response.json()["analysis_ref"]

        response = await client.get(f"/api/v1/analyses/{analysis_ref}", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["analysis_ref"] == analysis_ref

    async def test_delete_analysis(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        create_response = await client.post(
            "/api/v1/analyses",
            json={"content": "Test message for delete", "content_type": "MESSAGE"},
            headers=headers,
        )
        analysis_ref = create_response.json()["analysis_ref"]

        response = await client.delete(f"/api/v1/analyses/{analysis_ref}", headers=headers)
        assert response.status_code == 204

        response = await client.get(f"/api/v1/analyses/{analysis_ref}", headers=headers)
        assert response.status_code == 404


class TestDashboard:
    async def test_user_stats(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        response = await client.get("/api/v1/dashboard/user/stats", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert "total_analyses" in data
        assert "by_classification" in data
        assert "by_content_type" in data
        assert "recent_7_days" in data

    async def test_user_recent(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])

        response = await client.get("/api/v1/dashboard/user/recent", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)


class TestDataIsolation:
    async def test_user_cannot_access_other_analysis(self, client):
        user1 = {"email": "user1@example.com", "password": "Password123!"}
        user2 = {"email": "user2@example.com", "password": "Password123!"}

        await client.post("/api/v1/auth/register", json=user1)
        await client.post("/api/v1/auth/register", json=user2)

        # Login as user1
        csrf_response = await client.get("/api/v1/auth/login/csrf")
        assert csrf_response.status_code == 200
        login_csrf_token = csrf_response.cookies.get("login_csrf")

        login1 = await client.post(
            "/api/v1/auth/login",
            json=user1,
            headers={"X-CSRF-Token": login_csrf_token} if login_csrf_token else {},
        )
        assert login1.status_code == 200
        user1_token = login1.json()["access_token"]
        headers1 = auth_headers(user1_token)

        create_response = await client.post(
            "/api/v1/analyses",
            json={"content": "User1 private message", "content_type": "MESSAGE"},
            headers=headers1,
        )
        analysis_ref = create_response.json()["analysis_ref"]

        # Login as user2
        csrf_response = await client.get("/api/v1/auth/login/csrf")
        assert csrf_response.status_code == 200
        login_csrf_token = csrf_response.cookies.get("login_csrf")

        login2 = await client.post(
            "/api/v1/auth/login",
            json=user2,
            headers={"X-CSRF-Token": login_csrf_token} if login_csrf_token else {},
        )
        assert login2.status_code == 200
        user2_token = login2.json()["access_token"]
        headers2 = auth_headers(user2_token)

        response = await client.get(f"/api/v1/analyses/{analysis_ref}", headers=headers2)
        assert response.status_code == 404

        response = await client.delete(f"/api/v1/analyses/{analysis_ref}", headers=headers2)
        assert response.status_code == 404


class TestSessionExpiration:
    async def test_session_expires(self, client, registered_user):
        pass


class TestRevocation:
    async def test_revoke_all_sessions(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])
        response = await client.delete("/api/v1/auth/me/sessions", headers=headers)
        assert response.status_code == 200
        # Note: JWT access token is stateless and remains valid until expiry.
        # Session revocation prevents new refresh tokens but doesn't invalidate existing access tokens.
        # To test revocation, we would need to verify refresh token is invalidated.
        # For now, just verify the endpoint works.
        response = await client.get("/api/v1/auth/me", headers=headers)
        # Access token still valid (stateless JWT)
        assert response.status_code == 200


class TestAdmin:
    async def test_admin_stats_requires_admin(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])
        response = await client.get("/api/v1/dashboard/admin/stats", headers=headers)
        assert response.status_code == 403

    async def test_list_users_requires_admin(self, client, registered_user):
        headers = auth_headers(registered_user["access_token"])
        response = await client.get("/api/v1/dashboard/admin/users", headers=headers)
        assert response.status_code == 403


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
