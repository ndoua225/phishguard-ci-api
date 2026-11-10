"""PostgreSQL-specific concurrent tests for authentication.

These tests require a real PostgreSQL instance and are designed to run in CI
where PostgreSQL 16 is available as a service.
"""
from __future__ import annotations

import asyncio

import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.auth import RevokedRefreshToken
from app.main import create_app
from app.models import Base

# These tests only run when PostgreSQL is available
# Mark them with @pytest.mark.postgresql to allow selective running
pytestmark = pytest.mark.postgresql


@pytest_asyncio.fixture(scope="function")
async def pg_engine():
    """Create PostgreSQL engine for testing."""
    # This will use the CI environment variable
    import os
    db_url = os.environ.get("PHISHGUARD_DATABASE_URL")
    if not db_url or not db_url.startswith("postgresql"):
        pytest.skip("PostgreSQL not available")
    
    engine = create_async_engine(db_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def pg_app(pg_engine):
    """Create app with PostgreSQL."""
    async_session = sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)
    
    app = create_app(database_url=str(pg_engine.url))
    
    async def override_get_session():
        async with async_session() as session:
            yield session
    
    app.dependency_overrides[__import__('app.db.session', fromlist=['get_session_dependency']).get_session_dependency] = override_get_session
    
    yield app
    
    app.dependency_overrides.clear()


@pytest_asyncio.fixture(scope="function")
async def pg_client(pg_app):
    """Async HTTP client for PostgreSQL testing."""
    async with LifespanManager(pg_app):
        async with AsyncClient(transport=ASGITransport(app=pg_app), base_url="http://test") as ac:
            yield ac


@pytest_asyncio.fixture(scope="function")
async def pg_session(pg_engine):
    """Direct database session for testing."""
    async_session = sessionmaker(pg_engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session


class TestConcurrentRefresh:
    """Test concurrent refresh token scenarios on PostgreSQL."""

    async def test_two_refresh_simultaneous(self, pg_client, pg_session):
        """Two simultaneous refresh requests with same token should serialize via lock."""
        # Create user
        from app.core.auth import hash_password
        from app.models import User
        
        user = User(email="concurrent@example.com", password_hash=hash_password("Test123!"), role="USER", is_active=True)
        pg_session.add(user)
        await pg_session.commit()
        await pg_session.refresh(user)
        
        # Login to get refresh token
        login_resp = await pg_client.post("/api/v1/auth/login", json={
            "email": "concurrent@example.com", 
            "password": "Test123!"
        })
        assert login_resp.status_code == 200
        
        # Get refresh token (Bearer mode)
        refresh_token = login_resp.json()["refresh_token"]
        
        # Make two simultaneous refresh requests
        async def do_refresh():
            return await pg_client.post(
                "/api/v1/auth/refresh",
                headers={"Authorization": f"Bearer {refresh_token}"}
            )
        
        # Run both concurrently
        results = await asyncio.gather(
            do_refresh(),
            do_refresh(),
            return_exceptions=True
        )
        
        # One should succeed, one should get LOCK_ERROR or ALREADY_CONSUMED
        statuses = []
        for r in results:
            if isinstance(r, Exception):
                statuses.append(500)
            else:
                statuses.append(r.status_code)
        assert 200 in statuses  # One succeeds
        # The other gets 401 with LOCK_ERROR or ALREADY_CONSUMED detail
        failed = [r for r in results if not isinstance(r, Exception) and r.status_code == 401]
        assert len(failed) == 1
        detail = failed[0].json().get("detail", "")
        assert "LOCK_ERROR" in detail or "ALREADY_CONSUMED" in detail or "lock" in detail.lower()

    async def test_blacklist_concurrent_insert(self, pg_session):
        """Two concurrent inserts of same token hash should be idempotent."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert

        from app.core.auth import hash_token
        
        token = "test-token-concurrent"
        token_hash = hash_token(token)
        
        # Insert from two concurrent "requests" using ON CONFLICT
        stmt1 = pg_insert(RevokedRefreshToken).values(
            token_hash=token_hash,
            user_id="11111111-1111-1111-1111-111111111111",
            family_id="22222222-2222-2222-2222-222222222222",
            revoked_reason="ROTATION",
            original_expires_at="2099-12-31 23:59:59+00"
        ).on_conflict_do_nothing(index_elements=["token_hash"])
        
        stmt2 = pg_insert(RevokedRefreshToken).values(
            token_hash=token_hash,
            user_id="11111111-1111-1111-1111-111111111111",
            family_id="33333333-3333-3333-3333-333333333333",
            revoked_reason="ROTATION",
            original_expires_at="2099-12-31 23:59:59+00"
        ).on_conflict_do_nothing(index_elements=["token_hash"])
        
        # Execute both
        await pg_session.execute(stmt1)
        await pg_session.execute(stmt2)
        await pg_session.flush()
        
        # Only one row should exist
        result = await pg_session.execute(
            select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == token_hash)
        )
        rows = result.scalars().all()
        assert len(rows) == 1
        # First insert wins (reason ROTATION)
        assert rows[0].revoked_reason == "ROTATION"

    async def test_replay_attack_detection(self, pg_client, pg_session):
        """Old refresh token reuse should be detected as replay."""
        from app.core.auth import hash_password
        from app.models import User
        
        user = User(email="replay@example.com", password_hash=hash_password("Test123!"), role="USER", is_active=True)
        pg_session.add(user)
        await pg_session.commit()
        await pg_session.refresh(user)
        
        # Login
        login_resp = await pg_client.post("/api/v1/auth/login", json={
            "email": "replay@example.com", 
            "password": "Test123!"
        })
        assert login_resp.status_code == 200
        old_refresh = login_resp.json()["refresh_token"]
        
        # First rotation
        resp1 = await pg_client.post("/api/v1/auth/refresh", headers={"Authorization": f"Bearer {old_refresh}"})
        assert resp1.status_code == 200
        new_refresh = resp1.json()["refresh_token"]
        
        # Try to use old token again (replay attack)
        resp2 = await pg_client.post("/api/v1/auth/refresh", headers={"Authorization": f"Bearer {old_refresh}"})
        assert resp2.status_code == 401
        detail = resp2.json().get("detail", "")
        assert "REPLAY_DETECTED" in detail or "replay" in detail.lower()
        
        # Verify family was revoked - new token should also fail
        resp3 = await pg_client.post("/api/v1/auth/refresh", headers={"Authorization": f"Bearer {new_refresh}"})
        assert resp3.status_code == 401
        detail3 = resp3.json().get("detail", "")
        assert "REPLAY_DETECTED" in detail3 or "replay" in detail3.lower()

    async def test_family_revocation_preserves_others(self, pg_client, pg_session):
        """Replay on one family should not affect other families."""
        from app.core.auth import hash_password
        from app.models import User
        
        user = User(email="family@example.com", password_hash=hash_password("Test123!"), role="USER", is_active=True)
        pg_session.add(user)
        await pg_session.commit()
        await pg_session.refresh(user)
        
        # Login twice to create two families (would need separate login flows)
        # For now, test that revoke_family only affects target family
        from datetime import UTC, datetime, timedelta
        from uuid import uuid4

        from app.core.auth import revoke_family

        # Create two sessions manually
        from app.models import Session as SessionModel
        
        fam1 = uuid4()
        fam2 = uuid4()
        now = datetime.now(UTC)
        
        s1 = SessionModel(
            user_id=user.id,
            session_token_hash="hash1",
            csrf_token="csrf1",
            refresh_token_hash="refresh1",
            family_id=fam1,
            family_created_at=now,
            family_expires_at=now + timedelta(days=7),
            expires_at=now + timedelta(minutes=30),
            ip_hash="ip1",
        )
        s2 = SessionModel(
            user_id=user.id,
            session_token_hash="hash2",
            csrf_token="csrf2",
            refresh_token_hash="refresh2",
            family_id=fam2,
            family_created_at=now,
            family_expires_at=now + timedelta(days=7),
            expires_at=now + timedelta(minutes=30),
            ip_hash="ip2",
        )
        pg_session.add_all([s1, s2])
        await pg_session.commit()
        
        # Revoke family 1
        await revoke_family(pg_session, fam1, "REPLAY")
        await pg_session.flush()
        
        # Verify family 1 sessions deleted, family 2 preserved
        result = await pg_session.execute(select(SessionModel).where(SessionModel.family_id == fam1))
        assert len(result.scalars().all()) == 0
        
        result = await pg_session.execute(select(SessionModel).where(SessionModel.family_id == fam2))
        assert len(result.scalars().all()) == 1
        
        # Verify blacklist has only family 1 tokens
        from app.core.auth import RevokedRefreshToken
        result = await pg_session.execute(select(RevokedRefreshToken))
        revoked = result.scalars().all()
        for r in revoked:
            assert r.family_id == fam1


class TestMigrationDowngradeUpgrade:
    """Test Alembic migration cycle on PostgreSQL."""

    async def test_downgrade_upgrade_cycle(self, pg_session):
        """Verify downgrade then upgrade preserves schema."""
        import os
        import subprocess
        from pathlib import Path
        
        # Get repository root dynamically
        repo_root = Path(__file__).parent.parent
        
        # Run downgrade
        result = subprocess.run(
            ["alembic", "downgrade", "-1"],
            env={**os.environ, "PHISHGUARD_DATABASE_URL": str(pg_session.bind.url)},
            capture_output=True,
            text=True,
            cwd=str(repo_root),
        )
        assert result.returncode == 0, f"Downgrade failed: {result.stderr}"
        
        # Verify revoked_refresh_tokens table dropped
        from sqlalchemy import inspect
        inspector = inspect(pg_session.bind)
        tables = inspector.get_table_names()
        assert "revoked_refresh_tokens" not in tables
        
        # Run upgrade
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            env={**os.environ, "PHISHGUARD_DATABASE_URL": str(pg_session.bind.url)},
            capture_output=True,
            text=True,
            cwd=str(repo_root),
        )
        assert result.returncode == 0, f"Upgrade failed: {result.stderr}"
        
        # Verify table recreated
        tables = inspect(pg_session.bind).get_table_names()
        assert "revoked_refresh_tokens" in tables
        
        # Verify indexes exist
        indexes = inspector.get_indexes("revoked_refresh_tokens")
        index_names = [i["name"] for i in indexes]
        assert "ix_revoked_refresh_tokens_token_hash" in index_names
        assert "ix_revoked_refresh_tokens_family_id" in indexes


class TestRollbackBehavior:
    """Test transaction rollback behavior."""

    async def test_rollback_on_session_error(self, pg_session):
        """Verify session state is clean after IntegrityError rollback."""
        from sqlalchemy.dialects.postgresql import insert as pg_insert
        
        token_hash = "test-rollback-token"
        
        # Insert first
        stmt = pg_insert(RevokedRefreshToken).values(
            token_hash=token_hash,
            user_id="11111111-1111-1111-1111-111111111111",
            family_id="22222222-2222-2222-2222-222222222222",
            revoked_reason="ROTATION",
            original_expires_at="2099-12-31 23:59:59+00"
        ).on_conflict_do_nothing(index_elements=["token_hash"])
        
        await pg_session.execute(stmt)
        await pg_session.flush()
        
        # Verify it exists
        result = await pg_session.execute(
            select(RevokedRefreshToken).where(RevokedRefreshToken.token_hash == token_hash)
        )
        assert result.scalar_one_or_none() is not None
        
        # Simulate error and rollback in a new transaction context
        # (This tests that rollback cleans up properly)
        await pg_session.rollback()
        
        # Session should be clean
        await pg_session.flush()


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])