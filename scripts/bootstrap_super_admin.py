#!/usr/bin/env python3
"""Bootstrap script to create the initial SUPER_ADMIN user.

This script creates the first SUPER_ADMIN account securely:
- Reads configuration from environment variables
- Prompts for password securely (no echo)
- No hardcoded passwords
- Password never logged
- Prevents creating a second SUPER_ADMIN by mistake
"""

from __future__ import annotations

import getpass
import os
import sys

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

# Add the app directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.config import Settings
from app.models import User, UserRole


async def bootstrap_super_admin() -> None:
    """Create the initial SUPER_ADMIN user."""
    settings = Settings()
    
    # Create engine
    engine = create_async_engine(settings.database_url, echo=False)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        # Check if SUPER_ADMIN already exists
        result = await session.execute(
            select(User).where(User.role == UserRole.SUPER_ADMIN)
        )
        existing_admin = result.scalar_one_or_none()
        
        if existing_admin:
            print(f"ERROR: SUPER_ADMIN already exists: {existing_admin.email}")
            print("Cannot create a second SUPER_ADMIN. Use the admin panel to manage users.")
            await engine.dispose()
            sys.exit(1)
        
        # Get email from environment or prompt
        email = os.environ.get("PHISHGUARD_BOOTSTRAP_EMAIL")
        if not email:
            email = input("Enter SUPER_ADMIN email: ").strip()
            if not email:
                print("ERROR: Email is required")
                await engine.dispose()
                sys.exit(1)
        
        # Validate email format
        if "@" not in email:
            print("ERROR: Invalid email format")
            await engine.dispose()
            sys.exit(1)
        
        # Check if email already exists
        result = await session.execute(select(User).where(User.email == email))
        if result.scalar_one_or_none():
            print(f"ERROR: User with email {email} already exists")
            await engine.dispose()
            sys.exit(1)
        
        # Get password securely
        password = os.environ.get("PHISHGUARD_BOOTSTRAP_PASSWORD")
        if not password:
            password = getpass.getpass("Enter SUPER_ADMIN password: ")
            if not password:
                print("ERROR: Password is required")
                await engine.dispose()
                sys.exit(1)
            confirm = getpass.getpass("Confirm password: ")
            if password != confirm:
                print("ERROR: Passwords do not match")
                await engine.dispose()
                sys.exit(1)
        
        if len(password) < 12:
            print("ERROR: Password must be at least 12 characters")
            await engine.dispose()
            sys.exit(1)
        
        # Hash password and create user
        from app.core.auth import hash_password
        
        user = User(
            email=email,
            password_hash=hash_password(password),
            role=UserRole.SUPER_ADMIN,
            is_active=True,
            is_test_account=False,
        )
        
        session.add(user)
        await session.commit()
        await session.refresh(user)
        
        print(f"SUCCESS: SUPER_ADMIN created with ID: {user.id}")
        print(f"Email: {user.email}")
        print("You can now log in at /auth/login")
        
        await engine.dispose()


if __name__ == "__main__":
    import asyncio
    asyncio.run(bootstrap_super_admin())