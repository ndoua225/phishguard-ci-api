"""add_mfa_rate_limiting_fields

Revision ID: 5cef0e3c5854
Revises: 0ee00382c8b6
Create Date: 2026-11-09 02:28:12.674586

"""
from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '5cef0e3c5854'
down_revision: str | Sequence[str] | None = '0ee00382c8b6'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # Add MFA rate limiting fields
    op.add_column('users', sa.Column('failed_mfa_attempts', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('users', sa.Column('mfa_locked_until', sa.DateTime(timezone=True), nullable=True))
    # Note: SQLite doesn't support ALTER COLUMN TYPE, so totp_secret type change
    # is handled by the application layer (storing longer encrypted secrets in VARCHAR(32))
    # For PostgreSQL, the type change would be handled separately


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('users', 'mfa_locked_until')
    op.drop_column('users', 'failed_mfa_attempts')
