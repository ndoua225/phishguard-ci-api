"""add_auth_v22

Revision ID: 9e1ceeb19eed
Revises: 5cef0e3c5854
Create Date: 2026-11-09 09:16:54.225244

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '9e1ceeb19eed'
down_revision: str | Sequence[str] | None = '5cef0e3c5854'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema - V2.2 Auth changes only."""
    # Create revoked_refresh_tokens table
    op.create_table('revoked_refresh_tokens',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('family_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('revoked_reason', sa.String(length=64), nullable=False),
        sa.Column('original_expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_revoked_family_revoked', 'revoked_refresh_tokens', ['family_id', 'revoked_at'], unique=False)
    op.create_index(op.f('ix_revoked_refresh_tokens_family_id'), 'revoked_refresh_tokens', ['family_id'], unique=False)
    op.create_index(op.f('ix_revoked_refresh_tokens_token_hash'), 'revoked_refresh_tokens', ['token_hash'], unique=True)
    op.create_index(op.f('ix_revoked_refresh_tokens_user_id'), 'revoked_refresh_tokens', ['user_id'], unique=False)
    op.create_index('ix_revoked_user_revoked', 'revoked_refresh_tokens', ['user_id', 'revoked_at'], unique=False)

    # Add V2.2 auth columns to sessions table
    op.add_column('sessions', sa.Column('session_token_hash', sa.String(length=64), nullable=False))
    op.add_column('sessions', sa.Column('refresh_token_hash', sa.String(length=64), nullable=True))
    op.add_column('sessions', sa.Column('family_id', postgresql.UUID(as_uuid=True), nullable=False))
    op.add_column('sessions', sa.Column('family_created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False))
    op.add_column('sessions', sa.Column('family_expires_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index(op.f('ix_sessions_family_expires_at'), 'sessions', ['family_expires_at'], unique=False)
    op.create_index(op.f('ix_sessions_family_id'), 'sessions', ['family_id'], unique=False)
    op.create_index(op.f('ix_sessions_refresh_token_hash'), 'sessions', ['refresh_token_hash'], unique=False)
    op.create_index(op.f('ix_sessions_session_token_hash'), 'sessions', ['session_token_hash'], unique=True)


def downgrade() -> None:
    """Downgrade schema - V2.2 Auth changes only."""
    # Drop indexes
    op.drop_index(op.f('ix_sessions_session_token_hash'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_refresh_token_hash'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_family_id'), table_name='sessions')
    op.drop_index(op.f('ix_sessions_family_expires_at'), table_name='sessions')
    
    # Drop columns
    op.drop_column('sessions', 'family_expires_at')
    op.drop_column('sessions', 'family_created_at')
    op.drop_column('sessions', 'family_id')
    op.drop_column('sessions', 'refresh_token_hash')
    op.drop_column('sessions', 'session_token_hash')

    # Drop revoked_refresh_tokens table
    op.drop_index('ix_revoked_user_revoked', table_name='revoked_refresh_tokens')
    op.drop_index(op.f('ix_revoked_refresh_tokens_user_id'), table_name='revoked_refresh_tokens')
    op.drop_index(op.f('ix_revoked_refresh_tokens_token_hash'), table_name='revoked_refresh_tokens')
    op.drop_index(op.f('ix_revoked_refresh_tokens_family_id'), table_name='revoked_refresh_tokens')
    op.drop_index('ix_revoked_family_revoked', table_name='revoked_refresh_tokens')
    op.drop_table('revoked_refresh_tokens')