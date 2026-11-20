"""add token attestation table

Revision ID: bd9d5d4cb2c8
Revises: bc91b45c54bf
Create Date: 2026-11-19 10:28:48.206359

"""
from typing import Sequence, Union

from token_service.store.orm import PendulumDateTime

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bd9d5d4cb2c8'
down_revision: Union[str, Sequence[str], None] = 'bc91b45c54bf'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'token_attestation',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('token_id', sa.String(length=36), nullable=False),
        sa.Column('attested_by', sa.String(length=32), nullable=False),
        sa.Column('attested_at', PendulumDateTime(), nullable=False),
        sa.Column('rotated_at', PendulumDateTime(), nullable=True),
        sa.ForeignKeyConstraint(['token_id'], ['token.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(
        op.f('ix_token_attestation_token_id'), 'token_attestation', ['token_id']
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_token_attestation_token_id'), table_name='token_attestation')
    op.drop_table('token_attestation')
