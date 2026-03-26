"""Add webhooks table

Revision ID: b7c8d9e0f1a2
Revises: a1b2c3d4e5f6
Create Date: 2026-03-26
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = 'b7c8d9e0f1a2'
down_revision = '320927bb680c'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'webhooks',
        sa.Column('id', sa.String(16), primary_key=True),
        sa.Column('url', sa.String(500), nullable=False),
        sa.Column('secret', sa.String(200), nullable=True),
        sa.Column('events', sa.Text(), nullable=False, server_default='["*"]'),
        sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('created_at', sa.DateTime(), nullable=False),
    )


def downgrade():
    op.drop_table('webhooks')
