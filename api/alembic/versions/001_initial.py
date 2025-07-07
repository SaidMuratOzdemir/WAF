"""Initial migration

Revision ID: 001_initial
Create Date: 2025-07-06 18:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '001_initial'
down_revision = None
branch_labels = None
depends_on = None

def upgrade() -> None:
    op.create_table(
        'sites',
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('frontend_url', sa.String(), nullable=False),
        sa.Column('backend_url', sa.String(), nullable=False),
        sa.Column('xss_enabled', sa.Boolean(), default=True),
        sa.Column('sql_enabled', sa.Boolean(), default=True),
        sa.PrimaryKeyConstraint('port')
    )

def downgrade() -> None:
    op.drop_table('sites')
