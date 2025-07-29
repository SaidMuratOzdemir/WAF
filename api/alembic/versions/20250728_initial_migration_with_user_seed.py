"""initial_migration_with_user_seed

Revision ID: 5ecae12b2a86
Revises: 
Create Date: 2025-07-28 20:07:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import func
from passlib.context import CryptContext

# revision identifiers, used by Alembic.
revision = '5ecae12b2a86'
down_revision = None
branch_labels = None
depends_on = None

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    """Hashes a plain password."""
    return pwd_context.hash(password)


def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(), nullable=False, index=True),
        sa.Column('password_hash', sa.String(), nullable=False),
        sa.Column('is_admin', sa.Boolean(), nullable=False, server_default=sa.text('false')),
        sa.Column('created_at', sa.DateTime(), server_default=func.now(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username')
    )
    
    # Create sites table
    op.create_table(
        'sites',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('port', sa.Integer(), nullable=False),
        sa.Column('host', sa.String(), nullable=False),
        sa.Column('name', sa.String(), nullable=False),
        sa.Column('frontend_url', sa.String(), nullable=False),
        sa.Column('backend_url', sa.String(), nullable=False),
        sa.Column('xss_enabled', sa.Boolean(), server_default=sa.text('true'), nullable=True),
        sa.Column('sql_enabled', sa.Boolean(), server_default=sa.text('true'), nullable=True),
        sa.Column('vt_enabled', sa.Boolean(), server_default=sa.text('false'), nullable=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('port', 'host', name='unique_port_host')
    )
    
    # Create malicious_patterns table
    op.create_table(
        'malicious_patterns',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('pattern', sa.String(), nullable=False, index=True),
        sa.Column('type', sa.String(), nullable=False, index=True),
        sa.Column('description', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(), server_default=func.now(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), server_default=func.now(), onupdate=func.now(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Add admin user seed
    op.bulk_insert(
        sa.table(
            'users',
            sa.Column('username', sa.String()),
            sa.Column('password_hash', sa.String()),
            sa.Column('is_admin', sa.Boolean())
        ),
        [
            {
                'username': 'admin',
                'password_hash': get_password_hash('waf'),
                'is_admin': True
            }
        ]
    )


def downgrade() -> None:
    op.drop_table('malicious_patterns')
    op.drop_table('sites')
    op.drop_table('users')