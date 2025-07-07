"""Add users table

Revision ID: 002_add_users
Create Date: 2025-07-06 19:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import table, column
from passlib.context import CryptContext

# revision identifiers, used by Alembic.
revision = '002_add_users'
down_revision = '001_initial'
branch_labels = None
depends_on = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def upgrade() -> None:
    # Create users table
    op.create_table(
        'users',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('username', sa.String, unique=True, nullable=False),
        sa.Column('password_hash', sa.String, nullable=False),
        sa.Column('is_admin', sa.Boolean, default=False, nullable=False),
        sa.Column('created_at', sa.DateTime, server_default=sa.func.now())
    )

    # Create default admin user
    users = table('users',
        column('username', sa.String),
        column('password_hash', sa.String),
        column('is_admin', sa.Boolean)
    )

    # Hash default password: "waf"
    hashed_password = pwd_context.hash("waf")
    
    op.bulk_insert(users,
        [
            {
                'username': 'admin',
                'password_hash': hashed_password,
                'is_admin': True
            }
        ]
    )

def downgrade() -> None:
    op.drop_table('users')
