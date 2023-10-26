"""create_user_table

Revision ID: f42dfb451936
Revises: 
Create Date: 2023-10-25 10:32:11.588931

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f42dfb451936'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("email", sa.String, unique=True, index=True),
        sa.Column("hashed_password", sa.String),
        sa.Column("is_active", sa.Boolean, default=True),
        sa.Column("role", sa.String)
    )


def downgrade() -> None:
    op.drop_table("users")
