"""add_notification_sound_setting

Revision ID: a2c4d5e6f701
Revises: f1a1b3de9f22
Create Date: 2026-03-23 20:20:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "a2c4d5e6f701"
down_revision: Union[str, None] = "f1a1b3de9f22"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "notification_sound_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )
    op.alter_column("users", "notification_sound_enabled", server_default=None)


def downgrade() -> None:
    op.drop_column("users", "notification_sound_enabled")
