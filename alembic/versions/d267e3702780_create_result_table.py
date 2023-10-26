"""create_result_table

Revision ID: d267e3702780
Revises: 4f86c2991b06
Create Date: 2023-10-26 11:24:36.284292

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd267e3702780'
down_revision: Union[str, None] = '4f86c2991b06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "results",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id")),
        sa.Column("date", sa.DateTime, nullable=True),
        sa.Column("type", sa.String, nullable=True),
        sa.Column("detections", sa.Integer, nullable=True),
        sa.Column("not_detections", sa.Integer, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("results")
