"""create_detection_table

Revision ID: e84844000fa9
Revises: d267e3702780
Create Date: 2023-11-04 18:35:51.206853

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e84844000fa9'
down_revision: Union[str, None] = 'd267e3702780'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "detections",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id")),
        sa.Column("date", sa.DateTime, nullable=True),
        sa.Column("url_original", sa.String, nullable=True),
        sa.Column("url_processed", sa.String, nullable=True),
        sa.Column("positive", sa.String, nullable=True),
        sa.Column("confidence", sa.Float, nullable=True),
    )


def downgrade() -> None:
    op.drop_table("detections")
