"""create_role_hierarchy_table

Revision ID: c3c0d7b7a2f1
Revises: 8fc02b7758b8
Create Date: 2026-03-22 19:10:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "c3c0d7b7a2f1"
down_revision: Union[str, None] = "8fc02b7758b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "role_hierarchy",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(["parent_id"], ["role_hierarchy.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(
        op.f("ix_role_hierarchy_id"),
        "role_hierarchy",
        ["id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_role_hierarchy_name"),
        "role_hierarchy",
        ["name"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_role_hierarchy_name"), table_name="role_hierarchy")
    op.drop_index(op.f("ix_role_hierarchy_id"), table_name="role_hierarchy")
    op.drop_table("role_hierarchy")
