"""create_zones_table

Revision ID: 8fc02b7758b8
Revises: e84844000fa9
Create Date: 2023-11-16 15:02:16.135740

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '8fc02b7758b8'
down_revision: Union[str, None] = 'e84844000fa9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "zones",
        sa.Column("id", sa.Integer, primary_key=True, index=True),
        sa.Column('timezone', sa.VARCHAR(), autoincrement=False, nullable=False),
        sa.Column('start_time', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('end_time', sa.INTEGER(), autoincrement=False, nullable=False),
    )
    # añadir a la tabla users la columna zones que hace referencia a la tabla zones
    op.add_column('users', sa.Column('zones_id', sa.Integer, sa.ForeignKey('zones.id'), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'zones_id')
    op.drop_table('zones')