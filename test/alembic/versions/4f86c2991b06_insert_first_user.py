"""insert_first_user

Revision ID: 4f86c2991b06
Revises: f42dfb451936
Create Date: 2023-10-25 11:31:44.836161

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4f86c2991b06'
down_revision: Union[str, None] = 'f42dfb451936'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # insert first user
    op.execute(
        """
        INSERT INTO users (email, hashed_password, is_active, full_name)
        VALUES ('admin@admin.com', '$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW', true, 'admin')
        """
    )

def downgrade() -> None:
    op.execute(
        """
        DELETE FROM users WHERE email = 'admin@admin.com'
        """
    )
