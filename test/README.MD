Generate migration
alembic upgrade head

Delete migration
alembic downgrade -1
alembic downgrade 8ac14e223d1e