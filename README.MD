Generate migration
alembic upgrade head

Delete migration
alembic downgrade -1
alembic downgrade 8ac14e223d1e


alembic.ini
sqlalchemy.url = postgresql://postgres:postgres@localhost:5433/guaitaia

main.py
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:postgres@localhost:5433/guaitaia"