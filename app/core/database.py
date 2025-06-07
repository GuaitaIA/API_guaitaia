# app/core/database.py (CORREGIDO para SQLAlchemy 2.0)
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker  # ← Importación corregida
import asyncpg
from .config import settings

# SQLAlchemy setup
engine = create_engine(settings.database_url)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()  # ← Ahora desde sqlalchemy.orm

# Database dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Async database connection
async def get_database_connection():
    """
    Establece una conexión asincrónica a la base de datos PostgreSQL.
    """
    conn = await asyncpg.connect(
        user=settings.db_user,
        password=settings.db_password,
        database=settings.db_name,
        host=settings.db_host,
        port=settings.db_port
    )
    return conn
