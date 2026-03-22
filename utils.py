import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated
from urllib.parse import urlparse

import asyncpg
import pytz
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

import models as mod

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

EXTENSIONES_PERMITIDAS = {"jpg", "jpeg", "png", "webp"}
DEFAULT_ZONES = [
    ("Europe/Madrid", 6, 18),
    ("Atlantic/Canary", 6, 18),
]

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = int(os.getenv("DB_PORT", "5432"))

_db_pool: asyncpg.Pool | None = None


async def init_db_pool() -> None:
    global _db_pool

    if _db_pool is not None:
        return

    _db_pool = await asyncpg.create_pool(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_DATABASE,
        host=DB_HOST,
        port=DB_PORT,
        min_size=1,
        max_size=10,
    )


async def close_db_pool() -> None:
    global _db_pool

    if _db_pool is None:
        return

    await _db_pool.close()
    _db_pool = None


@asynccontextmanager
async def get_database_connection():
    if _db_pool is not None:
        async with _db_pool.acquire() as conn:
            yield conn
        return

    conn = await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_DATABASE,
        host=DB_HOST,
        port=DB_PORT,
    )
    try:
        yield conn
    finally:
        await conn.close()


async def ensure_default_zone(conn: asyncpg.Connection):
    insert_query = """
        INSERT INTO zones (timezone, start_time, end_time)
        VALUES ($1, $2, $3)
        RETURNING id, timezone, start_time, end_time
    """

    for timezone_name, start_time, end_time in DEFAULT_ZONES:
        existing_zone = await conn.fetchrow(
            "SELECT id FROM zones WHERE timezone = $1",
            timezone_name,
        )
        if existing_zone is None:
            await conn.fetchrow(insert_query, timezone_name, start_time, end_time)

    zone = await conn.fetchrow(
        "SELECT id, timezone, start_time, end_time FROM zones WHERE timezone = $1 LIMIT 1",
        "Europe/Madrid",
    )
    if zone is not None:
        return zone

    return await conn.fetchrow(
        "SELECT id, timezone, start_time, end_time FROM zones ORDER BY id LIMIT 1"
    )


async def get_zone_by_id_or_default(
    conn: asyncpg.Connection,
    zones_id: int | None,
    user_id: int | None = None,
):
    default_zone = await ensure_default_zone(conn)

    zone = None
    if zones_id is not None:
        zone = await conn.fetchrow(
            "SELECT id, timezone, start_time, end_time FROM zones WHERE id = $1",
            zones_id,
        )

    if zone is not None:
        return zone

    if user_id is not None:
        await conn.execute(
            "UPDATE users SET zones_id = $1 WHERE id = $2",
            default_zone["id"],
            user_id,
        )

    return default_zone


async def get_user_from_db(email: str):
    async with get_database_connection() as conn:
        user_record = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        if user_record:
            return mod.User(**user_record)
        return None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


async def authenticate_user(email: str, password: str):
    user = await get_user_from_db(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta if expires_delta is not None else timedelta(minutes=15)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> mod.User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str | None = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = mod.TokenData(email=email)
    except JWTError as exc:
        raise credentials_exception from exc

    user = await get_user_from_db(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user


async def get_current_user_time(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    async with get_database_connection() as conn:
        timezone_record = await get_zone_by_id_or_default(
            conn,
            current_user.zones_id,
            current_user.id,
        )

    timezone_model = mod.Zones(**dict(timezone_record))
    user_timezone = pytz.timezone(timezone_model.timezone)
    date_time = datetime.now(pytz.utc).astimezone(user_timezone)
    hour = int(date_time.strftime("%H"))

    if hour < timezone_model.start_time or hour >= timezone_model.end_time:
        raise HTTPException(status_code=400, detail="Not allowed at this time")
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_current_active_user(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


async def get_current_user_is_superadmin(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")
    return current_user


def validar_extension(filename: str) -> bool:
    try:
        _, extension = filename.rsplit(".", 1)
        return extension.lower() in EXTENSIONES_PERMITIDAS
    except ValueError:
        return False


async def insert_results(user: mod.User, type: str, detections: int, not_detections: int):
    async with get_database_connection() as conn:
        await conn.execute(
            """
            INSERT INTO results (user_id, date, type, detections, not_detections)
            VALUES ($1, $2, $3, $4, $5)
            """,
            user.id,
            datetime.now(),
            type,
            detections,
            not_detections,
        )
    return user.email


async def insert_detection(
    user: mod.User,
    date: datetime,
    url_original: str,
    url_processed: str,
    confidence: float,
):
    async with get_database_connection() as conn:
        await conn.execute(
            """
            INSERT INTO detections (user_id, date, url_original, url_processed, confidence)
            VALUES ($1, $2, $3, $4, $5)
            """,
            user.id,
            date,
            url_original,
            url_processed,
            confidence,
        )
    return user.email


async def create_user(
    email: str,
    password: str,
    role: str,
    zones_id: int | None,
    is_active: bool = True,
):
    if await get_user_from_db(email):
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = pwd_context.hash(password)
    async with get_database_connection() as conn:
        zone = await get_zone_by_id_or_default(conn, zones_id)
        await conn.execute(
            """
            INSERT INTO users (email, hashed_password, role, is_active, zones_id)
            VALUES ($1, $2, $3, $4, $5)
            """,
            email,
            hashed_password,
            role,
            is_active,
            zone["id"],
        )
    return email


async def update_user(
    current_user: mod.User,
    user_id: int,
    email: str,
    role: str,
    zones_id: int | None,
    is_active: bool,
    password: str | None = None,
):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        existing_user = await conn.fetchrow(
            "SELECT id, email FROM users WHERE id = $1",
            user_id,
        )
        if existing_user is None:
            raise HTTPException(status_code=404, detail="User not found")

        duplicated_user = await conn.fetchrow(
            "SELECT id FROM users WHERE email = $1 AND id <> $2",
            email,
            user_id,
        )
        if duplicated_user is not None:
            raise HTTPException(status_code=400, detail="Email already registered")

        zone = await get_zone_by_id_or_default(conn, zones_id)
        await conn.execute(
            """
            UPDATE users
            SET email = $1, role = $2, is_active = $3, zones_id = $4
            WHERE id = $5
            """,
            email,
            role,
            is_active,
            zone["id"],
            user_id,
        )

        if password:
            hashed_password = pwd_context.hash(password)
            await conn.execute(
                "UPDATE users SET hashed_password = $1 WHERE id = $2",
                hashed_password,
                user_id,
            )

    return True


async def update_password(user: mod.User, password: str):
    hashed_password = pwd_context.hash(password)
    async with get_database_connection() as conn:
        await conn.execute(
            "UPDATE users SET hashed_password = $1 WHERE id = $2",
            hashed_password,
            user.id,
        )
    return user.email


async def statistics(
    current_user: mod.User,
    user_id: int | None = None,
    date: datetime | str | None = None,
):
    results2 = []
    results3 = []

    async with get_database_connection() as conn:
        if current_user.role == "superadmin":
            if user_id:
                results = await conn.fetch(
                    """
                    SELECT
                        SUM(not_detections) AS not_detections,
                        SUM(detections) AS detections,
                        SUM(not_detections) + SUM(detections) AS total_sum
                    FROM results
                    WHERE user_id = $1
                    """,
                    user_id,
                )
            else:
                results = await conn.fetch(
                    """
                    SELECT
                        SUM(not_detections) AS not_detections,
                        SUM(detections) AS detections,
                        SUM(not_detections) + SUM(detections) AS total_sum
                    FROM results
                    """
                )
                results3 = await conn.fetch(
                    """
                    SELECT
                        SUM(CASE WHEN positive = 'true' THEN 1 ELSE 0 END) AS true_detections,
                        SUM(CASE WHEN positive = 'false' THEN 1 ELSE 0 END) AS false_detections
                    FROM detections
                    """
                )

                if date is None:
                    selected_date = datetime.now().date()
                elif isinstance(date, str):
                    selected_date = datetime.strptime(date, "%Y-%m-%d").date()
                else:
                    selected_date = date.date()

                results2 = await conn.fetch(
                    """
                    SELECT
                        DATE_TRUNC('hour', date) AS hour,
                        SUM(detections) AS total_detections,
                        SUM(not_detections) AS total_not_detections
                    FROM results
                    WHERE DATE(date) = $1
                    GROUP BY DATE_TRUNC('hour', date)
                    ORDER BY DATE_TRUNC('hour', date)
                    """,
                    selected_date,
                )
        elif current_user.role == "user":
            if user_id:
                raise HTTPException(status_code=400, detail="Permissions required")

            results = await conn.fetch(
                """
                SELECT
                    SUM(not_detections) AS not_detections,
                    SUM(detections) AS detections
                FROM results
                WHERE user_id = $1
                """,
                current_user.id,
            )
        else:
            raise HTTPException(status_code=400, detail="Permissions required")

    return results, results2, results3


async def get_results_dates(current_user: mod.User):
    async with get_database_connection() as conn:
        if current_user.role == "superadmin":
            return await conn.fetch(
                "SELECT DATE(date) AS date FROM detections GROUP BY DATE(date) ORDER BY DATE(date) DESC"
            )
        if current_user.role == "user":
            return await conn.fetch(
                "SELECT DISTINCT DATE(date) AS date FROM detections WHERE user_id = $1 ORDER BY DATE(date) DESC",
                current_user.id,
            )
        raise HTTPException(status_code=400, detail="Permissions required")


async def get_results_images_date(current_user: mod.User, date: str | None = None):
    if not date:
        raise HTTPException(status_code=400, detail="Date is required")

    selected_date = datetime.strptime(date, "%Y-%m-%d").date()

    async with get_database_connection() as conn:
        if current_user.role == "superadmin":
            return await conn.fetch(
                """
                SELECT id, url_processed, positive
                FROM detections
                WHERE DATE(date) = $1
                ORDER BY id DESC
                """,
                selected_date,
            )
        if current_user.role == "user":
            return await conn.fetch(
                """
                SELECT url_original, url_processed, date
                FROM detections
                WHERE user_id = $1 AND DATE(date) = $2
                ORDER BY id DESC
                """,
                current_user.id,
                selected_date,
            )
        raise HTTPException(status_code=400, detail="Permissions required")


def es_extension_permitida(url: str) -> bool:
    try:
        path = urlparse(url).path
        extension = os.path.splitext(path)[1].lstrip(".").lower()
        return extension in EXTENSIONES_PERMITIDAS
    except Exception:
        return False


async def update_results_images_status(current_user: mod.User, id: int, positive):
    if isinstance(positive, str):
        normalized_positive = positive.lower() == "true"
    else:
        normalized_positive = bool(positive)

    async with get_database_connection() as conn:
        if current_user.role == "superadmin":
            await conn.execute(
                "UPDATE detections SET positive = $1 WHERE id = $2",
                normalized_positive,
                id,
            )
            return True
        raise HTTPException(status_code=400, detail="Permissions required")


async def get_zones(current_user: mod.User):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        await ensure_default_zone(conn)
        return await conn.fetch(
            "SELECT id, timezone, start_time, end_time FROM zones ORDER BY timezone"
        )


async def get_users(current_user: mod.User):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        default_zone = await ensure_default_zone(conn)
        await conn.execute(
            "UPDATE users SET zones_id = $1 WHERE zones_id IS NULL",
            default_zone["id"],
        )
        return await conn.fetch(
            """
            SELECT users.id, users.email, users.role, users.is_active, users.zones_id, zones.timezone
            FROM users
            LEFT JOIN zones ON users.zones_id = zones.id
            ORDER BY users.id
            """
        )


async def delete_user(current_user: mod.User, id: int):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")
    if id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete current user")

    async with get_database_connection() as conn:
        result = await conn.execute("DELETE FROM users WHERE id = $1", id)
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="User not found")
        return True
