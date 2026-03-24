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
    ("Full", 0, 24),
]
DEFAULT_ROLE_HIERARCHY = [
    {
        "name": "superadmin",
        "description": "Acceso total a la administracion de GuaitaIA.",
        "parent_name": None,
    },
    {
        "name": "user",
        "description": "Usuario operativo del sistema.",
        "parent_name": "superadmin",
    },
]
PROTECTED_ROLES = {"superadmin", "user"}

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


def normalize_role_name(role_name: str | None) -> str:
    normalized_name = " ".join((role_name or "").strip().split())
    if not normalized_name:
        raise HTTPException(status_code=400, detail="Role name is required")
    return normalized_name


def get_role_lookup_name(role_name: str | None) -> str:
    return " ".join((role_name or "").strip().split()).lower()


def is_superadmin_role(role_name: str | None) -> bool:
    return get_role_lookup_name(role_name) == "superadmin"


def is_user_role(role_name: str | None) -> bool:
    return get_role_lookup_name(role_name) == "user"


def is_full_access_zone(timezone_name: str | None) -> bool:
    return " ".join((timezone_name or "").strip().split()).lower() == "full"


async def role_hierarchy_exists(conn: asyncpg.Connection) -> bool:
    return await conn.fetchval(
        """
        SELECT EXISTS (
            SELECT 1
            FROM information_schema.tables
            WHERE table_schema = 'public' AND table_name = 'role_hierarchy'
        )
        """
    )


async def ensure_default_role_hierarchy(conn: asyncpg.Connection) -> None:
    if not await role_hierarchy_exists(conn):
        return

    created_role_ids: dict[str, int] = {}

    for role in DEFAULT_ROLE_HIERARCHY:
        existing_role = await conn.fetchrow(
            "SELECT id, parent_id FROM role_hierarchy WHERE LOWER(name) = LOWER($1)",
            role["name"],
        )

        if existing_role is None:
            parent_id = created_role_ids.get(role["parent_name"])
            created_role = await conn.fetchrow(
                """
                INSERT INTO role_hierarchy (name, description, parent_id)
                VALUES ($1, $2, $3)
                RETURNING id
                """,
                role["name"],
                role["description"],
                parent_id,
            )
            created_role_ids[role["name"]] = created_role["id"]
            continue

        created_role_ids[role["name"]] = existing_role["id"]

        if role["parent_name"] is not None and existing_role["parent_id"] is None:
            parent_id = created_role_ids.get(role["parent_name"])
            if parent_id is not None:
                await conn.execute(
                    "UPDATE role_hierarchy SET parent_id = $1 WHERE id = $2",
                    parent_id,
                    existing_role["id"],
                )

    existing_user_roles = await conn.fetch(
        "SELECT DISTINCT role FROM users WHERE role IS NOT NULL AND BTRIM(role) <> ''"
    )
    for row in existing_user_roles:
        normalized_name = normalize_role_name(row["role"])
        existing_role = await conn.fetchrow(
            "SELECT id FROM role_hierarchy WHERE LOWER(name) = LOWER($1)",
            normalized_name,
        )
        if existing_role is None:
            await conn.execute(
                """
                INSERT INTO role_hierarchy (name, description, parent_id)
                VALUES ($1, NULL, NULL)
                """,
                normalized_name,
            )


async def get_role_by_id(conn: asyncpg.Connection, role_id: int):
    return await conn.fetchrow(
        "SELECT id, name, description, parent_id FROM role_hierarchy WHERE id = $1",
        role_id,
    )


async def get_role_by_name(conn: asyncpg.Connection, role_name: str):
    return await conn.fetchrow(
        """
        SELECT id, name, description, parent_id
        FROM role_hierarchy
        WHERE LOWER(name) = LOWER($1)
        """,
        normalize_role_name(role_name),
    )


async def validate_role_parent(
    conn: asyncpg.Connection,
    role_id: int | None,
    parent_id: int | None,
) -> asyncpg.Record | None:
    if parent_id is None:
        return None

    if role_id is not None and parent_id == role_id:
        raise HTTPException(
            status_code=400,
            detail="A role cannot be parent of itself",
        )

    parent_role = await get_role_by_id(conn, parent_id)
    if parent_role is None:
        raise HTTPException(status_code=404, detail="Parent role not found")

    if role_id is not None:
        is_descendant = await conn.fetchval(
            """
            WITH RECURSIVE descendants AS (
                SELECT id, parent_id
                FROM role_hierarchy
                WHERE parent_id = $1
                UNION ALL
                SELECT child.id, child.parent_id
                FROM role_hierarchy child
                INNER JOIN descendants ON child.parent_id = descendants.id
            )
            SELECT EXISTS(SELECT 1 FROM descendants WHERE id = $2)
            """,
            role_id,
            parent_id,
        )
        if is_descendant:
            raise HTTPException(
                status_code=400,
                detail="A role cannot depend on one of its descendants",
            )

    return parent_role


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
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")

    if is_full_access_zone(timezone_model.timezone):
        return current_user

    user_timezone = pytz.timezone(timezone_model.timezone)
    date_time = datetime.now(pytz.utc).astimezone(user_timezone)
    hour = int(date_time.strftime("%H"))

    if hour < timezone_model.start_time or hour >= timezone_model.end_time:
        raise HTTPException(status_code=400, detail="Not allowed at this time")
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
    if not is_superadmin_role(current_user.role):
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
        detection_record = await conn.fetchrow(
            """
            INSERT INTO detections (user_id, date, url_original, url_processed, confidence)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            """,
            user.id,
            date,
            url_original,
            url_processed,
            confidence,
        )
        await create_detection_notifications(
            conn,
            user,
            detection_record["id"],
            date,
            confidence,
        )
    return detection_record["id"]


async def create_detection_notifications(
    conn: asyncpg.Connection,
    source_user: mod.User,
    detection_id: int,
    detection_date: datetime,
    confidence: float,
):
    if not await role_hierarchy_exists(conn):
        return

    await ensure_default_role_hierarchy(conn)

    source_role = await get_role_by_name(conn, source_user.role or "")
    if source_role is None:
        return

    recipients = await conn.fetch(
        """
        WITH RECURSIVE allowed_roles AS (
            SELECT id, parent_id
            FROM role_hierarchy
            WHERE id = $1
            UNION ALL
            SELECT parent.id, parent.parent_id
            FROM role_hierarchy parent
            INNER JOIN allowed_roles current_hierarchy_role ON current_hierarchy_role.parent_id = parent.id
        )
        SELECT DISTINCT users.id
        FROM users
        INNER JOIN role_hierarchy ON LOWER(role_hierarchy.name) = LOWER(users.role)
        INNER JOIN allowed_roles ON allowed_roles.id = role_hierarchy.id
        WHERE users.id <> $2
          AND users.is_active = TRUE
          AND COALESCE(users.notifications_enabled, TRUE) = TRUE
        ORDER BY users.id
        """,
        source_role["id"],
        source_user.id,
    )

    if not recipients:
        return

    confidence_percentage = round(confidence * 100)
    detection_timestamp = detection_date.strftime("%d/%m/%Y %H:%M:%S")
    title = "Columna de humo detectada"
    message = (
        f"{source_user.email} ha registrado una deteccion positiva "
        f"el {detection_timestamp} con una confianza del {confidence_percentage}%."
    )

    await conn.executemany(
        """
        INSERT INTO notifications (user_id, source_user_id, detection_id, title, message)
        VALUES ($1, $2, $3, $4, $5)
        """,
        [
            (recipient["id"], source_user.id, detection_id, title, message)
            for recipient in recipients
        ],
    )


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
        await ensure_default_role_hierarchy(conn)
        role_record = await get_role_by_name(conn, role)
        if role_record is None:
            raise HTTPException(status_code=400, detail="Selected role does not exist")
        zone = await get_zone_by_id_or_default(conn, zones_id)
        await conn.execute(
            """
            INSERT INTO users (
                email,
                hashed_password,
                role,
                is_active,
                zones_id,
                notifications_enabled,
                notification_sound_enabled
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            email,
            hashed_password,
            role_record["name"],
            is_active,
            zone["id"],
            True,
            True,
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
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        await ensure_default_role_hierarchy(conn)
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

        role_record = await get_role_by_name(conn, role)
        if role_record is None:
            raise HTTPException(status_code=400, detail="Selected role does not exist")

        zone = await get_zone_by_id_or_default(conn, zones_id)
        await conn.execute(
            """
            UPDATE users
            SET email = $1, role = $2, is_active = $3, zones_id = $4
            WHERE id = $5
            """,
            email,
            role_record["name"],
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
        if is_superadmin_role(current_user.role):
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
        else:
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

    return results, results2, results3


async def get_results_dates(current_user: mod.User):
    async with get_database_connection() as conn:
        if is_superadmin_role(current_user.role):
            return await conn.fetch(
                "SELECT DATE(date) AS date FROM detections GROUP BY DATE(date) ORDER BY DATE(date) DESC"
            )

        return await conn.fetch(
            "SELECT DISTINCT DATE(date) AS date FROM detections WHERE user_id = $1 ORDER BY DATE(date) DESC",
            current_user.id,
        )


async def get_results_images_date(current_user: mod.User, date: str | None = None):
    if not date:
        raise HTTPException(status_code=400, detail="Date is required")

    selected_date = datetime.strptime(date, "%Y-%m-%d").date()

    async with get_database_connection() as conn:
        if is_superadmin_role(current_user.role):
            return await conn.fetch(
                """
                SELECT id, url_original, url_processed, positive, confidence, date
                FROM detections
                WHERE DATE(date) = $1
                ORDER BY id DESC
                """,
                selected_date,
            )

        return await conn.fetch(
            """
            SELECT id, url_original, url_processed, positive, confidence, date
            FROM detections
            WHERE user_id = $1 AND DATE(date) = $2
            ORDER BY id DESC
            """,
            current_user.id,
            selected_date,
        )


def es_extension_permitida(url: str) -> bool:
    try:
        path = urlparse(url).path
        extension = os.path.splitext(path)[1].lstrip(".").lower()
        return extension in EXTENSIONES_PERMITIDAS
    except Exception:
        return False


async def update_results_images_status(current_user: mod.User, id: int, positive):
    if id is None:
        raise HTTPException(status_code=400, detail="Image id is required")

    if isinstance(positive, str):
        normalized_positive = "true" if positive.lower() == "true" else "false"
    else:
        normalized_positive = "true" if bool(positive) else "false"

    async with get_database_connection() as conn:
        if is_superadmin_role(current_user.role):
            await conn.execute(
                "UPDATE detections SET positive = $1 WHERE id = $2",
                normalized_positive,
                id,
            )
            return True
        raise HTTPException(status_code=400, detail="Permissions required")


async def get_zones(current_user: mod.User):
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        await ensure_default_zone(conn)
        return await conn.fetch(
            "SELECT id, timezone, start_time, end_time FROM zones ORDER BY timezone"
        )


async def get_users(current_user: mod.User):
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        default_zone = await ensure_default_zone(conn)
        await ensure_default_role_hierarchy(conn)
        await conn.execute(
            "UPDATE users SET zones_id = $1 WHERE zones_id IS NULL",
            default_zone["id"],
        )
        return await conn.fetch(
            """
            SELECT
                users.id,
                users.email,
                users.role,
                users.is_active,
                users.notifications_enabled,
                users.zones_id,
                zones.timezone
            FROM users
            LEFT JOIN zones ON users.zones_id = zones.id
            ORDER BY users.id
            """
        )


async def delete_user(current_user: mod.User, id: int):
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")
    if id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete current user")

    async with get_database_connection() as conn:
        result = await conn.execute("DELETE FROM users WHERE id = $1", id)
        if result == "DELETE 0":
            raise HTTPException(status_code=404, detail="User not found")
        return True


async def get_notification_settings(current_user: mod.User):
    async with get_database_connection() as conn:
        settings = await conn.fetchrow(
            """
            SELECT
                COALESCE(notifications_enabled, TRUE) AS notifications_enabled,
                COALESCE(notification_sound_enabled, TRUE) AS notification_sound_enabled
            FROM users
            WHERE id = $1
            """,
            current_user.id,
        )

    return {
        "notifications_enabled": bool(settings["notifications_enabled"]),
        "notification_sound_enabled": bool(settings["notification_sound_enabled"]),
    }


async def update_notification_settings(
    current_user: mod.User,
    notifications_enabled: bool,
    notification_sound_enabled: bool,
):
    async with get_database_connection() as conn:
        await conn.execute(
            """
            UPDATE users
            SET notifications_enabled = $1, notification_sound_enabled = $2
            WHERE id = $3
            """,
            notifications_enabled,
            notification_sound_enabled,
            current_user.id,
        )

    return {
        "notifications_enabled": notifications_enabled,
        "notification_sound_enabled": notification_sound_enabled,
    }


async def get_unread_notifications(current_user: mod.User):
    async with get_database_connection() as conn:
        notifications_enabled = await conn.fetchval(
            """
            SELECT COALESCE(notifications_enabled, TRUE)
            FROM users
            WHERE id = $1
            """,
            current_user.id,
        )

        if notifications_enabled is False:
            return []

        notifications = await conn.fetch(
            """
            SELECT id, title, message, detection_id, created_at
            FROM notifications
            WHERE user_id = $1 AND is_read = FALSE
            ORDER BY created_at ASC
            LIMIT 20
            """,
            current_user.id,
        )

    return [dict(notification) for notification in notifications]


async def mark_notifications_as_read(
    current_user: mod.User,
    notification_ids: list[int],
):
    if not notification_ids:
        return True

    async with get_database_connection() as conn:
        await conn.execute(
            """
            UPDATE notifications
            SET is_read = TRUE
            WHERE user_id = $1
              AND id = ANY($2::int[])
            """,
            current_user.id,
            notification_ids,
        )

    return True


async def get_roles(current_user: mod.User):
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        await ensure_default_role_hierarchy(conn)
        roles = await conn.fetch(
            """
            WITH RECURSIVE role_tree AS (
                SELECT
                    id,
                    name,
                    description,
                    parent_id,
                    0 AS depth,
                    LOWER(name) AS sort_path
                FROM role_hierarchy
                WHERE parent_id IS NULL
                UNION ALL
                SELECT
                    child.id,
                    child.name,
                    child.description,
                    child.parent_id,
                    role_tree.depth + 1 AS depth,
                    role_tree.sort_path || '>' || LOWER(child.name) AS sort_path
                FROM role_hierarchy child
                INNER JOIN role_tree ON child.parent_id = role_tree.id
            )
            SELECT
                role_tree.id,
                role_tree.name,
                role_tree.description,
                role_tree.parent_id,
                parent.name AS parent_name,
                role_tree.depth,
                COALESCE(users_count.users_count, 0) AS users_count
            FROM role_tree
            LEFT JOIN role_hierarchy parent ON parent.id = role_tree.parent_id
            LEFT JOIN (
                SELECT role, COUNT(*) AS users_count
                FROM users
                GROUP BY role
            ) users_count ON users_count.role = role_tree.name
            ORDER BY role_tree.sort_path
            """
        )

    return [
        {
            "id": role["id"],
            "name": role["name"],
            "description": role["description"],
            "parent_id": role["parent_id"],
            "parent_name": role["parent_name"],
            "depth": role["depth"],
            "users_count": role["users_count"],
            "is_protected": get_role_lookup_name(role["name"]) in PROTECTED_ROLES,
        }
        for role in roles
    ]


async def create_role(
    current_user: mod.User,
    name: str,
    description: str | None = None,
    parent_id: int | None = None,
):
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")

    normalized_name = normalize_role_name(name)
    normalized_description = (description or "").strip() or None

    async with get_database_connection() as conn:
        await ensure_default_role_hierarchy(conn)
        await validate_role_parent(conn, None, parent_id)

        existing_role = await get_role_by_name(conn, normalized_name)
        if existing_role is not None:
            raise HTTPException(status_code=400, detail="Role already exists")

        created_role = await conn.fetchrow(
            """
            INSERT INTO role_hierarchy (name, description, parent_id)
            VALUES ($1, $2, $3)
            RETURNING id
            """,
            normalized_name,
            normalized_description,
            parent_id,
        )

    return created_role["id"]


async def update_role(
    current_user: mod.User,
    role_id: int,
    name: str,
    description: str | None = None,
    parent_id: int | None = None,
):
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")

    normalized_name = normalize_role_name(name)
    normalized_description = (description or "").strip() or None

    async with get_database_connection() as conn:
        await ensure_default_role_hierarchy(conn)

        existing_role = await get_role_by_id(conn, role_id)
        if existing_role is None:
            raise HTTPException(status_code=404, detail="Role not found")

        if get_role_lookup_name(existing_role["name"]) in PROTECTED_ROLES:
            if normalized_name != existing_role["name"]:
                raise HTTPException(
                    status_code=400,
                    detail="Protected roles cannot be renamed",
                )
            if parent_id != existing_role["parent_id"]:
                raise HTTPException(
                    status_code=400,
                    detail="Protected roles cannot change hierarchy",
                )

        duplicated_role = await conn.fetchrow(
            "SELECT id FROM role_hierarchy WHERE LOWER(name) = LOWER($1) AND id <> $2",
            normalized_name,
            role_id,
        )
        if duplicated_role is not None:
            raise HTTPException(status_code=400, detail="Role already exists")

        await validate_role_parent(conn, role_id, parent_id)

        await conn.execute(
            """
            UPDATE role_hierarchy
            SET name = $1, description = $2, parent_id = $3
            WHERE id = $4
            """,
            normalized_name,
            normalized_description,
            parent_id,
            role_id,
        )

        if normalized_name != existing_role["name"]:
            await conn.execute(
                "UPDATE users SET role = $1 WHERE role = $2",
                normalized_name,
                existing_role["name"],
            )

    return True


async def delete_role(current_user: mod.User, role_id: int):
    if not is_superadmin_role(current_user.role):
        raise HTTPException(status_code=400, detail="Permissions required")

    async with get_database_connection() as conn:
        await ensure_default_role_hierarchy(conn)

        existing_role = await get_role_by_id(conn, role_id)
        if existing_role is None:
            raise HTTPException(status_code=404, detail="Role not found")

        if get_role_lookup_name(existing_role["name"]) in PROTECTED_ROLES:
            raise HTTPException(status_code=400, detail="Protected roles cannot be deleted")

        assigned_users = await conn.fetchval(
            "SELECT COUNT(*) FROM users WHERE role = $1",
            existing_role["name"],
        )
        if assigned_users:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete a role assigned to existing users",
            )

        child_roles = await conn.fetchval(
            "SELECT COUNT(*) FROM role_hierarchy WHERE parent_id = $1",
            role_id,
        )
        if child_roles:
            raise HTTPException(
                status_code=400,
                detail="Cannot delete a role with child roles",
            )

        await conn.execute("DELETE FROM role_hierarchy WHERE id = $1", role_id)

    return True
