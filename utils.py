from datetime import datetime, timedelta, timezone
from jose import JWTError, jwt
from typing import Annotated
from fastapi import Depends, HTTPException, status
import models as mod
import asyncpg
from dotenv import load_dotenv
import os
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from urllib.parse import urlparse
import pytz
import logging

logger = logging.getLogger(__name__)

# Carga de variables de entorno.
load_dotenv()

# Claves y algoritmos de seguridad para JWT.
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

# Extensiones de archivo permitidas para la carga de imagenes.
EXTENSIONES_PERMITIDAS = {"jpg", "jpeg", "png", "webp"}

# Configuracion del contexto de cifrado para contrasenas.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema de autenticacion OAuth2 para FastAPI.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Credenciales de la base de datos desde variables de entorno.
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_DATABASE = os.getenv("DB_DATABASE")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# Pool de conexiones global.
_db_pool = None


async def init_db_pool():
    """
    Inicializa el pool de conexiones a la base de datos.
    """
    global _db_pool
    _db_pool = await asyncpg.create_pool(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_DATABASE,
        host=DB_HOST,
        port=DB_PORT,
        min_size=2,
        max_size=10
    )


async def close_db_pool():
    """
    Cierra el pool de conexiones a la base de datos.
    """
    global _db_pool
    if _db_pool:
        await _db_pool.close()
        _db_pool = None


async def get_database_connection():
    """
    Obtiene una conexion a la base de datos.

    Si el pool esta inicializado, adquiere una conexion del pool.
    Si no, crea una conexion directa como fallback.

    Returns:
        Una conexion asincronica a la base de datos.
    """
    if _db_pool:
        return await _db_pool.acquire()
    return await asyncpg.connect(
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_DATABASE,
        host=DB_HOST,
        port=DB_PORT
    )


async def get_user_from_db(email: str):
    """
    Obtiene un registro de usuario de la base de datos por correo electronico.

    Args:
    - email (str): El correo electronico del usuario a buscar.

    Returns:
    - Una instancia del modelo User si se encuentra el registro, None en caso contrario.
    """
    async with _db_pool.acquire() as conn:
        query = "SELECT * FROM users WHERE email = $1"
        user_record = await conn.fetchrow(query, email)
        if user_record:
            return mod.User(**user_record)
        return None


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica que una contrasena en texto plano coincida con su version cifrada.

    Args:
    - plain_password (str): La contrasena en texto plano a verificar.
    - hashed_password (str): La contrasena cifrada con la que se compara.

    Returns:
    - bool: Verdadero si las contrasenas coinciden, Falso en caso contrario.
    """
    return pwd_context.verify(plain_password, hashed_password)


async def authenticate_user(email: str, password: str):
    """
    Autentica a un usuario basandose en el correo electronico y contrasena proporcionados.

    Args:
    - email (str): El correo electronico del usuario.
    - password (str): La contrasena del usuario en texto plano.

    Returns:
    - User: La instancia del usuario si la autenticacion es exitosa.
    - bool: False si la autenticacion falla.
    """
    user = await get_user_from_db(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Crea un token de acceso JWT para la autenticacion de usuarios.

    Args:
    - data (dict): Un diccionario con los datos del payload del token.
    - expires_delta (timedelta, opcional): La duracion antes de que el token expire.

    Returns:
    - str: El token de acceso JWT codificado.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> mod.User:
    """
    Obtiene el usuario actual a partir de un token JWT.

    Args:
    - token (str): El token JWT que contiene las credenciales del usuario.

    Returns:
    - User: La instancia del usuario si el token es valido.

    Raises:
    - HTTPException: Si el token no es valido o el usuario no existe en la base de datos.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = mod.TokenData(email=email)
    except JWTError:
        raise credentials_exception

    user = await get_user_from_db(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Funcion para validar si el usario puede ejectuar la api para detectar segun la hora de la solicitud.
async def get_current_user_time(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    """
    Verifica si el usuario actual puede ejecutar la API de deteccion.

    Args:
    - current_user (User): Instancia del usuario actual obtenida de la dependencia.

    Returns:
    - User: La instancia del usuario si puede ejecutar la API.

    Raises:
    - HTTPException: Si el usuario no puede ejecutar la API.
    """
    if current_user.zones_id is None:
        raise HTTPException(status_code=403, detail="Usuario sin zona horaria asignada")

    async with _db_pool.acquire() as conn:
        query = "SELECT * FROM zones WHERE id = $1"
        tz_records = await conn.fetch(query, current_user.zones_id)

    dateTime = datetime.now()
    timezoneM = mod.Zones(**tz_records[0])
    user_timezone = pytz.timezone(timezoneM.timezone)

    dateTime = dateTime.astimezone(user_timezone)
    hora = dateTime.strftime("%H")
    if int(hora) < timezoneM.start_time or int(hora) >= timezoneM.end_time:
        raise HTTPException(status_code=400, detail="Not allowed at this time")
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Funcion para obtener el usuario activo actual.
async def get_current_active_user(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    """
    Verifica si el usuario actual esta activo.

    Args:
    - current_user (User): Instancia del usuario actual obtenida de la dependencia.

    Returns:
    - User: La instancia del usuario si esta activo.

    Raises:
    - HTTPException: Si el usuario esta inactivo.
    """
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Funcion para verificar si el usuario actual es superadministrador.
async def get_current_user_is_superadmin(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    """
    Verifica si el usuario actual es un superadministrador.

    Args:
    - current_user (User): Instancia del usuario actual obtenida de la dependencia.

    Returns:
    - User: La instancia del usuario si tiene el rol de superadministrador.

    Raises:
    - HTTPException: Si el usuario no tiene permisos de superadministrador.
    """
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")
    return current_user


def validar_extension(filename: str) -> bool:
    """
    Valida la extension de un archivo.

    Args:
    - filename (str): El nombre del archivo a validar.

    Returns:
    - bool: Verdadero si la extension del archivo esta en la lista de permitidas, falso si no.
    """
    try:
        nombre, extension = filename.rsplit('.', 1)
        return extension.lower() in EXTENSIONES_PERMITIDAS
    except ValueError:
        return False


async def insert_results(user: mod.User, type: str, detections: int, not_detections: int):
    """
    Inserta resultados de detecciones en la base de datos.

    Args:
    - user (User): El usuario asociado con los resultados.
    - type (str): El tipo de deteccion realizada.
    - detections (int): El numero de detecciones positivas.
    - not_detections (int): El numero de detecciones negativas.

    Returns:
    - str: El correo electronico del usuario si la insercion es exitosa.
    """
    dateTime = datetime.now()
    async with _db_pool.acquire() as conn:
        query = "INSERT INTO results (user_id, date, type, detections, not_detections) VALUES ($1, $2, $3, $4, $5)"
        await conn.execute(query, user.id, dateTime, type, detections, not_detections)
    return user.email


async def insert_detection(user: mod.User, date: datetime, url_original: str, url_processed: str, confidence: float):
    """
    Inserta un registro de deteccion en la base de datos.

    Args:
    - user (User): El usuario que realiza la deteccion.
    - date (datetime): La fecha y hora de la deteccion.
    - url_original (str): La URL de la imagen original.
    - url_processed (str): La URL de la imagen procesada.
    - confidence (float): La confianza en la deteccion.

    Returns:
    - str: El correo electronico del usuario si la insercion es exitosa.

    Raises:
    - Exception: Si ocurre un error al insertar en la base de datos.
    """
    async with _db_pool.acquire() as conn:
        try:
            query = "INSERT INTO detections (user_id, date, url_original, url_processed, confidence) VALUES ($1, $2, $3, $4, $5)"
            await conn.execute(query, user.id, date, url_original, url_processed, confidence)
        except Exception as e:
            raise Exception(f"Error al insertar deteccion en base de datos: {e}")
    return user.email


async def create_user(email: str, password: str, role: str, zones_id: int):
    """
    Crea un nuevo usuario en la base de datos.

    Args:
    - email (str): El correo electronico del nuevo usuario.
    - password (str): La contrasena del nuevo usuario.
    - role (str): El rol del nuevo usuario.
    - zones_id (int): El ID de la zona horaria del nuevo usuario.

    Returns:
    - str: El correo electronico del usuario si la creacion es exitosa.

    Raises:
    - HTTPException: Si el correo electronico ya esta registrado.
    """
    hashed_password = pwd_context.hash(password)
    async with _db_pool.acquire() as conn:
        user_record = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        if user_record:
            raise HTTPException(status_code=400, detail="Email already registered")
        query = "INSERT INTO users (email, hashed_password, role, is_active, zones_id) VALUES ($1, $2, $3, $4, $5)"
        await conn.execute(query, email, hashed_password, role, True, zones_id)
    return email


async def update_password(user: mod.User, password: str):
    """
    Actualiza la contrasena de un usuario en la base de datos.

    Args:
    - user (User): El usuario al que se le actualizara la contrasena.
    - password (str): La nueva contrasena.

    Returns:
    - str: El correo electronico del usuario si la actualizacion es exitosa.
    """
    hashed_password = pwd_context.hash(password)
    async with _db_pool.acquire() as conn:
        query = "UPDATE users SET hashed_password = $1 WHERE id = $2"
        await conn.execute(query, hashed_password, user.id)
    return user.email


async def statistics(current_user: mod.User, user_id: int | None = None, date: datetime | None = None):
    """
    Recupera estadisticas de deteccion de la base de datos.

    Para un 'superadmin', puede recuperar estadisticas de todos los usuarios o de un usuario especifico.
    Para un usuario con rol 'user', solo puede recuperar sus propias estadisticas.

    Args:
    - current_user (User): El usuario que realiza la solicitud de estadisticas.
    - user_id (int, opcional): El ID del usuario cuyas estadisticas se quieren recuperar.
    - date (datetime, opcional): La fecha para filtrar estadisticas.

    Returns:
    - Tuple: Una tupla con las estadisticas de detecciones y no detecciones.

    Raises:
    - HTTPException: Si el usuario no tiene permisos para realizar la accion.
    """
    results2 = []
    result3 = []

    async with _db_pool.acquire() as conn:
        if current_user.role == "superadmin":
            if user_id:
                query = "SELECT sum(not_detections) as not_detections, sum(detections) as detections, SUM(not_detections) + SUM(detections) as total_sum FROM results WHERE user_id = $1"
                results = await conn.fetch(query, user_id)
            else:
                query = "SELECT sum(not_detections) as not_detections, sum(detections) as detections, SUM(not_detections) + SUM(detections) as total_sum FROM results"
                results = await conn.fetch(query)

                query3 = "SELECT SUM(CASE WHEN positive = 'true' THEN 1 ELSE 0 END) AS true_detections, SUM(CASE WHEN positive = 'false' THEN 1 ELSE 0 END) AS false_detections FROM detections;"
                result3 = await conn.fetch(query3)
                if date is None:
                    date = datetime.now().date()
                else:
                    date = datetime.strptime(date, '%Y-%m-%d').date()

                query2 = "SELECT DATE_TRUNC('hour', date) AS hour, SUM(detections) AS total_detections, SUM(not_detections) AS total_not_detections FROM results WHERE DATE(date) = $1 GROUP BY DATE_TRUNC('hour', date) ORDER BY DATE_TRUNC('hour', date);"
                results2 = await conn.fetch(query2, date)
        elif current_user.role == "user":
            if user_id:
                raise HTTPException(
                    status_code=400, detail="Permissions required")
            else:
                query = "SELECT sum(not_detections) as not_detections, sum(detections) as detections FROM results WHERE user_id = $1"
                results = await conn.fetch(query, current_user.id)
        else:
            raise HTTPException(status_code=400, detail="Permissions required")
        return results, results2, result3

async def get_results_dates(current_user: mod.User):
    async with _db_pool.acquire() as conn:
        if current_user.role == "superadmin":
            query = "SELECT DATE(date) AS date FROM detections GROUP BY DATE(date) ORDER BY DATE(date) DESC"
            results = await conn.fetch(query)
            logger.info(results)
        elif current_user.role == "user":
            query = "SELECT DISTINCT date FROM results WHERE user_id = $1 ORDER BY date DESC"
            results = await conn.fetch(query, current_user.id)
        else:
            raise HTTPException(status_code=403, detail="Rol no autorizado")
        return results

async def get_results_images_date(current_user: mod.User, date: datetime | None = None):
    async with _db_pool.acquire() as conn:
        if current_user.role == "superadmin":
            date = datetime.strptime(date, '%Y-%m-%d').date()
            query = "SELECT id, url_processed, positive FROM detections WHERE DATE(date) = $1 ORDER BY id DESC"
            results = await conn.fetch(query, date)
        elif current_user.role == "user":
            date = datetime.strptime(date, '%Y-%m-%d').date()
            query = "SELECT url_original, url_processed, date FROM detections WHERE user_id = $1 AND DATE(date) = $2 ORDER BY id DESC"
            results = await conn.fetch(query, current_user.id, date)
        else:
            raise HTTPException(status_code=403, detail="Rol no autorizado")
        return results

def es_extension_permitida(url):
    """
    Verifica si la extension de archivo en una URL esta en la lista de extensiones permitidas.

    Args:
    - url (str): La URL de la que se verificara la extension.

    Returns:
    - bool: True si la extension de archivo esta en la lista de extensiones permitidas, False en caso contrario.
    """

    try:
        path = urlparse(url).path
        ext = os.path.splitext(path)[1].lstrip('.')
        return ext in EXTENSIONES_PERMITIDAS
    except Exception as e:
        logger.error(f"Error al verificar la extension permitida: {e}")
        return False

async def update_results_images_status(current_user: mod.User, id: int, positive: str):
    async with _db_pool.acquire() as conn:
        if current_user.role == "superadmin":
            query = "UPDATE detections SET positive = $1 WHERE id = $2"
            await conn.execute(query, positive, id)
            return True
        elif current_user.role == "user":
            raise HTTPException(status_code=400, detail="Permissions required")
        else:
            raise HTTPException(status_code=403, detail="Rol no autorizado")

# get users
async def get_users(current_user: mod.User):
    async with _db_pool.acquire() as conn:
        if current_user.role == "superadmin":
            query = "SELECT users.id, users.email, users.role, users.is_active, zones.timezone FROM users JOIN zones ON users.zones_id = zones.id"
            results = await conn.fetch(query)
        elif current_user.role == "user":
            raise HTTPException(status_code=400, detail="Permissions required")
        else:
            raise HTTPException(status_code=403, detail="Rol no autorizado")
        return results

# delete user
async def delete_user(current_user: mod.User, id: int):
    async with _db_pool.acquire() as conn:
        if current_user.role == "superadmin":
            query = "DELETE FROM users WHERE id = $1"
            await conn.execute(query, id)
            return True
        elif current_user.role == "user":
            raise HTTPException(status_code=400, detail="Permissions required")
        else:
            raise HTTPException(status_code=403, detail="Rol no autorizado")
