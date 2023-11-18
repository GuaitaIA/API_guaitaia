from datetime import datetime, timedelta
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

# Carga de variables de entorno.
load_dotenv()

# Claves y algoritmos de seguridad para JWT.
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))

# Extensiones de archivo permitidas para la carga de imágenes.
EXTENSIONES_PERMITIDAS = {"jpg", "jpeg", "png", "webp"}

# Configuración del contexto de cifrado para contraseñas.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Esquema de autenticación OAuth2 para FastAPI.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


async def get_database_connection():
    """
    Establece una conexión asincrónica a la base de datos PostgreSQL.

    Las credenciales y detalles de la conexión se obtienen de las variables de entorno.
    Utiliza `asyncpg` para la conexión asincrónica.

    Returns:
        Una conexión asincrónica a la base de datos.
    """
    # Establece una conexión a la base de datos usando las credenciales de las variables de entorno.
    conn = await asyncpg.connect(
        user=os.getenv("DB_USER"),        # Usuario de la base de datos
        password=os.getenv("DB_PASSWORD"),  # Contraseña del usuario
        database=os.getenv("DB_DATABASE"),  # Nombre de la base de datos
        # Host del servidor de la base de datos
        host=os.getenv("DB_HOST"),
        # Puerto del servidor de la base de datos
        port=os.getenv("DB_PORT")
    )
    return conn


async def get_user_from_db(email: str):
    """
    Obtiene un registro de usuario de la base de datos por correo electrónico.

    Args:
    - email (str): El correo electrónico del usuario a buscar.

    Returns:
    - Una instancia del modelo User si se encuentra el registro, None en caso contrario.

    Esta función asume que existe una tabla 'users' en la base de datos.
    """
    # Obtener una conexión a la base de datos.
    conn = await get_database_connection()
    try:
        # Preparar la consulta SQL para obtener el registro del usuario.
        query = "SELECT * FROM users WHERE email = $1"
        # Ejecutar la consulta y obtener el registro del usuario.
        user_record = await conn.fetchrow(query, email)
        # Si se encuentra un registro, crear y devolver una instancia del modelo User.
        if user_record:
            return mod.User(**user_record)
        # Si no se encuentra un registro, devolver None.
        return None
    finally:
        # Cerrar la conexión a la base de datos.
        await conn.close()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica que una contraseña en texto plano coincida con su versión cifrada.

    Args:
    - plain_password (str): La contraseña en texto plano a verificar.
    - hashed_password (str): La contraseña cifrada con la que se compara.

    Returns:
    - bool: Verdadero si las contraseñas coinciden, Falso en caso contrario.
    """
    # Utiliza el contexto de cifrado para verificar la contraseña.
    return pwd_context.verify(plain_password, hashed_password)


async def authenticate_user(email: str, password: str):
    """
    Autentica a un usuario basándose en el correo electrónico y contraseña proporcionados.

    Args:
    - email (str): El correo electrónico del usuario.
    - password (str): La contraseña del usuario en texto plano.

    Returns:
    - User: La instancia del usuario si la autenticación es exitosa.
    - bool: False si la autenticación falla.

    La función primero busca el usuario en la base de datos por correo electrónico,
    luego verifica la contraseña proporcionada contra el hash almacenado.
    """
    # Obtener el registro de usuario de la base de datos por correo electrónico.
    user = await get_user_from_db(email)
    # Si no hay usuario con ese correo electrónico, retorna Falso.
    if not user:
        return False
    # Si la contraseña no coincide con la versión cifrada, retorna Falso.
    if not verify_password(password, user.hashed_password):
        return False
    # Si todo es correcto, retorna el registro de usuario.
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """
    Crea un token de acceso JWT para la autenticación de usuarios.

    Args:
    - data (dict): Un diccionario con los datos del payload del token.
    - expires_delta (timedelta, opcional): La duración antes de que el token expire.
        Si no se proporciona, se utilizará un valor por defecto de 15 minutos.

    Returns:
    - str: El token de acceso JWT codificado.
    """
    # Copia los datos para no modificar el original.
    to_encode = data.copy()
    # Si se proporciona 'expires_delta', calcular la fecha de expiración con este valor.
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    # Si no, establecer la expiración en 15 minutos desde el momento actual.
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    # Actualizar el diccionario con la fecha de expiración.
    to_encode.update({"exp": expire})
    # Codificar el JWT usando la clave secreta y el algoritmo especificado.
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> mod.User:
    """
    Obtiene el usuario actual a partir de un token JWT.

    Args:
    - token (str): El token JWT que contiene las credenciales del usuario.

    Returns:
    - User: La instancia del usuario si el token es válido.

    Raises:
    - HTTPException: Si el token no es válido o el usuario no existe en la base de datos.
    """
    # Excepción a utilizar si la autenticación falla.
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        # Decodificar el token JWT utilizando la clave secreta y el algoritmo.
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # Obtener el email del payload del token.
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        # Crear un objeto TokenData con el email.
        token_data = mod.TokenData(email=email)
    except JWTError:
        raise credentials_exception

    # Obtener el usuario de la base de datos utilizando el email.
    user = await get_user_from_db(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

# Funcion para validar si el usario puede ejectuar la api para detectar segun la hora de la solicitud.
async def get_current_user_time(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    """
    Verifica si el usuario actual puede ejecutar la API de detección.

    Args:
    - current_user (User): Instancia del usuario actual obtenida de la dependencia.

    Returns:
    - User: La instancia del usuario si puede ejecutar la API.

    Raises:
    - HTTPException: Si el usuario no puede ejecutar la API.
    """
    # consulta a la db ara recuperar la zona horaria del usuario
    conn = await get_database_connection()
    try:
        query = "SELECT * FROM zones WHERE id = $1"
        timezone = await conn.fetch(query, current_user.zones_id)
    finally:
        await conn.close()
    # Obtener la fecha y hora actual.
    dateTime = datetime.now()
    # Obtener la hora actual en la zona horaria del usuario.
    timezoneM = mod.Zones(**timezone[0])
    user_timezone = pytz.timezone(timezoneM.timezone)

    # Obtener la hora actual en la zona horaria del usuario.
    dateTime = dateTime.astimezone(user_timezone)
    # Obtener la hora actual en formato de 24 horas.
    hora = dateTime.strftime("%H")
    # Verificar si la hora actual está entre las 6:00 y las 18:00.
    if int(hora) < timezoneM.start_time or int(hora) >= timezoneM.end_time:
        # Si no está entre las 6:00 y las 18:00, lanza una excepción HTTP.
        raise HTTPException(status_code=400, detail="Not allowed at this time")
    # Si está entre las 6:00 y las 18:00, devuelve el usuario actual.
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

# Función para obtener el usuario activo actual.
async def get_current_active_user(
    current_user: Annotated[mod.User, Depends(get_current_user)]
) -> mod.User:
    """
    Verifica si el usuario actual está activo.

    Args:
    - current_user (User): Instancia del usuario actual obtenida de la dependencia.

    Returns:
    - User: La instancia del usuario si está activo.

    Raises:
    - HTTPException: Si el usuario está inactivo.
    """
    # Verificar si el usuario actual está marcado como activo.
    if current_user.is_active is False:
        # Si no está activo, lanza una excepción HTTP.
        raise HTTPException(status_code=400, detail="Inactive user")
    # Si está activo, devuelve el usuario actual.
    return current_user

# Función para verificar si el usuario actual es superadministrador.
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
    # Comprobar si el rol del usuario actual es 'superadmin'.
    if current_user.role != "superadmin":
        # Si no es superadministrador, lanza una excepción HTTP.
        raise HTTPException(status_code=400, detail="Permissions required")
    # Si es superadministrador, devuelve el usuario actual.
    return current_user


def validar_extension(filename: str) -> bool:
    """
    Valida la extensión de un archivo.

    Args:
    - filename (str): El nombre del archivo a validar.

    Returns:
    - bool: Verdadero si la extensión del archivo está en la lista de permitidas, falso si no.
    """
    try:
        # Separar el nombre del archivo y la extensión y verificar si esta última está permitida.
        nombre, extension = filename.rsplit('.', 1)
        return extension.lower() in EXTENSIONES_PERMITIDAS
    except ValueError:
        # Si no se encuentra un punto en el nombre del archivo, retorna falso.
        return False

# Función asíncrona para insertar resultados de detecciones en la base de datos.


async def insert_results(user: mod.User, type: str, detections: int, not_detections: int):
    """
    Inserta resultados de detecciones en la base de datos.

    Args:
    - user (User): El usuario asociado con los resultados.
    - type (str): El tipo de detección realizada.
    - detections (int): El número de detecciones positivas.
    - not_detections (int): El número de detecciones negativas.

    Returns:
    - str: El correo electrónico del usuario si la inserción es exitosa.
    """
    # Obtener la fecha y hora actual.
    dateTime = datetime.now()
    # Obtener una conexión a la base de datos.
    conn = await get_database_connection()
    try:
        # Preparar y ejecutar la consulta para insertar los resultados.
        query = "INSERT INTO results (user_id, date, type, detections, not_detections) VALUES ($1, $2, $3, $4, $5)"
        await conn.execute(query, user.id, dateTime, type, detections, not_detections)
    finally:
        # Cerrar la conexión de forma segura.
        await conn.close()
    # Retornar el email del usuario como confirmación.
    return user.email


async def insert_detection(user: mod.User, date: datetime, url_original: str, url_processed: str, confidence: float):
    """
    Inserta un registro de detección en la base de datos.

    Args:
    - user (User): El usuario que realiza la detección.
    - date (datetime): La fecha y hora de la detección.
    - url_original (str): La URL de la imagen original.
    - url_processed (str): La URL de la imagen procesada.
    - confidence (float): La confianza en la detección.

    Returns:
    - str: El correo electrónico del usuario si la inserción es exitosa.

    Raises:
    - Exception: Si ocurre un error al insertar en la base de datos.
    """
    conn = await get_database_connection()
    try:
        query = "INSERT INTO detections (user_id, date, url_original, url_processed, confidence) VALUES ($1, $2, $3, $4, $5)"
        await conn.execute(query, user.id, date, url_original, url_processed, confidence)
    except Exception as e:
        raise Exception(f"Error al insertar detección en base de datos: {e}")
    finally:
        await conn.close()
    return user.email


async def create_user(email: str, password: str, role: str):
    """
    Crea un nuevo usuario en la base de datos.

    Args:
    - email (str): El correo electrónico del nuevo usuario.
    - password (str): La contraseña del nuevo usuario.
    - role (str): El rol del nuevo usuario.

    Returns:
    - str: El correo electrónico del usuario si la creación es exitosa.

    Raises:
    - HTTPException: Si el correo electrónico ya está registrado.
    """
    hashed_password = pwd_context.hash(password)
    conn = await get_database_connection()
    user = await get_user_from_db(email)
    if user:
        raise HTTPException(status_code=400, detail="Email already registered")
    try:
        query = "INSERT INTO users (email, hashed_password, role, is_active) VALUES ($1, $2, $3, $4)"
        await conn.execute(query, email, hashed_password, role, True)
    finally:
        await conn.close()
    return email


async def update_password(user: mod.User, password: str):
    """
    Actualiza la contraseña de un usuario en la base de datos.

    Args:
    - user (User): El usuario al que se le actualizará la contraseña.
    - password (str): La nueva contraseña.

    Returns:
    - str: El correo electrónico del usuario si la actualización es exitosa.
    """
    hashed_password = pwd_context.hash(password)
    conn = await get_database_connection()
    try:
        query = "UPDATE users SET hashed_password = $1 WHERE id = $2"
        await conn.execute(query, hashed_password, user.id)
    finally:
        await conn.close()
    return user.email


async def statistics(current_user: mod.User, user_id: int | None = None, date: datetime | None = None):
    """
    Recupera estadísticas de detección de la base de datos.

    Para un 'superadmin', puede recuperar estadísticas de todos los usuarios o de un usuario específico.
    Para un usuario con rol 'user', solo puede recuperar sus propias estadísticas.

    Args:
    - current_user (User): El usuario que realiza la solicitud de estadísticas.
    - user_id (int, opcional): El ID del usuario cuyas estadísticas se quieren recuperar.

    Returns:
    - List: Una lista con las estadísticas de detecciones y no detecciones.

    Raises:
    - HTTPException: Si el usuario no tiene permisos para realizar la acción.
    """
    # Establecer conexión con la base de datos.
    conn = await get_database_connection()
    try:
        # Verificar si el usuario actual es un superadministrador.
        if current_user.role == "superadmin":
            # Si se proporciona un user_id, recuperar estadísticas de ese usuario.
            if user_id:
                query = "SELECT sum(not_detections) as not_detections, sum(detections) as detections, SUM(not_detections) + SUM(detections) as total_sum FROM results WHERE user_id = $1"
                results = await conn.fetch(query)
            # De lo contrario, recuperar estadísticas generales de todos los usuarios.
            else:
                query = "SELECT sum(not_detections) as not_detections, sum(detections) as detections, SUM(not_detections) + SUM(detections) as total_sum FROM results"
                results = await conn.fetch(query)

                if date is None:
                    date = datetime.now().date()
                else:
                    date = datetime.strptime(date, '%Y-%m-%d').date()

                query2 = "SELECT DATE_TRUNC('hour', date) AS hour, SUM(detections) AS total_detections, SUM(not_detections) AS total_not_detections FROM results WHERE DATE(date) = $1 GROUP BY DATE_TRUNC('hour', date) ORDER BY DATE_TRUNC('hour', date);"
                results2 = await conn.fetch(query2, date)
        # Verificar si el usuario actual tiene rol de 'user'.
        elif current_user.role == "user":
            # Si se proporciona un user_id, lanzar una excepción, ya que no debería acceder a estadísticas de otros usuarios.
            if user_id:
                raise HTTPException(
                    status_code=400, detail="Permissions required")
            # Recuperar estadísticas solo del usuario actual.
            else:
                query = "SELECT sum(not_detections) as not_detections, sum(detections) as detections FROM results WHERE user_id = $1"
                results = await conn.fetch(query, current_user.id)
        # Si el usuario no tiene un rol válido, lanzar una excepción.
        else:
            raise HTTPException(status_code=400, detail="Permissions required")
        # Devolver las estadísticas obtenidas.
        return results, results2
    finally:
        # Cerrar la conexión con la base de datos.
        await conn.close()

async def get_results_dates(current_user: mod.User):
    conn = await get_database_connection()
    try:
        if current_user.role == "superadmin":
            query = "SELECT DATE(date) AS date FROM detections GROUP BY DATE(date) ORDER BY DATE(date) DESC"
            results = await conn.fetch(query)
            print(results)
        elif current_user.role == "user":
            query = "SELECT DISTINCT date FROM results WHERE user_id = $1 ORDER BY date DESC"
            results = await conn.fetch(query, current_user.id)
        return results
    finally:
        await conn.close()

async def get_results_images_date(current_user: mod.User, date: datetime | None = None):
    conn = await get_database_connection()
    try:
        if current_user.role == "superadmin":
            date = datetime.strptime(date, '%Y-%m-%d').date()
            query = "SELECT id, url_processed, positive FROM detections WHERE DATE(date) = $1 ORDER BY id DESC"
            results = await conn.fetch(query, date)
        elif current_user.role == "user":
            date = datetime.strptime(date, '%Y-%m-%d').date()
            query = "SELECT url_original, url_processed, date FROM detections WHERE user_id = $1 AND DATE(date) = $2 ORDER BY id DESC"
            results = await conn.fetch(query, current_user.id, date)
        return results
    finally:
        await conn.close()

def es_extension_permitida(url):
    """
    Verifica si la extensión de archivo en una URL está en la lista de extensiones permitidas.

    Args:
    - url (str): La URL de la que se verificará la extensión.

    Returns:
    - bool: True si la extensión de archivo está en la lista de extensiones permitidas, False en caso contrario.

    Raises:
    - None

    Example:
    >>> es_extension_permitida("http://example.com/file.jpg")
    True
    """

    try:
        # Parsear la URL para obtener el componente de path
        path = urlparse(url).path

        # Obtener la extensión del archivo de la URL y eliminar el punto
        ext = os.path.splitext(path)[1].lstrip('.')

        # Verificar si la extensión (sin el punto) está en la lista de extensiones permitidas
        return ext in EXTENSIONES_PERMITIDAS
    except Exception as e:
        print(f"Error al verificar la extensión permitida: {e}")
        return False

async def update_results_images_status(current_user: mod.User, id: int, positive: bool):
    conn = await get_database_connection()
    try:
        if current_user.role == "superadmin":
            query = "UPDATE detections SET positive = $1 WHERE id = $2"
            await conn.execute(query, positive, id)
            return True
        elif current_user.role == "user":
            raise HTTPException(status_code=400, detail="Permissions required")
    finally:
        await conn.close()