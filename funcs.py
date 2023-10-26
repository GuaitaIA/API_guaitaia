from ultralytics import YOLO
from dotenv import load_dotenv
import os
from PIL import Image
import tempfile
import shutil
from typing import List, Tuple, Any
from fastapi import UploadFile

import models as mod
import asyncpg
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext

from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import Annotated
from fastapi import Depends, HTTPException, status

# Cargar variables de entorno
load_dotenv() 

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
EXTENSIONES_PERMITIDAS = {"jpg", "jpeg", "png"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")



# Cargar el modelo YOLO
try:
    model = YOLO(os.getenv("MODELO"))
except Exception as e:
    raise Exception(f"Error al cargar el modelo: {e}")

def procesar_imagen(imagen: Image.Image, confianza: float, iou: float, cpu: int) -> tuple:
    try:
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as temp_file:
            imagen.save(temp_file.name)
            input_image = Image.open(temp_file.name)
            
            device = "cpu" if cpu == 1 else None
            
            results = model.predict(input_image, conf=confianza, iou=iou, save=True, project="./", name="Resultados", exist_ok=True, device=device, imgsz=(800,480))
            results = results[0].boxes.numpy()

        if results.conf.size > 0:
            conf = round(results.conf[0], 2)
            deteccion = True
            procesada = os.path.basename(temp_file.name)
        else:
            conf = 0
            deteccion = False
            procesada = os.path.basename(temp_file.name)

        return deteccion, float(conf), procesada  # Aquí devolvemos la ruta a la imagen procesada

    except Exception as e:
        raise Exception(f"Error al procesar la imagen: {e}")

    finally:
        if os.path.exists(temp_file.name):
            os.remove(temp_file.name)
            
def procesar_imagen2(imagenes: List[Any], confianza: float, iou: float, cpu: int) -> Tuple[List[bool], List[float], List[str]]:
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            processed_image_names = []
            for imagen in imagenes:
                image_path = os.path.join(temp_dir, imagen.filename)
                with open(image_path, "wb") as buffer:
                    shutil.copyfileobj(imagen.file, buffer)
                processed_image_names.append(os.path.basename(image_path))

            device = "cpu" if cpu == 1 else None

            # Procesar todas las imágenes en el directorio temporal de una vez
            results = model.predict(temp_dir, conf=confianza, iou=iou, save=True, project="./", name="Resultados", exist_ok=True, device=device)
            
            detecciones = []
            confs = []

            for res in results:
                boxes = res.boxes.numpy()
                if boxes.conf.size > 0:
                    conf = round(boxes.conf[0], 2)
                    deteccion = True
                else:
                    conf = 0
                    deteccion = False
                detecciones.append(deteccion)
                confs.append(float(conf))

            return detecciones, confs, processed_image_names

    except Exception as e:
        raise Exception(f"Error al procesar las imágenes: {e}")

async def get_database_connection():
    conn = await asyncpg.connect(
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_DATABASE"),
        host=os.getenv("DB_HOST"),
        port=os.getenv("DB_PORT")
    )
    return conn

async def get_user_from_db(email: str):
    conn = await get_database_connection()
    try:
        query = "SELECT * FROM users WHERE email = $1"
        user_record = await conn.fetchrow(query, email)
        if user_record:
            return mod.User(**user_record)
        return None
    finally:
        await conn.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def authenticate_user(email: str, password: str):
    user = await get_user_from_db(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]):
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

async def get_current_active_user(
    current_user: Annotated[mod.User, Depends(get_current_user)]
):
    if current_user.is_active is False:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_user_is_superadmin(
    current_user: Annotated[mod.User, Depends(get_current_user)]
):
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")
    return current_user

def validar_extension(filename: str) -> bool:
    try:
        nombre, extension = filename.rsplit('.', 1)
        return extension.lower() in EXTENSIONES_PERMITIDAS
    except ValueError:
        return False
    
async def insert_results(user: mod.User, type: str, detections: int, not_detections: int):
    print(detections)
    print(not_detections)
    dateTime = datetime.now()
    conn = await get_database_connection()
    try:
        query = "INSERT INTO results (user_id, date, type, detections, not_detections) VALUES ($1, $2, $3, $4, $5)"
        await conn.execute(query, user.id, dateTime, type, detections, not_detections)
    finally:
        await conn.close()
    return user.email