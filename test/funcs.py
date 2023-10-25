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

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1
EXTENSIONES_PERMITIDAS = {"jpg", "jpeg", "png"}

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Cargar variables de entorno
load_dotenv() 

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
        user="postgres",
        password="postgres",
        database="guaitaia",
        host="localhost",
        port="5433"
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
    user = get_user_from_db(email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(
    current_user: Annotated[mod.User, Depends(get_current_user)]
):
    if current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def validar_extension(filename: str) -> bool:
    try:
        nombre, extension = filename.rsplit('.', 1)
        return extension.lower() in EXTENSIONES_PERMITIDAS
    except ValueError:
        return False