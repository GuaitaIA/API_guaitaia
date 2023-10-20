from datetime import datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, File, UploadFile, Form, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from datetime import datetime
from PIL import Image
from typing import List

import funcs as fc 

# to get a string like this run:
# openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1

# generate password online
# https://bcrypt.online/

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
    "vigilant": {
        "username": "vigilant",
        "full_name": "John Doe",
        "email": "vigilant@example.com",
        "hashed_password": "$2y$10$VoPY4X96VpCTVYDCEjbgxu2FK9jjMqgGnKWD14bA7cgpVgaU.QeNO",
        "disabled": False,
    }
}


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: str | None = None


class User(BaseModel):
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None


class UserInDB(User):
    hashed_password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

tags_metadata = [
    {
        "name": "Authenticate",
        "description": "Authenticate users."
    },
    {
        "name": "Individual detection",
        "description": "Process images one by one."
    },
    {
        "name": "Multiple detection",
        "description": "Process multiple images at once."
    }
]

app = FastAPI(
    title="GuaitaIA",
    description="AI smoke plume detection in the forest",
    version="0.0.1 beta",
    openapi_tags=tags_metadata
)

EXTENSIONES_PERMITIDAS = {"jpg", "jpeg", "png"}

def validar_extension(filename: str) -> bool:
    try:
        nombre, extension = filename.rsplit('.', 1)
        return extension.lower() in EXTENSIONES_PERMITIDAS
    except ValueError:
        return False

# Configuración de CORS
origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
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
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(
    current_user: Annotated[User, Depends(get_current_user)]
):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post(
    "/token", 
    response_model=Token,
    tags=["Authenticate"]
)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

"""
@app.get(
    "/users/me/", 
    response_model=User,
    tags=["Authenticate"]
)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    return current_user
"""

app.mount("/imagenes", StaticFiles(directory="Resultados"), name="imagenes")

@app.post(
    "/detectar_incendio/", 
    tags=["Individual detection"],
    responses={
        # 404: {"model": Message, "description": "The item was not found"},
        200: {
            "description": "Item requested by ID",
            "content": {
                "application/json": {
                    "example": {
                        "detecciones": True,
                        "confianza": 0.8399999737739563,
                        "imagen_procesada": "tmpyoaewshv.jpg",
                        "fecha": "2023-10-19",
                        "hora": "09:33:40.461835",
                        "GPU": 1
                    }
                }
            },
        },
    },
)
async def detectar_incendio(
    current_user: Annotated[User, Depends(get_current_active_user)],
    imagen: UploadFile = File(...),
    confianza: float = Form(...),
    iou: float = Form(...),
    cpu: int = Form(...)
):
    if not validar_extension(imagen.filename):
        raise HTTPException(status_code=400, detail="Formato de imagen no permitido")

    try:
        image = Image.open(imagen.file)
        detecciones, valor_confianza, nombre_resultado = fc.procesar_imagen(image, confianza, iou, cpu)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar la imagen: {e}")

    ahora = datetime.now()
 
    return {
        "detecciones": detecciones,
        "confianza": valor_confianza,
        "imagen_procesada": nombre_resultado,
        "fecha": ahora.date().isoformat(),
        "hora": ahora.time().isoformat(),
        "GPU": cpu,
    }

@app.post("/detectar_incendios_multiples/", tags=["Multiple detection"])
async def detectar_incendios_multiples(
    current_user: Annotated[User, Depends(get_current_active_user)],
    imagenes: List[UploadFile] = File(...),
    confianza: float = Form(...),
    iou: float = Form(...),
    cpu: int = Form(...)
):
    for imagen in imagenes:
        if not validar_extension(imagen.filename):
            raise HTTPException(status_code=400, detail="Formato de imagen no permitido")
    
    try:
        detecciones, valor_confianza, nombres_resultados = fc.procesar_imagen2(imagenes, confianza, iou, cpu)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar las imágenes: {e}")

    ahora = datetime.now()

    return {
        "detecciones": detecciones,
        "confianza": valor_confianza,
        "imagenes_procesadas": nombres_resultados,
        "fecha": ahora.date().isoformat(),
        "hora": ahora.time().isoformat(),
        "GPU": cpu,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)