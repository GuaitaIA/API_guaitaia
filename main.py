from datetime import timedelta
from typing import Annotated
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from fastapi.middleware.cors import CORSMiddleware
from fastapi import Depends, FastAPI, HTTPException, File, UploadFile, Form, status
from PIL import Image

from dotenv import load_dotenv
import os

import funcs as fc 
import models as mod

# Cargar variables de entorno
load_dotenv() 

SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL")

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

tags_metadata = [
    {
        "name": "Authenticate",
        "description": "Authenticate users."
    },
    {
        "name": "User",
        "description": "Create and update users."
    },
    {
        "name": "Individual detection",
        "description": "Process images one by one."
    },
    {
        "name": "Multiple detection",
        "description": "Process multiple images at once."
    },
    {
        "name": "Results",
        "description": "Get the results of the detections."
    }
]

app = FastAPI(
    title="GuaitaIA",
    description="AI smoke plume detection in the forest",
    version="0.0.1 beta",
    openapi_tags=tags_metadata
)

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

#@app.get("/")
#async def root(
#    current_user: Annotated[mod.User, Depends(fc.get_current_active_user)]
#):
#    user = await fc.get_user_from_db("admin@admin.com")
#    return user

@app.post(
    "/token", 
    response_model=mod.Token,
    tags=["Authenticate"]
)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = await fc.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    access_token_expires = timedelta(weeks=fc.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = fc.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

app.mount("/imagenes", StaticFiles(directory="Resultados"), name="imagenes")
app.mount("/imagenes_original", StaticFiles(directory="Original"), name="imagenes")

@app.post("/user/create", tags=["User"])
async def create_user(
    current_user: Annotated[mod.User, Depends(fc.get_current_user_is_superadmin)],
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...)
):
    try:
        await fc.create_user(email, password, role)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al crear el usuario: {e}")

    return {
        status: 'success',
    }

@app.patch("/user/update/password", tags=["User"])
async def update_password(
    current_user: Annotated[mod.User, Depends(fc.get_current_active_user)],
    password: str = Form(...)
):
    try:
        await fc.update_password(current_user, password)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar la contraseña: {e}")

    return {
        "status": 'success',
    }

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
    current_user: Annotated[mod.User, Depends(fc.get_current_active_user)],
    imagen: UploadFile = File(...),
    confianza: float = Form(...),
    iou: float = Form(...),
    cpu: int = Form(...)
):
    if not fc.validar_extension(imagen.filename):
        raise HTTPException(status_code=400, detail="Formato de imagen no permitido")

    try:
        image = Image.open(imagen.file)
        detecciones, valor_confianza, nombre_resultado, original = fc.procesar_imagen(image, confianza, iou, cpu)
        if detecciones == True:
            await fc.insert_results(current_user, 'simple', 1, 0)
        else:
            await fc.insert_results(current_user, 'simple', 0, 1)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar la imagen: {e}")

    ahora = fc.datetime.now()
 
    return {
        "detecciones": detecciones,
        "confianza": valor_confianza,
        "imagen_procesada": nombre_resultado,
        "fecha": ahora.date().isoformat(),
        "hora": ahora.time().isoformat(),
        "GPU": cpu,
        "original": original,
    }

@app.post("/detectar_incendios_multiples/", tags=["Multiple detection"])
async def detectar_incendios_multiples(
    current_user: Annotated[mod.User, Depends(fc.get_current_active_user)],
    imagenes: fc.List[UploadFile] = File(...),
    confianza: float = Form(...),
    iou: float = Form(...),
    cpu: int = Form(...)
):
    for imagen in imagenes:
        if not fc.validar_extension(imagen.filename):
            raise HTTPException(status_code=400, detail="Formato de imagen no permitido")
    
    try:
        detecciones, valor_confianza, nombres_resultados = fc.procesar_imagen2(imagenes, confianza, iou, cpu)
        detections = detecciones.count(True)
        not_detections = detecciones.count(False)
        await fc.insert_results(current_user, 'multiples', detections, not_detections)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar las imágenes: {e}")

    ahora = fc.datetime.now()

    return {
        "detecciones": detecciones,
        "confianza": valor_confianza,
        "imagenes_procesadas": nombres_resultados,
        "fecha": ahora.date().isoformat(),
        "hora": ahora.time().isoformat(),
        "GPU": cpu,
    }

@app.get("/statistics/", tags=["Results"])
async def get_statistics(
    current_user: Annotated[mod.User, Depends(fc.get_current_active_user)],
    user: int | None = None,
):
    try:
        statistics = await fc.statistics(current_user, user)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener los resultados: {e}")

    return statistics[0]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)