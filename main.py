# Importaciones de librerías estándar de Python
from contextlib import asynccontextmanager
from datetime import timedelta
import logging
import os

# Importaciones para tipado estático
from typing import Annotated, List, Optional

# Importaciones de FastAPI para crear y configurar el servidor web
from fastapi import Depends, FastAPI, HTTPException, File, UploadFile, Form, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

# Importaciones para manejo de variables de entorno
from dotenv import load_dotenv

# Importaciones de módulos locales
import funcs as fc
import models as mod
import utils

# Carga de variables de entorno desde un archivo .env
load_dotenv()

# Configuración de logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# CORS configurable desde variable de entorno
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")

# Metadatos para etiquetas utilizadas en la documentación de la API OpenAPI.
tags_metadata = [
    {
        "name": "Authenticate",
        "description": "Operaciones de autenticación para los usuarios."
    },
    {
        "name": "User",
        "description": "Operaciones para crear y actualizar usuarios."
    },
    {
        "name": "Wildfire detection",
        "description": "Procesar imágenes y vectores en formato base64 para la detección de incendios."
    },
    {
        "name": "Results",
        "description": "Obtener los resultados de las detecciones de incendios."
    }
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await utils.init_db_pool()
    yield
    await utils.close_db_pool()


# Inicializar la aplicación FastAPI con lifespan y metadatos.
app = FastAPI(
    lifespan=lifespan,
    title="GuaitaIA",
    description="Detección de humo de incendios forestales mediante IA",
    version="0.0.1 beta",
    openapi_tags=tags_metadata
)

# Configuración del middleware CORS.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False if ALLOWED_ORIGINS == ["*"] else True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post(
    "/token",
    response_model=mod.Token,
    tags=["Authenticate"]
)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    Endpoint que emite un token de acceso para la autenticación de usuarios.

    Args:
    - form_data: Datos del formulario que incluyen el nombre de usuario y la contraseña.

    Returns:
    - Un objeto JSON con el token de acceso y el tipo de token.

    Raises:
    - HTTPException: Si el usuario no existe, si la contraseña es incorrecta,
                     o si el usuario está inactivo.
    """

    # Autenticar al usuario y devolver un objeto de usuario si es exitoso.
    user = await utils.authenticate_user(form_data.username, form_data.password)
    # Si el usuario no se encuentra o la contraseña es incorrecta, lanza una excepción.
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Si el usuario está marcado como inactivo, también lanza una excepción.
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Define el tiempo de expiración del token de acceso.
    access_token_expires = timedelta(minutes=utils.ACCESS_TOKEN_EXPIRE_MINUTES)

    # Crea un token de acceso utilizando los datos del usuario y el tiempo de expiración.
    access_token = utils.create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )

    # Devuelve el token de acceso y el tipo de token en un objeto JSON.
    return {"access_token": access_token, "token_type": "bearer"}


# Montar un directorio estático para servir imágenes resultantes de operaciones.
app.mount("/imagenes", StaticFiles(directory="Resultados"),
          name="imagenes_resultados")

# Montar un directorio estático para servir imágenes originales.
app.mount("/imagenes_original", StaticFiles(directory="Original"),
          name="imagenes_originales")


@app.get("/users", tags=["User"])
async def get_users(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
):
    """
    Endpoint para obtener todos los usuarios.

    Requiere la autenticación del usuario actual.

    Args:
    - current_user: Usuario actual que ha pasado la autenticación.

    Returns:
    - Un JSON con todos los usuarios.

    Raises:
    - HTTPException: Si hay un error al obtener los usuarios.
    """

    try:
        users = await utils.get_users(current_user)
    except Exception as e:
        logger.exception("Error al obtener los usuarios")
        raise HTTPException(
            status_code=400, detail="Error al obtener los usuarios")

    return users

@app.post("/user/create", tags=["User"])
async def create_user(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    zones_id: int = Form(...),
):
    """
    Endpoint para crear un nuevo usuario.

    Solo puede ser utilizado por superadministradores. Requiere correo electrónico,
    contraseña y rol para el nuevo usuario.

    Args:
    - current_user: Usuario actual, debe ser superadministrador.
    - email: Dirección de correo electrónico del nuevo usuario.
    - password: Contraseña del nuevo usuario.
    - role: Rol del nuevo usuario.
    - zones_id: Zona del nuevo usuario.

    Returns:
    - Un diccionario indicando el estado de la operación.

    Raises:
    - HTTPException: Si ocurre un error al crear el usuario.
    """

    try:
        await utils.create_user(email, password, role, zones_id)
    except Exception as e:
        logger.exception("Error al crear el usuario")
        raise HTTPException(
            status_code=400, detail="Error al crear el usuario")

    return {"status": 'success'}


@app.delete("/user/{user_id}", tags=["User"])
async def delete_user(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    user_id: int
):
    """
    Endpoint para eliminar un usuario.

    Solo puede ser utilizado por superadministradores. Requiere el ID del usuario a eliminar.

    Args:
    - current_user: Usuario actual, debe ser superadministrador.
    - user_id: ID del usuario a eliminar.

    Returns:
    - Un diccionario indicando el estado de la operación.

    Raises:
    - HTTPException: Si ocurre un error al eliminar el usuario.
    """

    try:
        await utils.delete_user(current_user, user_id)
    except Exception as e:
        logger.exception("Error al eliminar el usuario")
        raise HTTPException(
            status_code=400, detail="Error al eliminar el usuario")

    return {"status": 'success'}


@app.patch("/user/update/password", tags=["User"])
async def update_password(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    password: str = Form(...)
):
    """
    Endpoint para actualizar la contraseña del usuario.

    Requiere la autenticación del usuario actual y una nueva contraseña.

    Args:
    - current_user: Usuario actual que ha pasado la autenticación.
    - password: Nueva contraseña para el usuario.

    Returns:
    - Un diccionario con el estado de la operación.

    Raises:
    - HTTPException: Si hay un error al actualizar la contraseña.
    """

    try:
        await utils.update_password(current_user, password)
    except Exception as e:
        logger.exception("Error al actualizar la contraseña")
        raise HTTPException(
            status_code=500, detail="Error al actualizar la contraseña")

    return {"status": 'success'}


@app.post("/detectar_incendios/", tags=["Wildfire detection"])
async def detectar_incendios_multiples(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_time)],
    imagenes: Optional[List[UploadFile]] = File(default=None),
    imagenes_strings: Optional[List[str]] = Form(default=None),
    confianza: float = Form(default=0.5, ge=0.0, le=1.0),
    iou: float = Form(default=0.5, ge=0.0, le=1.0),
    cpu: int = Form(default=1, ge=0, le=1)
):
    """
    Endpoint para la detección de incendios en múltiples imágenes.

    Acepta imágenes directamente, urls a imágenes o como strings codificados en base64.
    Requiere parámetros para la confianza, IoU y el uso de CPU o GPU.

    Args:
    - current_user: Usuario actual que ha pasado la autenticación.
    - imagenes: Lista de imágenes subidas (opcional).
    - imagenes_strings: Lista de strings base64 de imágenes (opcional).
    - confianza: Umbral de confianza para la detección (0.0 a 1.0).
    - iou: Umbral de IoU para la detección (0.0 a 1.0).
    - cpu: 1 para procesar utilizando CPU o 0 para utilizar GPU.

    Returns:
    - Un JSON con los resultados de la detección.

    Raises:
    - HTTPException: Si no se proporcionan imágenes o si hay un error al procesarlas.
    """

    # Verificar que se haya proporcionado al menos un conjunto de imágenes.
    if not imagenes and not imagenes_strings:
        raise HTTPException(
            status_code=400, detail="Debe proporcionar al menos un conjunto de imágenes o strings.")

    # Asegurarse de que no haya campos de imagen vacíos.
    if imagenes and all(imagen.filename == "" for imagen in imagenes):
        imagenes = None

    # Evitar la recepción de imágenes y strings simultáneamente.
    if imagenes and imagenes_strings:
        raise HTTPException(
            status_code=400, detail="Proporcione solo imágenes o solo strings, no ambos.")

    if imagenes_strings:
        imagenes_strings = imagenes_strings[0].split(',')

    # Elegir el conjunto de entrada para procesar.
    input_para_procesar = imagenes if imagenes else imagenes_strings

    # Procesar las imágenes y manejar posibles excepciones.
    try:
        result = await fc.procesar_imagen_multiple(input_para_procesar, confianza, iou, cpu, current_user)
    except Exception as e:
        logger.exception("Error al procesar las imágenes")
        raise HTTPException(
            status_code=500, detail="Error al procesar las imágenes")

    # Devolver el resultado del procesamiento directamente.
    return result


@app.get("/statistics/", tags=["Results"])
async def get_statistics(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    user: Optional[int] = None,
    date: Optional[str] = None
):
    """
    Endpoint para obtener estadísticas.

    Utiliza la autenticación OAuth2 para identificar al usuario actual y,
    opcionalmente, acepta un ID de usuario para obtener estadísticas específicas.

    Args:
    - current_user: Usuario actual que ha pasado la autenticación.
    - user: ID del usuario para el cual se obtendrán las estadísticas (opcional).
    - date: Fecha para filtrar estadísticas (opcional).

    Returns:
    - Un JSON con las estadísticas obtenidas.

    Raises:
    - HTTPException: Si hay un error al obtener las estadísticas.
    """

    try:
        statistics, statics2, statics3 = await utils.statistics(current_user, user, date)
    except Exception as e:
        logger.exception("Error al obtener los resultados")
        raise HTTPException(
            status_code=400, detail="Error al obtener los resultados")

    return statistics, statics2, statics3

@app.get("/results/dates", tags=["Results"])
async def get_results_dates(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
):
    """
    Endpoint para obtener las fechas en las que hay resultados.

    Returns:
    - Un JSON con las fechas en las que hay resultados.
    """

    try:
        dates = await utils.get_results_dates(current_user)
    except Exception as e:
        logger.exception("Error al obtener las fechas")
        raise HTTPException(
            status_code=400, detail="Error al obtener las fechas")

    return dates

@app.get("/results/images", tags=["Results"])
async def get_results_images_date(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    date: Optional[str] = None
):
    """
    Endpoint para obtener las imágenes de una fecha.

    Returns:
    - Un JSON con las imágenes de una fecha.
    """

    try:
        images = await utils.get_results_images_date(current_user, date)
    except Exception as e:
        logger.exception("Error al obtener las imágenes")
        raise HTTPException(
            status_code=400, detail="Error al obtener las imágenes")

    return images

@app.put("/results/images/status", tags=["Results"])
async def update_results_images_status(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    id: Optional[int] = None,
    positive: Optional[str] = Form(None)
):
    """
    Endpoint para actualizar el estado de una imagen.

    Returns:
    - Un JSON con el resultado de la actualización.
    """
    try:
        result = await utils.update_results_images_status(current_user, id, positive)
    except Exception as e:
        logger.exception("Error al actualizar el estado de la imagen")
        raise HTTPException(
            status_code=400, detail="Error al actualizar el estado de la imagen")

    return result

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
