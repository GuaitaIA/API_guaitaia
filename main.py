# Importaciones de librerías estándar de Python
from datetime import timedelta  # Para manejar diferencias de tiempo
import json  # Para manejar datos en formato JSON
import os  # Para interactuar con el sistema operativo

# Importaciones para tipado estático
# Para tipado estático avanzado y anotaciones
from typing import Annotated, List, Optional

# Importaciones de FastAPI para crear y configurar el servidor web
# Para la creación de la API y manejo de excepciones y dependencias
from fastapi import Depends, FastAPI, HTTPException, File, UploadFile, Form, status
# Para la autenticación OAuth2
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles  # Para servir archivos estáticos
# Para manejar Cross-Origin Resource Sharing (CORS)
from fastapi.middleware.cors import CORSMiddleware

# Importaciones para manejo de bases de datos con SQLAlchemy
# Para crear la conexión a la base de datos
from sqlalchemy import create_engine
# Para crear la clase base de los modelos de la base de datos
from sqlalchemy.ext.declarative import declarative_base
# Para crear una fábrica de sesiones de base de datos
from sqlalchemy.orm import sessionmaker

# Importaciones para manejo de variables de entorno
# Para cargar las variables de entorno del archivo .env
from dotenv import load_dotenv

# Importaciones de módulos locales o personalizados
import funcs as fc  # Módulo local de funciones (debe existir en el proyecto)
import models as mod  # Módulo local para modelos (debe existir en el proyecto)
import utils  # Módulo local de utilidades (debe existir en el proyecto)

# Carga de variables de entorno desde un archivo .env
load_dotenv()


# Obtener la URL de la base de datos de las variables de entorno.
SQLALCHEMY_DATABASE_URL = os.getenv("SQLALCHEMY_DATABASE_URL")

# Crear el motor de la base de datos SQLAlchemy con la URL de la base de datos.
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Crear una fábrica de sesiones de SQLAlchemy configurada para trabajar con el motor de la base de datos.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Crear una clase base para los modelos de la base de datos declarativos de SQLAlchemy.
Base = declarative_base()

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

# Inicializar la aplicación FastAPI con metadatos de la versión y las etiquetas para la documentación OpenAPI.
app = FastAPI(
    title="GuaitaIA",
    description="Detección de humo de incendios forestales mediante IA",
    version="0.0.1 beta",
    openapi_tags=tags_metadata
)

# Lista de orígenes permitidos en la política CORS.
origins = ["*"]

# Configuración del middleware CORS para permitir todas las conexiones entrantes.
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # Permite todas las fuentes
    allow_credentials=True,  # Permite cookies/autenticación basada en cabeceras
    allow_methods=["*"],    # Permite todos los métodos HTTP
    allow_headers=["*"],    # Permite todas las cabeceras
)

# @app.get("/")
# async def root(
#    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
# ):
#    user = await utils.get_user_from_db("admin@admin.com")
#    return user


@app.post(
    "/token",
    response_model=mod.Token,  # Especifica el modelo de respuesta que se espera devolver
    # Agrupa este endpoint en la documentación bajo 'Authenticate'
    tags=["Authenticate"]
)
async def login_for_access_token(
    # Depende del formulario OAuth2 estándar para la solicitud de token.
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
    access_token_expires = timedelta(weeks=utils.ACCESS_TOKEN_EXPIRE_MINUTES)

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


@app.post("/user/create", tags=["User"])
async def create_user(
    # Usuario actual autenticado como superadministrador.
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    # Dirección de correo electrónico para el nuevo usuario.
    email: str = Form(...),
    # Contraseña para el nuevo usuario.
    password: str = Form(...),
    # Rol para el nuevo usuario.
    role: str = Form(...)
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

    Returns:
    - Un diccionario indicando el estado de la operación.

    Raises:
    - HTTPException: Si ocurre un error al crear el usuario.
    """

    # Intentar crear un nuevo usuario utilizando una función de utilidad.
    try:
        await utils.create_user(email, password, role)
    except Exception as e:
        # Lanzar una excepción HTTP si ocurre un error durante la creación.
        raise HTTPException(
            status_code=400, detail=f"Error al crear el usuario: {e}")

    # Devolver una respuesta de éxito si la creación es exitosa.
    return {"status": 'success'}


@app.patch("/user/update/password", tags=["User"])
async def update_password(
    # Usuario actual autenticado mediante token OAuth2.
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    # Nueva contraseña proporcionada a través de un formulario.
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

    # Intentar actualizar la contraseña utilizando una función de utilidad.
    try:
        await utils.update_password(current_user, password)
    except Exception as e:
        # Lanzar una excepción HTTP si ocurre un error durante la actualización.
        raise HTTPException(
            status_code=500, detail=f"Error al actualizar la contraseña: {e}")

    # Devolver una respuesta de éxito si la actualización es exitosa.
    return {"status": 'success'}


@app.post("/detectar_incendios/", tags=["Wildfire detection"])
async def detectar_incendios_multiples(
    # Usuario actual autenticado mediante token OAuth2.
    current_user: Annotated[mod.User, Depends(utils.get_current_user_time)],
    # Lista opcional de imágenes subidas para la detección de incendios.
    imagenes: Optional[List[UploadFile]] = File(default=None),
    # Lista opcional de strings base64 de imágenes para la detección de incendios.
    imagenes_strings: Optional[List[str]] = Form(default=None),
    # Parámetro de confianza para el modelo de detección.
    confianza: float = Form(...),
    # Parámetro de intersección sobre unión (IoU) para el modelo de detección.
    iou: float = Form(...),
    # Parámetro para indicar el uso de CPU o GPU en el proceso de detección.
    cpu: int = Form(...)
):
    """
    Endpoint para la detección de incendios en múltiples imágenes.

    Acepta imágenes directamente, urls a imágenes o como strings codificados en base64.
    Requiere parámetros para la confianza, IoU y el uso de CPU o GPU.

    Args:
    - current_user: Usuario actual que ha pasado la autenticación.
    - imagenes: Lista de imágenes subidas (opcional).
    - imagenes_strings: Lista de strings base64 de imágenes (opcional).
    - confianza: Umbral de confianza para la detección.
    - iou: Umbral de IoU para la detección.
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
        raise HTTPException(
            status_code=500, detail=f"Error al procesar las imágenes: {e}")

    # Devolver el resultado del procesamiento como JSON.
    return json.loads(result)


@app.get("/statistics/", tags=["Results"])
async def get_statistics(
    # Usuario actual autenticado mediante token OAuth2.
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    # ID del usuario opcional para filtrar estadísticas; None por defecto.
    user: Optional[int] = None,
):
    """
    Endpoint para obtener estadísticas.

    Utiliza la autenticación OAuth2 para identificar al usuario actual y,
    opcionalmente, acepta un ID de usuario para obtener estadísticas específicas.

    Args:
    - current_user: Usuario actual que ha pasado la autenticación.
    - user: ID del usuario para el cual se obtendrán las estadísticas (opcional).

    Returns:
    - Un JSON con las estadísticas obtenidas.

    Raises:
    - HTTPException: Si hay un error al obtener las estadísticas.
    """

    try:
        # Obtener estadísticas usando la función de utilidad.
        statistics = await utils.statistics(current_user, user)
    except Exception as e:
        # Lanzar excepción HTTP con el error específico si falla la obtención de estadísticas.
        raise HTTPException(
            status_code=400, detail=f"Error al obtener los resultados: {e}")

    # Devolver el primer elemento de la lista de estadísticas.
    return statistics[0]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)
