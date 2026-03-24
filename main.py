import os
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Annotated, List, Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles

import funcs as fc
import models as mod
import utils

load_dotenv()

Base = mod.Base

ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
    if origin.strip()
]
if not ALLOWED_ORIGINS:
    ALLOWED_ORIGINS = ["*"]

tags_metadata = [
    {
        "name": "Authenticate",
        "description": "Operaciones de autenticacion para los usuarios.",
    },
    {
        "name": "User",
        "description": "Operaciones para crear y actualizar usuarios.",
    },
    {
        "name": "Roles",
        "description": "Gestion de la jerarquia de roles del sistema.",
    },
    {
        "name": "Settings",
        "description": "Ajustes personales del usuario autenticado.",
    },
    {
        "name": "Wildfire detection",
        "description": "Procesar imagenes y vectores en formato base64 para la deteccion de incendios.",
    },
    {
        "name": "Models",
        "description": "Consultar los modelos disponibles para el analisis.",
    },
    {
        "name": "Results",
        "description": "Obtener los resultados de las detecciones de incendios.",
    },
    {
        "name": "Notifications",
        "description": "Consultar y marcar notificaciones de detecciones.",
    },
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    await utils.init_db_pool()
    try:
        yield
    finally:
        await utils.close_db_pool()


app = FastAPI(
    lifespan=lifespan,
    title="GuaitaIA",
    description="Deteccion de humo de incendios forestales mediante IA",
    version="0.0.1 beta",
    openapi_tags=tags_metadata,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=ALLOWED_ORIGINS != ["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

os.makedirs("Resultados", exist_ok=True)
os.makedirs("Original", exist_ok=True)

app.mount("/imagenes", StaticFiles(directory="Resultados"), name="imagenes_resultados")
app.mount(
    "/imagenes_original",
    StaticFiles(directory="Original"),
    name="imagenes_originales",
)


@app.post("/token", response_model=mod.Token, tags=["Authenticate"])
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    user = await utils.get_user_from_db(form_data.username)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    if not utils.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user",
        )

    access_token_expires = timedelta(minutes=utils.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = utils.create_access_token(
        data={"sub": user.email},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users", tags=["User"])
async def get_users(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
):
    try:
        return await utils.get_users(current_user)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener los usuarios: {exc}",
        ) from exc


@app.get("/zones", tags=["User"])
async def get_zones(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)]
):
    try:
        return await utils.get_zones(current_user)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener las zonas: {exc}",
        ) from exc


@app.get(
    "/roles",
    response_model=List[mod.RoleHierarchyResponse],
    tags=["Roles"],
    summary="List Role Hierarchy",
    description="Devuelve la jerarquia de roles disponible para la administracion de usuarios.",
)
async def get_roles(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)]
):
    try:
        return await utils.get_roles(current_user)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener los roles: {exc}",
        ) from exc


@app.post("/roles", tags=["Roles"])
async def create_role(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    name: str = Form(...),
    description: Optional[str] = Form(default=None),
    parent_id: Optional[int] = Form(default=None),
):
    try:
        await utils.create_role(current_user, name, description, parent_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al crear el rol: {exc}",
        ) from exc

    return {"status": "success"}


@app.put("/roles/{role_id}", tags=["Roles"])
async def update_role(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    role_id: int,
    name: str = Form(...),
    description: Optional[str] = Form(default=None),
    parent_id: Optional[int] = Form(default=None),
):
    try:
        await utils.update_role(current_user, role_id, name, description, parent_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al actualizar el rol: {exc}",
        ) from exc

    return {"status": "success"}


@app.delete("/roles/{role_id}", tags=["Roles"])
async def delete_role(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    role_id: int,
):
    try:
        await utils.delete_role(current_user, role_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al eliminar el rol: {exc}",
        ) from exc

    return {"status": "success"}


@app.post("/user/create", tags=["User"])
async def create_user(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    zones_id: int = Form(...),
    is_active: bool = Form(True),
):
    try:
        await utils.create_user(email, password, role, zones_id, is_active)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al crear el usuario: {exc}",
        ) from exc

    return {"status": "success"}


@app.put("/user/{user_id}", tags=["User"])
async def update_user(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    user_id: int,
    email: str = Form(...),
    role: str = Form(...),
    zones_id: int = Form(...),
    is_active: bool = Form(...),
    password: Optional[str] = Form(default=None),
):
    try:
        await utils.update_user(
            current_user,
            user_id,
            email,
            role,
            zones_id,
            is_active,
            password,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al actualizar el usuario: {exc}",
        ) from exc

    return {"status": "success"}


@app.delete("/user/{user_id}", tags=["User"])
async def delete_user(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_is_superadmin)],
    user_id: int,
):
    try:
        await utils.delete_user(current_user, user_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al eliminar el usuario: {exc}",
        ) from exc

    return {"status": "success"}


@app.patch("/user/update/password", tags=["User"])
async def update_password(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    password: str = Form(...),
):
    try:
        await utils.update_password(current_user, password)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error al actualizar la contrasena: {exc}",
        ) from exc

    return {"status": "success"}


@app.get(
    "/settings/notifications",
    response_model=mod.NotificationSettingsResponse,
    tags=["Settings"],
)
async def get_notification_settings(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
):
    try:
        return await utils.get_notification_settings(current_user)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener los ajustes: {exc}",
        ) from exc


@app.patch(
    "/settings/notifications",
    response_model=mod.NotificationSettingsResponse,
    tags=["Settings"],
)
async def update_notification_settings(
    payload: mod.NotificationSettingsUpdate,
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
):
    try:
        return await utils.update_notification_settings(
            current_user,
            payload.notifications_enabled,
            payload.notification_sound_enabled,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al actualizar los ajustes: {exc}",
        ) from exc


@app.get(
    "/notifications/unread",
    response_model=List[mod.NotificationResponse],
    tags=["Notifications"],
)
async def get_unread_notifications(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
):
    try:
        return await utils.get_unread_notifications(current_user)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener las notificaciones: {exc}",
        ) from exc


@app.patch("/notifications/read", tags=["Notifications"])
async def mark_notifications_as_read(
    payload: mod.NotificationReadRequest,
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
):
    try:
        await utils.mark_notifications_as_read(current_user, payload.ids)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al actualizar las notificaciones: {exc}",
        ) from exc

    return {"status": "success"}


@app.get(
    "/models",
    response_model=List[mod.AvailableModel],
    tags=["Models"],
    summary="List Available Models",
    description="Devuelve los modelos disponibles en la carpeta model y marca cual es el modelo por defecto.",
)
async def get_models(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
):
    try:
        available_models = fc.get_available_models()
        default_model_name = fc.get_default_model_name()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener los modelos: {exc}",
        ) from exc

    return [
        {
            "name": model["name"],
            "is_default": model["name"] == default_model_name,
        }
        for model in available_models
    ]


@app.post("/detectar_incendios/", tags=["Wildfire detection"])
async def detectar_incendios_multiples(
    current_user: Annotated[mod.User, Depends(utils.get_current_user_time)],
    imagenes: Optional[List[UploadFile]] = File(default=None),
    imagenes_strings: Optional[List[str]] = Form(default=None),
    confianza: float = Form(default=0.5, ge=0.0, le=1.0),
    iou: float = Form(default=0.5, ge=0.0, le=1.0),
    cpu: int = Form(default=1, ge=0, le=1),
    model_name: Optional[str] = Form(default=None),
):
    if not imagenes and not imagenes_strings:
        raise HTTPException(
            status_code=400,
            detail="Debe proporcionar al menos un conjunto de imagenes o strings.",
        )

    if imagenes and all(imagen.filename == "" for imagen in imagenes):
        imagenes = None

    if imagenes and imagenes_strings:
        raise HTTPException(
            status_code=400,
            detail="Proporcione solo imagenes o solo strings, no ambos.",
        )

    if imagenes_strings and len(imagenes_strings) == 1:
        imagenes_strings = [
            item for item in imagenes_strings[0].split(",") if item
        ]

    input_para_procesar = imagenes if imagenes else imagenes_strings

    try:
        return await fc.procesar_imagen_multiple(
            input_para_procesar,
            confianza,
            iou,
            cpu,
            current_user,
            model_name,
        )
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Error al procesar las imagenes: {exc}",
        ) from exc


@app.get("/statistics/", tags=["Results"])
async def get_statistics(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    user: Optional[int] = None,
    date: Optional[str] = None,
):
    try:
        statistics, statics2, statics3 = await utils.statistics(current_user, user, date)
        return statistics, statics2, statics3
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener los resultados: {exc}",
        ) from exc


@app.get("/results/dates", tags=["Results"])
async def get_results_dates(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)]
):
    try:
        return await utils.get_results_dates(current_user)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener las fechas: {exc}",
        ) from exc


@app.get("/results/images", tags=["Results"])
async def get_results_images_date(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    date: Optional[str] = None,
):
    try:
        return await utils.get_results_images_date(current_user, date)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al obtener las imagenes: {exc}",
        ) from exc


@app.put("/results/images/status", tags=["Results"])
async def update_results_images_status(
    current_user: Annotated[mod.User, Depends(utils.get_current_active_user)],
    id: Optional[int] = None,
    status: Optional[str] = None,
):
    try:
        return await utils.update_results_images_status(current_user, id, status)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Error al actualizar el estado de la imagen: {exc}",
        ) from exc


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
