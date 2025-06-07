# app/api/v1/endpoints/users.py
from typing import Annotated, List
from fastapi import APIRouter, Depends, HTTPException, Form

from app.models.user import User
from app.schemas.user import UserCreate
from app.services.user_service import UserService
from app.utils.dependencies import get_current_active_user, get_current_user_is_superadmin

router = APIRouter()

@router.get("/")
async def get_users(current_user: Annotated[User, Depends(get_current_active_user)]):
    """Endpoint para obtener todos los usuarios."""
    try:
        users = await UserService.get_users(current_user)
        return users
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al obtener los usuarios: {e}")

@router.post("/create")
async def create_user(
    current_user: Annotated[User, Depends(get_current_user_is_superadmin)],
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    zones_id: int = Form(...),
):
    """Endpoint para crear un nuevo usuario."""
    try:
        user_data = UserCreate(email=email, password=password, role=role, zones_id=zones_id)
        await UserService.create_user(user_data)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al crear el usuario: {e}")

@router.delete("/{user_id}")
async def delete_user(
    current_user: Annotated[User, Depends(get_current_user_is_superadmin)],
    user_id: int
):
    """Endpoint para eliminar un usuario."""
    try:
        await UserService.delete_user(current_user, user_id)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Error al eliminar el usuario: {e}")

@router.patch("/update/password")
async def update_password(
    current_user: Annotated[User, Depends(get_current_active_user)],
    password: str = Form(...)
):
    """Endpoint para actualizar la contraseña del usuario."""
    try:
        await UserService.update_password(current_user, password)
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar la contraseña: {e}")
