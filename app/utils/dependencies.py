# app/utils/dependencies.py
from datetime import datetime
from typing import Annotated
from fastapi import Depends, HTTPException, status
import pytz

from app.core.security import oauth2_scheme
from app.core.database import get_database_connection
from app.services.auth_service import AuthService
from app.models.user import User, Zones

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> User:
    """Obtiene el usuario actual a partir de un token JWT."""
    return await AuthService.get_current_user(token)

async def get_current_active_user(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Verifica si el usuario actual está activo."""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def get_current_user_is_superadmin(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Verifica si el usuario actual es un superadministrador."""
    if current_user.role != "superadmin":
        raise HTTPException(status_code=400, detail="Permissions required")
    return current_user

async def get_current_user_time(current_user: Annotated[User, Depends(get_current_user)]) -> User:
    """Verifica si el usuario actual puede ejecutar la API de detección según la hora."""
    conn = await get_database_connection()
    try:
        query = "SELECT * FROM zones WHERE id = $1"
        timezone_record = await conn.fetch(query, current_user.zones_id)
    finally:
        await conn.close()
    
    date_time = datetime.now()
    timezone_model = Zones(**timezone_record[0])
    user_timezone = pytz.timezone(timezone_model.timezone)
    
    date_time = date_time.astimezone(user_timezone)
    hour = int(date_time.strftime("%H"))
    
    if hour < timezone_model.start_time or hour >= timezone_model.end_time:
        raise HTTPException(status_code=400, detail="Not allowed at this time")
    
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    return current_user
