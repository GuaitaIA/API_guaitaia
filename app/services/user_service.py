# app/services/user_service.py
from typing import List, Optional
from fastapi import HTTPException
from app.core.database import get_database_connection
from app.core.security import get_password_hash
from app.models.user import User
from app.schemas.user import UserCreate

class UserService:
    
    @staticmethod
    async def create_user(user_data: UserCreate) -> str:
        """Crea un nuevo usuario en la base de datos."""
        hashed_password = get_password_hash(user_data.password)
        conn = await get_database_connection()
        
        # Verificar si el usuario ya existe
        existing_user = await UserService._get_user_by_email(user_data.email)
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered")
        
        try:
            query = """
                INSERT INTO users (email, hashed_password, role, is_active, zones_id) 
                VALUES ($1, $2, $3, $4, $5)
            """
            await conn.execute(
                query, 
                user_data.email, 
                hashed_password, 
                user_data.role, 
                True, 
                user_data.zones_id
            )
        finally:
            await conn.close()
        return user_data.email

    @staticmethod
    async def get_users(current_user: User) -> List[dict]:
        """Obtiene todos los usuarios (solo para superadmin)."""
        if current_user.role != "superadmin":
            raise HTTPException(status_code=400, detail="Permissions required")
        
        conn = await get_database_connection()
        try:
            query = """
                SELECT users.id, users.email, users.role, users.is_active, zones.timezone 
                FROM users 
                JOIN zones ON users.zones_id = zones.id
            """
            results = await conn.fetch(query)
            return [dict(record) for record in results]
        finally:
            await conn.close()

    @staticmethod
    async def delete_user(current_user: User, user_id: int) -> bool:
        """Elimina un usuario (solo para superadmin)."""
        if current_user.role != "superadmin":
            raise HTTPException(status_code=400, detail="Permissions required")
        
        conn = await get_database_connection()
        try:
            query = "DELETE FROM users WHERE id = $1"
            await conn.execute(query, user_id)
            return True
        finally:
            await conn.close()

    @staticmethod
    async def update_password(user: User, new_password: str) -> str:
        """Actualiza la contraseña de un usuario."""
        hashed_password = get_password_hash(new_password)
        conn = await get_database_connection()
        try:
            query = "UPDATE users SET hashed_password = $1 WHERE id = $2"
            await conn.execute(query, hashed_password, user.id)
        finally:
            await conn.close()
        return user.email

    @staticmethod
    async def _get_user_by_email(email: str) -> Optional[User]:
        """Método privado para obtener usuario por email."""
        conn = await get_database_connection()
        try:
            query = "SELECT * FROM users WHERE email = $1"
            user_record = await conn.fetchrow(query, email)
            if user_record:
                return User(**user_record)
            return None
        finally:
            await conn.close()
