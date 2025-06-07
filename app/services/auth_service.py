# app/services/auth_service.py
from typing import Optional
from fastapi import HTTPException, status, Depends
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from app.core.config import settings
from app.core.security import verify_password
from app.core.database import get_database_connection
from app.models.user import User
from app.schemas.user import TokenData

class AuthService:
    
    @staticmethod
    async def get_user_from_db(email: str) -> Optional[User]:
        """Obtiene un registro de usuario de la base de datos por correo electrónico."""
        conn = await get_database_connection()
        try:
            query = "SELECT * FROM users WHERE email = $1"
            user_record = await conn.fetchrow(query, email)
            if user_record:
                return User(**user_record)
            return None
        finally:
            await conn.close()

    @staticmethod
    async def authenticate_user(email: str, password: str) -> Optional[User]:
        """Autentica a un usuario basándose en el correo electrónico y contraseña."""
        user = await AuthService.get_user_from_db(email)
        if not user:
            return False
        if not verify_password(password, user.hashed_password):
            return False
        return user

    @staticmethod
    async def get_current_user(token: str) -> User:
        """Obtiene el usuario actual a partir de un token JWT."""
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
            email: str = payload.get("sub")
            if email is None:
                raise credentials_exception
            token_data = TokenData(email=email)
        except JWTError:
            raise credentials_exception

        user = await AuthService.get_user_from_db(email=token_data.email)
        if user is None:
            raise credentials_exception
        return user
