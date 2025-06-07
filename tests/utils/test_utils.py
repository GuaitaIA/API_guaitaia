# tests/utils/test_utils.py
import pytest
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from datetime import datetime
import pytz

from app.utils.dependencies import (
    get_current_user,
    get_current_active_user,
    get_current_user_is_superadmin,
    get_current_user_time
)
from app.models.user import User, Zones


class TestDependencies:
    """Tests para las dependencias de la aplicación."""
    
    @pytest.mark.asyncio
    async def test_get_current_active_user_active(self):
        """Test obtener usuario activo."""
        mock_user = User(
            id=1,
            email="test@example.com",
            hashed_password="hashed",
            is_active=True,
            role="user",
            zones_id=1
        )
        
        result = await get_current_active_user(mock_user)
        
        assert result == mock_user
    
    @pytest.mark.asyncio
    async def test_get_current_active_user_inactive(self):
        """Test obtener usuario inactivo (debería fallar)."""
        mock_user = User(
            id=1,
            email="test@example.com",
            hashed_password="hashed",
            is_active=False,
            role="user",
            zones_id=1
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_active_user(mock_user)
        
        assert exc_info.value.status_code == 400
        assert "Inactive user" in str(exc_info.value.detail)
    
    @pytest.mark.asyncio
    async def test_get_current_user_is_superadmin_valid(self):
        """Test obtener superadmin válido."""
        mock_user = User(
            id=1,
            email="admin@example.com",
            hashed_password="hashed",
            is_active=True,
            role="superadmin",
            zones_id=1
        )
        
        result = await get_current_user_is_superadmin(mock_user)
        
        assert result == mock_user
    
    @pytest.mark.asyncio
    async def test_get_current_user_is_superadmin_invalid(self):
        """Test usuario regular intentando acceso de superadmin."""
        mock_user = User(
            id=1,
            email="user@example.com",
            hashed_password="hashed",
            is_active=True,
            role="user",
            zones_id=1
        )
        
        with pytest.raises(HTTPException) as exc_info:
            await get_current_user_is_superadmin(mock_user)
        
        assert exc_info.value.status_code == 400
        assert "Permissions required" in str(exc_info.value.detail)
    
    # tests/utils/test_utils.py

    @pytest.mark.asyncio
    async def test_get_current_user_time_allowed_hours(self):
        """Test acceso en horas permitidas."""
        from app.utils.dependencies import get_current_user_time
        
        # Crear un objeto User simple para el test
        class MockUser:
            def __init__(self, **kwargs):
                for key, value in kwargs.items():
                    setattr(self, key, value)
        
        mock_user = MockUser(
            id=1,
            email="user@example.com",
            hashed_password="hashed",
            is_active=True,
            role="user",
            zones_id=1
        )

        with patch('app.utils.dependencies.datetime') as mock_datetime:
            from datetime import datetime
            # Mock de la hora actual (10 AM - dentro del horario permitido)
            mock_now = datetime(2023, 1, 1, 10, 0, 0)
            mock_datetime.now.return_value = mock_now
            
            result = await get_current_user_time(mock_user)
            assert result == mock_user

    # tests/utils/test_utils.py

    @pytest.mark.asyncio
    async def test_get_current_user_time_not_allowed_hours(self):
        """Test acceso en horas no permitidas."""
        from app.utils.dependencies import get_current_user_time
        from fastapi import HTTPException

        class MockUser:
            def __init__(self, **kwargs):
                for key, value in kwargs.items():
                    setattr(self, key, value)

        mock_user = MockUser(
            id=1,
            email="user@example.com",
            hashed_password="hashed",
            is_active=True,
            role="user",
            zones_id=1
        )

        with patch('app.utils.dependencies.datetime') as mock_datetime:
            from datetime import datetime
            # Mock de la hora actual (2 AM - fuera del horario permitido)
            mock_now = datetime(2023, 1, 1, 2, 0, 0)
            mock_datetime.now.return_value = mock_now

            with pytest.raises(HTTPException) as exc_info:
                await get_current_user_time(mock_user)

            # El código de estado es 400, no 403 según el código fuente
            assert exc_info.value.status_code == 400
            assert exc_info.value.detail == "Not allowed at this time"
