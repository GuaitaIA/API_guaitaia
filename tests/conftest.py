  # tests/conftest.py
import pytest
import asyncio
from typing import Generator
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app.main import app
from app.core.security import get_password_hash
  
@pytest.fixture(scope="function")
def bucle_evento():
    """Crea una instancia del bucle de eventos predeterminado para la sesión de prueba."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()
  
@pytest.fixture
def cliente() -> Generator:
    """Crea un cliente de prueba."""
    with TestClient(app) as c:
        yield c
  
# Mock de la base de datos para los tests
@pytest.fixture(autouse=True)
def base_datos_mock():
    """Simulación de conexiones a la base de datos para todas las pruebas."""
      
    # Datos de usuarios de prueba
    usuarios_prueba = {
        "test@example.com": {
            "id": 1,
            "email": "test@example.com",
            "hashed_password": get_password_hash("testpassword123"),
            "is_active": True,
            "role": "user",
            "zones_id": 1
        },
        "admin@example.com": {
            "id": 2,
            "email": "admin@example.com",
            "hashed_password": get_password_hash("adminpassword123"),
            "is_active": True,
            "role": "superadmin",
            "zones_id": 1
        }
    }
      
    # Datos de zonas de prueba
    zonas_prueba = {
        1: {
            "id": 1,
            "timezone": "UTC",
            "start_time": 6,
            "end_time": 18
        }
    }
      
    async def mock_obtener_conexion_base_datos():
        """Simulación de conexión a la base de datos."""
        mock_conn = AsyncMock()
          
        # Simulación de fetchrow para obtener usuarios
        async def mock_fetchrow(query, *args):
            if "SELECT * FROM users WHERE email" in query:
                email = args[0]
                return usuarios_prueba.get(email)
            return None
          
        # Simulación de fetch para obtener zonas
        async def mock_fetch(query, *args):
            if "SELECT * FROM zones WHERE id" in query:
                zone_id = args[0]
                zone_data = zonas_prueba.get(zone_id)
                return [zone_data] if zone_data else []
            return []
          
        # Simulación de execute para operaciones de escritura
        async def mock_execute(query, *args):
            return "OK"
          
        mock_conn.fetchrow = mock_fetchrow
        mock_conn.fetch = mock_fetch
        mock_conn.execute = mock_execute
        mock_conn.close = AsyncMock()
          
        return mock_conn
      
    with patch('app.core.database.get_database_connection', side_effect=mock_obtener_conexion_base_datos):
        with patch('app.services.auth_service.get_database_connection', side_effect=mock_obtener_conexion_base_datos):
            with patch('app.services.user_service.get_database_connection', side_effect=mock_obtener_conexion_base_datos):
                with patch('app.services.results_service.get_database_connection', side_effect=mock_obtener_conexion_base_datos):
                    with patch('app.utils.dependencies.get_database_connection', side_effect=mock_obtener_conexion_base_datos):
                        yield
  
@pytest.fixture
def token_usuario_prueba(cliente: TestClient) -> str:
    """Obtiene el token de autenticación para el usuario de prueba."""
    datos_login = {
        "username": "test@example.com",
        "password": "testpassword123"
    }
      
    response = cliente.post("/api/v1/auth/token", data=datos_login)
    assert response.status_code == 200, f"Error de inicio de sesión: {response.json()}"
    return response.json()["access_token"]
  
@pytest.fixture
def token_superadmin_prueba(cliente: TestClient) -> str:
    """Obtiene el token de autenticación para el usuario superadmin."""
    datos_login = {
        "username": "admin@example.com",
        "password": "adminpassword123"
    }
      
    response = cliente.post("/api/v1/auth/token", data=datos_login)
    assert response.status_code == 200, f"Error de inicio de sesión de admin: {response.json()}"
    return response.json()["access_token"]
  
@pytest.fixture
def cabeceras_autenticacion(token_usuario_prueba: str) -> dict:
    """Devuelve las cabeceras de autorización con el token del usuario."""
    return {"Authorization": f"Bearer {token_usuario_prueba}"}
  
@pytest.fixture
def cabeceras_admin(token_superadmin_prueba: str) -> dict:
    """Devuelve las cabeceras de autorización con el token del admin."""
    return {"Authorization": f"Bearer {token_superadmin_prueba}"}