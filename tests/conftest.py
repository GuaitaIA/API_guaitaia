# tests/conftest.py
import pytest
import asyncio
from typing import Generator
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock
from app.main import app
from app.core.security import get_password_hash

@pytest.fixture(scope="function")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def client() -> Generator:
    """Create a test client."""
    with TestClient(app) as c:
        yield c

# Mock de la base de datos para los tests
@pytest.fixture(autouse=True)
def mock_database():
    """Mock database connections for all tests."""
    
    # Datos de usuarios de prueba
    test_users = {
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
    test_zones = {
        1: {
            "id": 1,
            "timezone": "UTC",
            "start_time": 6,
            "end_time": 18
        }
    }
    
    async def mock_get_database_connection():
        """Mock database connection."""
        mock_conn = AsyncMock()
        
        # Mock fetchrow para obtener usuarios
        async def mock_fetchrow(query, *args):
            if "SELECT * FROM users WHERE email" in query:
                email = args[0]
                return test_users.get(email)
            return None
        
        # Mock fetch para obtener zonas
        async def mock_fetch(query, *args):
            if "SELECT * FROM zones WHERE id" in query:
                zone_id = args[0]
                zone_data = test_zones.get(zone_id)
                return [zone_data] if zone_data else []
            return []
        
        # Mock execute para operaciones de escritura
        async def mock_execute(query, *args):
            return "OK"
        
        mock_conn.fetchrow = mock_fetchrow
        mock_conn.fetch = mock_fetch
        mock_conn.execute = mock_execute
        mock_conn.close = AsyncMock()
        
        return mock_conn
    
    with patch('app.core.database.get_database_connection', side_effect=mock_get_database_connection):
        with patch('app.services.auth_service.get_database_connection', side_effect=mock_get_database_connection):
            with patch('app.services.user_service.get_database_connection', side_effect=mock_get_database_connection):
                with patch('app.services.results_service.get_database_connection', side_effect=mock_get_database_connection):
                    with patch('app.utils.dependencies.get_database_connection', side_effect=mock_get_database_connection):
                        yield

@pytest.fixture
def test_user_token(client: TestClient) -> str:
    """Get authentication token for test user."""
    login_data = {
        "username": "test@example.com",
        "password": "testpassword123"
    }
    
    response = client.post("/api/v1/auth/token", data=login_data)
    assert response.status_code == 200, f"Login failed: {response.json()}"
    return response.json()["access_token"]

@pytest.fixture
def test_superadmin_token(client: TestClient) -> str:
    """Get authentication token for superadmin user."""
    login_data = {
        "username": "admin@example.com",
        "password": "adminpassword123"
    }
    
    response = client.post("/api/v1/auth/token", data=login_data)
    assert response.status_code == 200, f"Admin login failed: {response.json()}"
    return response.json()["access_token"]

@pytest.fixture
def auth_headers(test_user_token: str) -> dict:
    """Return authorization headers with user token."""
    return {"Authorization": f"Bearer {test_user_token}"}

@pytest.fixture
def admin_headers(test_superadmin_token: str) -> dict:
    """Return authorization headers with admin token."""
    return {"Authorization": f"Bearer {test_superadmin_token}"}
