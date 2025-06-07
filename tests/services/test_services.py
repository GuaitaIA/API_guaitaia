# tests/services/test_services.py
import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from app.services.auth_service import AuthService
from app.services.user_service import UserService
from app.services.detection_service import DetectionService
from app.services.results_service import ResultsService
from app.schemas.user import UserCreate

class TestAuthService:
    
    @pytest.mark.asyncio
    async def test_get_user_from_db_success(self):
        """Test obtener usuario de BD exitosamente."""
        user = await AuthService.get_user_from_db("test@example.com")
        assert user is not None
        assert user.email == "test@example.com"
        assert user.role == "user"

    @pytest.mark.asyncio
    async def test_get_user_from_db_not_found(self):
        """Test usuario no encontrado en BD."""
        user = await AuthService.get_user_from_db("nonexistent@example.com")
        assert user is None

    @pytest.mark.asyncio
    async def test_authenticate_user_success(self):
        """Test autenticación exitosa."""
        user = await AuthService.authenticate_user("test@example.com", "testpassword123")
        assert user is not False
        assert user.email == "test@example.com"

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(self):
        """Test autenticación con contraseña incorrecta."""
        user = await AuthService.authenticate_user("test@example.com", "wrongpassword")
        assert user is False

    @pytest.mark.asyncio
    async def test_create_user_success(self):
        """Test crear usuario exitosamente."""
        user_data = UserCreate(
            email="newuser@example.com",
            password="password123",
            role="user",
            zones_id=1
        )

        with patch.object(AuthService, 'get_user_from_db') as mock_get_user:
            mock_get_user.return_value = None  # Usuario no existe
            
            result = await UserService.create_user(user_data)
            assert result == "newuser@example.com"

class TestUserService:

    @pytest.mark.asyncio
    async def test_create_user_success(self):
        """Test crear usuario exitosamente."""
        user_data = UserCreate(
            email="newuser@example.com",
            password="password123",
            role="user",
            zones_id=1
        )

        with patch.object(UserService, '_get_user_by_email') as mock_get_user:
            mock_get_user.return_value = None  # Usuario no existe
            
            result = await UserService.create_user(user_data)
            assert result == "newuser@example.com"

    @pytest.mark.asyncio
    async def test_create_user_already_exists(self):
        """Test crear usuario que ya existe."""
        user_data = UserCreate(
            email="test@example.com",  # Este usuario ya existe
            password="password123",
            role="user",
            zones_id=1
        )

        with pytest.raises(Exception) as exc_info:
            await UserService.create_user(user_data)
        
        assert "Email already registered" in str(exc_info.value)

class TestDetectionService:

    @patch('app.services.detection_service.YOLO')
    def test_validate_extension_valid(self, mock_yolo):
        """Test validación de extensión válida."""
        mock_yolo.return_value = MagicMock()
        detection_service = DetectionService()
        result = detection_service._validate_extension("test.jpg")
        assert result is True

    @patch('app.services.detection_service.YOLO')
    def test_validate_extension_invalid(self, mock_yolo):
        """Test validación de extensión inválida."""
        mock_yolo.return_value = MagicMock()
        detection_service = DetectionService()
        result = detection_service._validate_extension("test.txt")
        assert result is False

    @patch('app.services.detection_service.YOLO')
    def test_is_allowed_extension_url_valid(self, mock_yolo):
        """Test validación de URL con extensión válida."""
        mock_yolo.return_value = MagicMock()
        detection_service = DetectionService()
        result = detection_service._is_allowed_extension_url("http://example.com/image.jpg")
        assert result is True

    @patch('app.services.detection_service.YOLO')
    def test_is_allowed_extension_url_invalid(self, mock_yolo):
        """Test validación de URL con extensión inválida."""
        mock_yolo.return_value = MagicMock()
        detection_service = DetectionService()
        result = detection_service._is_allowed_extension_url("http://example.com/file.txt")
        assert result is False

class TestResultsService:

    @pytest.mark.asyncio
    async def test_get_statistics_superadmin(self):
        """Test obtener estadísticas como superadmin."""
        class MockUser:
            def __init__(self, **kwargs):
                for key, value in kwargs.items():
                    setattr(self, key, value)

        mock_user = MockUser(
            id=1,
            email="admin@example.com",
            hashed_password="hashed",
            is_active=True,
            role="superadmin",
            zones_id=1
        )

        # Usar el mock global pero sobrescribir para este test específico
        async def mock_get_database_connection():
            mock_conn = AsyncMock()
            
            # Configurar múltiples llamadas fetch para las 3 consultas
            fetch_results = [
                [{"detections": 10, "not_detections": 5, "total_sum": 15}],  # Primera consulta
                [{"true_detections": 8, "false_detections": 2}],  # Tercera consulta (query3)
                [{"hour": "2023-01-01 10:00:00", "total_detections": 3, "total_not_detections": 2}]  # Segunda consulta (query2)
            ]
            
            mock_conn.fetch = AsyncMock(side_effect=fetch_results)
            mock_conn.close = AsyncMock()
            
            return mock_conn

        with patch('app.services.results_service.get_database_connection', side_effect=mock_get_database_connection):
            results, results2, results3 = await ResultsService.get_statistics(mock_user)
            
            # Verificar que se devolvieron los resultados correctos
            assert len(results) == 1
            assert len(results2) == 1  
            assert len(results3) == 1

    @pytest.mark.asyncio
    async def test_get_statistics_regular_user_with_user_id(self):
        """Test obtener estadísticas como usuario regular con user_id (debería fallar)."""
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

        with pytest.raises(Exception) as exc_info:
            await ResultsService.get_statistics(mock_user, user_id=2)
        
        assert "Permissions required" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_update_results_images_status_not_superadmin(self):
        """Test actualizar estado de imagen sin ser superadmin (debería fallar)."""
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

        with pytest.raises(Exception) as exc_info:
            await ResultsService.update_results_images_status(mock_user, 1, "true")
        
        assert "Permissions required" in str(exc_info.value)
