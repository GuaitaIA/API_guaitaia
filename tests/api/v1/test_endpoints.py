# tests/api/v1/test_endpoints.py
import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

class TestAuthEndpoints:
    """Tests para endpoints de autenticación."""
    
    def test_login_success(self, cliente: TestClient):
        """Test login exitoso."""
        login_data = {
            "username": "test@example.com",
            "password": "testpassword123"
        }
        
        with patch('app.services.auth_service.AuthService.authenticate_user') as mock_auth:
            # Mock del usuario autenticado
            mock_user = AsyncMock()
            mock_user.email = "test@example.com"
            mock_user.is_active = True
            mock_auth.return_value = mock_user
            
            response = cliente.post("/api/v1/auth/token", data=login_data)
            
            assert response.status_code == 200
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
    
    def test_login_invalid_credentials(self, cliente: TestClient):
        """Test login con credenciales inválidas."""
        login_data = {
            "username": "wrong@example.com",
            "password": "wrongpassword"
        }
        
        with patch('app.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_auth.return_value = None
            
            response = cliente.post("/api/v1/auth/token", data=login_data)
            
            assert response.status_code == 401
            assert "Incorrect email or password" in response.json()["detail"]
    
    def test_login_inactive_user(self, cliente: TestClient):
        """Test login con usuario inactivo."""
        login_data = {
            "username": "inactive@example.com",
            "password": "password123"
        }
        
        with patch('app.services.auth_service.AuthService.authenticate_user') as mock_auth:
            mock_user = AsyncMock()
            mock_user.email = "inactive@example.com"
            mock_user.is_active = False
            mock_auth.return_value = mock_user
            
            response = cliente.post("/api/v1/auth/token", data=login_data)
            
            assert response.status_code == 400
            assert "Inactive user" in response.json()["detail"]


class TestUserEndpoints:
    """Tests para endpoints de usuarios."""
    
    def test_get_users_as_superadmin(self, cliente: TestClient, cabeceras_admin: dict):
        """Test obtener usuarios como superadmin."""
        with patch('app.services.user_service.UserService.get_users') as mock_get_users:
            mock_get_users.return_value = [
                {"id": 1, "email": "user1@example.com", "role": "user"},
                {"id": 2, "email": "user2@example.com", "role": "user"}
            ]
            
            response = cliente.get("/api/v1/users/", headers=cabeceras_admin)
            
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 2
    
    def test_get_users_as_regular_user(self, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test obtener usuarios como usuario regular (debería fallar)."""
        with patch('app.services.user_service.UserService.get_users') as mock_get_users:
            mock_get_users.side_effect = Exception("Permissions required")
            
            response = cliente.get("/api/v1/users/", headers=cabeceras_autenticacion)
            
            assert response.status_code == 400
    
    def test_create_user_success(self, cliente: TestClient, cabeceras_admin: dict):
        """Test crear usuario exitosamente."""
        user_data = {
            "email": "newuser@example.com",
            "password": "newpassword123",
            "role": "user",
            "zones_id": 1
        }
        
        with patch('app.services.user_service.UserService.create_user') as mock_create:
            mock_create.return_value = "newuser@example.com"
            
            response = cliente.post("/api/v1/users/create", data=user_data, headers=cabeceras_admin)
            
            assert response.status_code == 200
            assert response.json()["status"] == "success"
    
    def test_delete_user_success(self, cliente: TestClient, cabeceras_admin: dict):
        """Test eliminar usuario exitosamente."""
        with patch('app.services.user_service.UserService.delete_user') as mock_delete:
            mock_delete.return_value = True
            
            response = cliente.delete("/api/v1/users/1", headers=cabeceras_admin)
            
            assert response.status_code == 200
            assert response.json()["status"] == "success"
    
    def test_update_password_success(self, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test actualizar contraseña exitosamente."""
        password_data = {"password": "newpassword123"}
        
        with patch('app.services.user_service.UserService.update_password') as mock_update:
            mock_update.return_value = "user@example.com"
            
            response = cliente.patch("/api/v1/users/update/password", data=password_data, headers=cabeceras_autenticacion)
            
            assert response.status_code == 200
            assert response.json()["status"] == "success"


class TestDetectionEndpoints:
    """Tests para endpoints de detección."""
    
    # tests/api/v1/test_endpoints.py - Para los tests de detección

    def test_detect_wildfires_no_images(self, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test detección sin imágenes (debería fallar)."""
        detection_data = {
            "confianza": 0.5,
            "iou": 0.5,
            "cpu": 1
        }

        # Mock de la hora para que esté dentro del horario permitido
        with patch('app.utils.dependencies.datetime') as mock_datetime:
            from datetime import datetime
            mock_now = datetime(2023, 1, 1, 10, 0, 0)  # 10 AM - horario permitido
            mock_datetime.now.return_value = mock_now
            
            response = cliente.post("/api/v1/detection/", data=detection_data, headers=cabeceras_autenticacion)

        assert response.status_code == 400
        assert "Debe proporcionar al menos un conjunto de imágenes" in response.json()["detail"]

    def test_detect_wildfires_with_images_and_strings(self, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test detección con imágenes y strings (debería fallar)."""
        detection_data = {
            "confianza": 0.5,
            "iou": 0.5,
            "cpu": 1,
            "imagenes_strings": ["base64string"]
        }

        files = {"imagenes": ("test.jpg", b"fake_image_data", "image/jpeg")}

        # Mock de la hora para que esté dentro del horario permitido
        with patch('app.utils.dependencies.datetime') as mock_datetime:
            from datetime import datetime
            mock_now = datetime(2023, 1, 1, 10, 0, 0)  # 10 AM - horario permitido
            mock_datetime.now.return_value = mock_now
            
            response = cliente.post("/api/v1/detection/", data=detection_data, files=files, headers=cabeceras_autenticacion)

        assert response.status_code == 400
        assert "Proporcione solo imágenes o solo strings" in response.json()["detail"]

    @patch('app.services.detection_service.DetectionService.process_multiple_images')
    def test_detect_wildfires_success(self, mock_process, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test detección exitosa."""
        mock_process.return_value = '[{"detection": true, "conf": 0.85}]'

        detection_data = {
            "confianza": 0.5,
            "iou": 0.5,
            "cpu": 1
        }

        files = {"imagenes": ("test.jpg", b"fake_image_data", "image/jpeg")}

        # Mock de la hora para que esté dentro del horario permitido
        with patch('app.utils.dependencies.datetime') as mock_datetime:
            from datetime import datetime
            mock_now = datetime(2023, 1, 1, 10, 0, 0)  # 10 AM - horario permitido
            mock_datetime.now.return_value = mock_now
            
            response = cliente.post("/api/v1/detection/", data=detection_data, files=files, headers=cabeceras_autenticacion)

        assert response.status_code == 200


class TestResultsEndpoints:
    """Tests para endpoints de resultados."""
    
    def test_get_statistics_success(self, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test obtener estadísticas exitosamente."""
        with patch('app.services.results_service.ResultsService.get_statistics') as mock_stats:
            mock_stats.return_value = (
                [{"detections": 10, "not_detections": 5}],
                [{"hour": "2023-01-01 10:00:00", "total_detections": 3}],
                [{"true_detections": 8, "false_detections": 2}]
            )
            
            response = cliente.get("/api/v1/results/statistics", headers=cabeceras_autenticacion)
            
            assert response.status_code == 200
            data = response.json()
            assert "general_stats" in data
            assert "hourly_stats" in data
            assert "detection_stats" in data
    
    def test_get_results_dates_success(self, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test obtener fechas de resultados exitosamente."""
        with patch('app.services.results_service.ResultsService.get_results_dates') as mock_dates:
            mock_dates.return_value = [
                {"date": "2023-01-01"},
                {"date": "2023-01-02"}
            ]
            
            response = cliente.get("/api/v1/results/dates", headers=cabeceras_autenticacion)
            
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 2
    
    def test_get_results_images_success(self, cliente: TestClient, cabeceras_autenticacion: dict):
        """Test obtener imágenes por fecha exitosamente."""
        with patch('app.services.results_service.ResultsService.get_results_images_date') as mock_images:
            mock_images.return_value = [
                {"id": 1, "url_processed": "image1.webp", "positive": "true"},
                {"id": 2, "url_processed": "image2.webp", "positive": "false"}
            ]
            
            response = cliente.get("/api/v1/results/images?date=2023-01-01", headers=cabeceras_autenticacion)
            
            assert response.status_code == 200
            data = response.json()
            assert len(data) == 2
    
    def test_update_image_status_success(self, cliente: TestClient, cabeceras_admin: dict):
        """Test actualizar estado de imagen exitosamente."""
        with patch('app.services.results_service.ResultsService.update_results_images_status') as mock_update:
            mock_update.return_value = True
            
            response = cliente.put("/api/v1/results/images/status?id=1&status=true", headers=cabeceras_admin)
            
            assert response.status_code == 200
            data = response.json()
            assert data["status"] == "success"
            assert data["updated"] == True
