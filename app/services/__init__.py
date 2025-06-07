# app/services/__init__.py (actualizado)
from .auth_service import AuthService
from .user_service import UserService
from .detection_service import DetectionService
from .results_service import ResultsService

__all__ = ["AuthService", "UserService", "DetectionService", "ResultsService"]
