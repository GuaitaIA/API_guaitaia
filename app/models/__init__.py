# app/models/__init__.py
from .user import User, Zones
from .detection import Detection, Result

__all__ = ["User", "Zones", "Detection", "Result"]
