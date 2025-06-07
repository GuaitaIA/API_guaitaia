# app/schemas/__init__.py
from .user import User, UserCreate, UserUpdate, Token, TokenData
from .detection import DetectionRequest, DetectionResponse, StatisticsResponse

__all__ = [
    "User", "UserCreate", "UserUpdate", "Token", "TokenData",
    "DetectionRequest", "DetectionResponse", "StatisticsResponse"
]
