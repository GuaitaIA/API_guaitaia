from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    notifications_enabled = Column(Boolean, default=True)
    notification_sound_enabled = Column(Boolean, default=True)
    role = Column(String)
    zones_id = Column(Integer, ForeignKey("zones.id"))


class Zones(Base):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True, index=True)
    timezone = Column(String)
    start_time = Column(Integer)
    end_time = Column(Integer)


class RoleHierarchy(Base):
    __tablename__ = "role_hierarchy"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)
    description = Column(String, nullable=True)
    parent_id = Column(Integer, ForeignKey("role_hierarchy.id"), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    source_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    detection_id = Column(Integer, ForeignKey("detections.id"), nullable=True)
    title = Column(String, nullable=False)
    message = Column(String, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, nullable=False)


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    email: str | None = None


class AvailableModel(BaseModel):
    name: str
    is_default: bool


class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    notifications_enabled: bool = True
    role: str
    zones_id: Optional[int] = None
    timezone: Optional[str] = None


class DetectionResponse(BaseModel):
    detection: bool
    conf: Optional[float] = None
    procesada: Optional[str] = None
    original: Optional[str] = None
    fecha: str
    hora: Optional[str] = None


class StatisticsResponse(BaseModel):
    detections: Optional[int] = None
    not_detections: Optional[int] = None
    total_sum: Optional[int] = None
    date: Optional[str] = None
    user_id: Optional[int] = None


class RoleHierarchyResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    parent_id: Optional[int] = None
    parent_name: Optional[str] = None
    depth: int
    users_count: int
    is_protected: bool


class NotificationSettingsResponse(BaseModel):
    notifications_enabled: bool
    notification_sound_enabled: bool


class NotificationSettingsUpdate(BaseModel):
    notifications_enabled: bool
    notification_sound_enabled: bool


class NotificationResponse(BaseModel):
    id: int
    title: str
    message: str
    detection_id: Optional[int] = None
    created_at: datetime


class NotificationReadRequest(BaseModel):
    ids: list[int]
