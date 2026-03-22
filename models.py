from typing import Optional

from pydantic import BaseModel
from sqlalchemy import Boolean, Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(String)
    zones_id = Column(Integer, ForeignKey("zones.id"))


class Zones(Base):
    __tablename__ = "zones"

    id = Column(Integer, primary_key=True, index=True)
    timezone = Column(String)
    start_time = Column(Integer)
    end_time = Column(Integer)


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
