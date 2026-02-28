from sqlalchemy import Column, ForeignKey, String, Integer, Boolean
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)
    role = Column(String)
    zones_id = Column(Integer, ForeignKey('zones.id'))

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


class UserResponse(BaseModel):
    id: int
    email: str
    is_active: bool
    role: str
    zones_id: Optional[int] = None


class DetectionResponse(BaseModel):
    detection: bool
    conf: float
    procesada: str
    original: str
    fecha: str
    hora: str


class StatisticsResponse(BaseModel):
    detections: int
    not_detections: int
    date: Optional[str] = None
    user_id: Optional[int] = None