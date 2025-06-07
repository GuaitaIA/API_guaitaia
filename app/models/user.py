# app/models/user.py
from sqlalchemy import Column, ForeignKey, String, Integer, Boolean
from app.core.database import Base

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
