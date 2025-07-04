# app/models/detection.py
from sqlalchemy import Column, String, Integer, DateTime, Float, ForeignKey
from app.core.database import Base

class Result(Base):
    __tablename__ = "results"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    date = Column(DateTime)
    type = Column(String)
    detections = Column(Integer)
    not_detections = Column(Integer)

class Detection(Base):
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    date = Column(DateTime)
    url_original = Column(String)
    url_processed = Column(String)
    confidence = Column(Float)
    positive = Column(String, default=None)
