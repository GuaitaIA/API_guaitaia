# app/schemas/detection.py (CORREGIDO para Pydantic V2)
from pydantic import BaseModel, field_validator  # ← Cambio aquí
from typing import List, Optional
from datetime import datetime

class DetectionRequest(BaseModel):
    confidence: float
    iou: float
    cpu: int = 1
    
    @field_validator('confidence')  # ← Cambio de @validator a @field_validator
    @classmethod
    def validate_confidence(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('Confidence must be between 0.0 and 1.0')
        return v
    
    @field_validator('iou')  # ← Cambio de @validator a @field_validator
    @classmethod
    def validate_iou(cls, v):
        if not 0.0 <= v <= 1.0:
            raise ValueError('IoU must be between 0.0 and 1.0')
        return v

class DetectionResponse(BaseModel):
    detection: bool
    conf: Optional[float]
    procesada: Optional[str]
    original: Optional[str]
    fecha: str
    hora: Optional[str]

class StatisticsResponse(BaseModel):
    detections: int
    not_detections: int
    total_sum: int
