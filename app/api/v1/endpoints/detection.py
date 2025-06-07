# app/api/v1/endpoints/detection.py
from typing import Annotated, List, Optional
from fastapi import APIRouter, Depends, HTTPException, File, UploadFile, Form
import json

from app.models.user import User
from app.services.detection_service import DetectionService
from app.utils.dependencies import get_current_user_time

router = APIRouter()
detection_service = DetectionService()

@router.post("/")
async def detect_wildfires(
    current_user: Annotated[User, Depends(get_current_user_time)],
    imagenes: Optional[List[UploadFile]] = File(default=None),
    imagenes_strings: Optional[List[str]] = Form(default=None),
    confianza: float = Form(...),
    iou: float = Form(...),
    cpu: int = Form(...)
):
    """
    Endpoint para la detección de incendios en múltiples imágenes.
    """
    if not imagenes and not imagenes_strings:
        raise HTTPException(
            status_code=400, 
            detail="Debe proporcionar al menos un conjunto de imágenes o strings."
        )

    if imagenes and all(imagen.filename == "" for imagen in imagenes):
        imagenes = None

    if imagenes and imagenes_strings:
        raise HTTPException(
            status_code=400, 
            detail="Proporcione solo imágenes o solo strings, no ambos."
        )

    if imagenes_strings:
        imagenes_strings = imagenes_strings[0].split(',')

    input_para_procesar = imagenes if imagenes else imagenes_strings

    try:
        result = await detection_service.process_multiple_images(
            input_para_procesar, confianza, iou, cpu == 1, current_user
        )
        return json.loads(result)
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error al procesar las imágenes: {e}"
        )
