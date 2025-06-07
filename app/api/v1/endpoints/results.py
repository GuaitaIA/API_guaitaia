# app/api/v1/endpoints/results.py (actualizado)
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException

from app.models.user import User
from app.services.results_service import ResultsService
from app.utils.dependencies import get_current_active_user

router = APIRouter()

@router.get("/statistics")
async def get_statistics(
    current_user: Annotated[User, Depends(get_current_active_user)],
    user: Optional[int] = None,
    date: Optional[str] = None
):
    """Endpoint para obtener estadísticas."""
    try:
        statistics, statistics2, statistics3 = await ResultsService.get_statistics(
            current_user, user, date
        )
        return {
            "general_stats": [dict(record) for record in statistics],
            "hourly_stats": [dict(record) for record in statistics2],
            "detection_stats": [dict(record) for record in statistics3]
        }
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error al obtener las estadísticas: {e}"
        )

@router.get("/dates")
async def get_results_dates(
    current_user: Annotated[User, Depends(get_current_active_user)]
):
    """Endpoint para obtener las fechas en las que hay resultados."""
    try:
        dates = await ResultsService.get_results_dates(current_user)
        return dates
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error al obtener las fechas: {e}"
        )

@router.get("/images")
async def get_results_images_date(
    current_user: Annotated[User, Depends(get_current_active_user)],
    date: Optional[str] = None
):
    """Endpoint para obtener las imágenes de una fecha."""
    try:
        images = await ResultsService.get_results_images_date(current_user, date)
        return images
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error al obtener las imágenes: {e}"
        )

@router.put("/images/status")
async def update_results_images_status(
    current_user: Annotated[User, Depends(get_current_active_user)],
    id: Optional[int] = None,
    status: Optional[str] = None
):
    """Endpoint para actualizar el estado de una imagen."""
    try:
        result = await ResultsService.update_results_images_status(
            current_user, id, status
        )
        return {"status": "success", "updated": result}
    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail=f"Error al actualizar el estado de la imagen: {e}"
        )
