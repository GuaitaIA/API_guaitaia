# app/services/results_service.py
from datetime import datetime
from typing import List, Optional, Tuple
from fastapi import HTTPException

from app.core.database import get_database_connection
from app.models.user import User

class ResultsService:
    
    @staticmethod
    async def get_statistics(
        current_user: User, 
        user_id: Optional[int] = None, 
        date: Optional[str] = None
    ) -> Tuple[List, List, List]:
        """
        Recupera estadísticas de detección de la base de datos.
        """
        conn = await get_database_connection()
        try:
            if current_user.role == "superadmin":
                if user_id:
                    query = """
                        SELECT sum(not_detections) as not_detections, 
                               sum(detections) as detections, 
                               SUM(not_detections) + SUM(detections) as total_sum 
                        FROM results WHERE user_id = $1
                    """
                    results = await conn.fetch(query, user_id)
                else:
                    query = """
                        SELECT sum(not_detections) as not_detections, 
                               sum(detections) as detections, 
                               SUM(not_detections) + SUM(detections) as total_sum 
                        FROM results
                    """
                    results = await conn.fetch(query)

                    query3 = """
                        SELECT SUM(CASE WHEN positive = 'true' THEN 1 ELSE 0 END) AS true_detections, 
                               SUM(CASE WHEN positive = 'false' THEN 1 ELSE 0 END) AS false_detections 
                        FROM detections
                    """
                    result3 = await conn.fetch(query3)
                    
                    if date is None:
                        date = datetime.now().date()
                    else:
                        date = datetime.strptime(date, '%Y-%m-%d').date()

                    query2 = """
                        SELECT DATE_TRUNC('hour', date) AS hour, 
                               SUM(detections) AS total_detections, 
                               SUM(not_detections) AS total_not_detections 
                        FROM results 
                        WHERE DATE(date) = $1 
                        GROUP BY DATE_TRUNC('hour', date) 
                        ORDER BY DATE_TRUNC('hour', date)
                    """
                    results2 = await conn.fetch(query2, date)
                    
            elif current_user.role == "user":
                if user_id:
                    raise HTTPException(status_code=400, detail="Permissions required")
                else:
                    query = """
                        SELECT sum(not_detections) as not_detections, 
                               sum(detections) as detections 
                        FROM results WHERE user_id = $1
                    """
                    results = await conn.fetch(query, current_user.id)
                    results2 = []
                    result3 = []
            else:
                raise HTTPException(status_code=400, detail="Permissions required")
                
            return results, results2, result3
        finally:
            await conn.close()

    @staticmethod
    async def get_results_dates(current_user: User) -> List:
        """Obtiene las fechas en las que hay resultados."""
        conn = await get_database_connection()
        try:
            if current_user.role == "superadmin":
                query = """
                    SELECT DATE(date) AS date 
                    FROM detections 
                    GROUP BY DATE(date) 
                    ORDER BY DATE(date) DESC
                """
                results = await conn.fetch(query)
            elif current_user.role == "user":
                query = """
                    SELECT DISTINCT date 
                    FROM results 
                    WHERE user_id = $1 
                    ORDER BY date DESC
                """
                results = await conn.fetch(query, current_user.id)
            else:
                raise HTTPException(status_code=400, detail="Permissions required")
                
            return [dict(record) for record in results]
        finally:
            await conn.close()

    @staticmethod
    async def get_results_images_date(
        current_user: User, 
        date: Optional[str] = None
    ) -> List:
        """Obtiene las imágenes de una fecha específica."""
        conn = await get_database_connection()
        try:
            if current_user.role == "superadmin":
                date_obj = datetime.strptime(date, '%Y-%m-%d').date()
                query = """
                    SELECT id, url_processed, positive 
                    FROM detections 
                    WHERE DATE(date) = $1 
                    ORDER BY id DESC
                """
                results = await conn.fetch(query, date_obj)
            elif current_user.role == "user":
                date_obj = datetime.strptime(date, '%Y-%m-%d').date()
                query = """
                    SELECT url_original, url_processed, date 
                    FROM detections 
                    WHERE user_id = $1 AND DATE(date) = $2 
                    ORDER BY id DESC
                """
                results = await conn.fetch(query, current_user.id, date_obj)
            else:
                raise HTTPException(status_code=400, detail="Permissions required")
                
            return [dict(record) for record in results]
        finally:
            await conn.close()

    @staticmethod
    async def update_results_images_status(
        current_user: User, 
        detection_id: int, 
        positive: str
    ) -> bool:
        """Actualiza el estado de una imagen."""
        if current_user.role != "superadmin":
            raise HTTPException(status_code=400, detail="Permissions required")
            
        conn = await get_database_connection()
        try:
            query = "UPDATE detections SET positive = $1 WHERE id = $2"
            await conn.execute(query, positive, detection_id)
            return True
        finally:
            await conn.close()
