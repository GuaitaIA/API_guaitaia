# app/services/detection_service.py
import json
import os
import tempfile
import shutil
import uuid
from datetime import datetime
from typing import List, Any, Tuple
from io import BytesIO
import base64
import requests
import cv2
from PIL import Image
from ultralytics import YOLO

from app.core.config import settings
from app.core.database import get_database_connection
from app.models.user import User
from app.schemas.detection import DetectionResponse

class DetectionService:
    def __init__(self):
        self.model = self._load_model()

    def _load_model(self):
        """Carga el modelo YOLO."""
        try:
            return YOLO(settings.model_path)
        except Exception as e:
            raise Exception(f"Error al cargar el modelo: {e}")

    async def process_multiple_images(
        self, 
        images: List[Any], 
        confidence: float, 
        iou: float, 
        use_cpu: bool,
        current_user: User
    ) -> str:
        """Procesa múltiples imágenes para detección de objetos."""
        count_detections = 0
        count_not_detections = 0
        processed_image_names = []

        with tempfile.TemporaryDirectory() as temp_dir:
            # Procesar cada imagen de entrada
            for image in images:
                image_path = await self._process_image_input(image, temp_dir)
                processed_image_names.append(os.path.basename(image_path))

            # Determinar dispositivo de procesamiento
            device = "cpu" if use_cpu else 0

            # Ejecutar predicciones
            predictions = self.model.predict(
                temp_dir, 
                conf=confidence, 
                iou=iou, 
                save=True, 
                project="./",
                name="Resultados", 
                exist_ok=True, 
                device=device, 
                imgsz=(960, 960), 
                augment=True
            )

            # Procesar resultados
            detections = []
            for index, prediction in enumerate(predictions):
                detection, conf = await self._process_prediction(
                    prediction, temp_dir, processed_image_names[index]
                )
                
                if detection:
                    count_detections += 1
                    original = f"original_{processed_image_names[index]}.webp"
                    processed = f"{processed_image_names[index]}.webp"
                    await self._insert_detection(current_user, datetime.now(), original, processed, conf)
                else:
                    count_not_detections += 1

                detections.append({
                    "detection": detection,
                    "conf": float(conf) if detection else None,
                    "procesada": f"{processed_image_names[index]}.webp" if detection else None,
                    "original": f"original_{processed_image_names[index]}.webp" if detection else None,
                    "fecha": str(datetime.now().date().isoformat()),
                    "hora": str(datetime.now().time().isoformat()) if detection else None
                })

            # Registrar resultados en la base de datos
            await self._insert_results(current_user, 'multiples', count_detections, count_not_detections)

            return json.dumps(detections)

    async def _process_image_input(self, image, temp_dir):
        """Procesa la entrada de imagen (URL, base64 o archivo)."""
        try:
            if isinstance(image, str) and image.startswith('http'):
                # URL
                if self._is_allowed_extension_url(image):
                    response = requests.get(image)
                    image_path = os.path.join(temp_dir, os.path.basename(image))
                    with open(image_path, "wb") as buffer:
                        buffer.write(response.content)
                else:
                    raise ValueError("La URL no corresponde a una imagen con extensión permitida.")
            
            elif isinstance(image, str) and not image.startswith('http'):
                # Base64
                image_data = base64.b64decode(image)
                pil_image = Image.open(BytesIO(image_data))
                image_filename = f"image_{uuid.uuid4()}.webp"
                image_path = os.path.join(temp_dir, image_filename)
                pil_image.save(image_path, 'WEBP')
            
            else:
                # Archivo
                if self._validate_extension(image.filename):
                    image_path = os.path.join(temp_dir, image.filename)
                    with open(image_path, "wb") as buffer:
                        shutil.copyfileobj(image.file, buffer)
                else:
                    raise ValueError("Formato de imagen no soportado.")
            
            return image_path
        except Exception as e:
            raise Exception(f"Error al procesar la entrada de imagen: {e}")

    async def _process_prediction(self, prediction, temp_dir, image_name):
        """Procesa la predicción del modelo."""
        try:
            boxes = prediction.boxes.cpu().numpy()
            if boxes.conf.size > 0:
                conf = round(boxes.conf[0], 2)
                await self._save_processed_images(temp_dir, image_name)
                return True, conf
            else:
                return False, None
        except Exception as e:
            raise Exception(f"Error al procesar la predicción: {e}")

    async def _save_processed_images(self, temp_dir, image_name):
        """Guarda las imágenes originales y procesadas en formato WEBP."""
        try:
            # Guardar imagen original
            image = cv2.imread(os.path.join(temp_dir, image_name))
            cv2.imwrite(
                os.path.join("./", "Original", f"original_{image_name}.webp"), 
                image, 
                [cv2.IMWRITE_WEBP_QUALITY, settings.webp_quality]
            )

            # Guardar imagen procesada
            processed_image = cv2.imread(os.path.join("./", "Resultados", image_name))
            cv2.imwrite(
                os.path.join("./", "Resultados", f"{image_name}.webp"), 
                processed_image, 
                [cv2.IMWRITE_WEBP_QUALITY, settings.webp_quality]
            )
            os.remove(os.path.join("./", "Resultados", image_name))
        except Exception as e:
            raise Exception(f"Error al guardar las imágenes: {e}")

    def _validate_extension(self, filename: str) -> bool:
        """Valida la extensión de un archivo."""
        try:
            nombre, extension = filename.rsplit('.', 1)
            return extension.lower() in settings.allowed_extensions
        except ValueError:
            return False

    def _is_allowed_extension_url(self, url: str) -> bool:
        """Verifica si la extensión de archivo en una URL está permitida."""
        try:
            from urllib.parse import urlparse
            path = urlparse(url).path
            ext = os.path.splitext(path)[1].lstrip('.')
            return ext in settings.allowed_extensions
        except Exception:
            return False

    async def _insert_results(self, user: User, type_detection: str, detections: int, not_detections: int):
        """Inserta resultados de detecciones en la base de datos."""
        date_time = datetime.now()
        conn = await get_database_connection()
        try:
            query = """
                INSERT INTO results (user_id, date, type, detections, not_detections) 
                VALUES ($1, $2, $3, $4, $5)
            """
            await conn.execute(query, user.id, date_time, type_detection, detections, not_detections)
        finally:
            await conn.close()

    async def _insert_detection(self, user: User, date: datetime, url_original: str, url_processed: str, confidence: float):
        """Inserta un registro de detección en la base de datos."""
        conn = await get_database_connection()
        try:
            query = """
                INSERT INTO detections (user_id, date, url_original, url_processed, confidence) 
                VALUES ($1, $2, $3, $4, $5)
            """
            await conn.execute(query, user.id, date, url_original, url_processed, confidence)
        except Exception as e:
            raise Exception(f"Error al insertar detección en base de datos: {e}")
        finally:
            await conn.close()
