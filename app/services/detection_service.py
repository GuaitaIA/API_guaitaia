# File: app/services/detection_service.py
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
        # Crear directorios necesarios al inicializar
        self._ensure_directories_exist()

    def _ensure_directories_exist(self):
        """Asegura que los directorios necesarios existan."""
        directories = ["Original", "Resultados"]
        for directory in directories:
            os.makedirs(directory, exist_ok=True)

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
                    # Asegurarse de que los nombres de archivo para la base de datos
                    # no tengan doble extensión y apunten a los archivos finales
                    original_db_name = f"original_{os.path.splitext(processed_image_names[index])[0]}.webp"
                    processed_db_name = f"{os.path.splitext(processed_image_names[index])[0]}.webp"
                    await self._insert_detection(current_user, datetime.now(), original_db_name, processed_db_name, conf)
                else:
                    count_not_detections += 1

                detections.append({
                    "detection": detection,
                    "conf": float(conf) if detection else None,
                    "procesada": f"{os.path.splitext(processed_image_names[index])[0]}.webp" if detection else None,
                    "original": f"original_{os.path.splitext(processed_image_names[index])[0]}.webp" if detection else None,
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
                # Guardar como WEBP en el temp_dir para que YOLO lo procese
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
                # Pasa la ruta donde YOLO guardó la imagen procesada
                await self._save_processed_images(temp_dir, image_name, prediction.save_dir)
                return True, conf
            else:
                return False, None
        except Exception as e:
            raise Exception(f"Error al procesar la predicción: {e}")

    async def _save_processed_images(self, temp_dir, image_name, yolo_save_dir):
        """Guarda las imágenes originales y procesadas en formato WEBP."""
        try:
            # Asegurar que los directorios existan
            os.makedirs("Original", exist_ok=True)
            os.makedirs("Resultados", exist_ok=True)
            
            # Normalizar la ruta del directorio de YOLO
            yolo_save_dir = os.path.normpath(yolo_save_dir)
            
            # Buscar la imagen procesada por YOLO
            yolo_processed_image_path = None
            
            # YOLO puede guardar con diferentes extensiones, buscar la imagen
            base_name = os.path.splitext(image_name)[0]
            possible_extensions = ['.jpg', '.jpeg', '.png', '.webp', '.bmp']
            
            for ext in possible_extensions:
                potential_path = os.path.join(yolo_save_dir, f"{base_name}{ext}")
                if os.path.exists(potential_path):
                    yolo_processed_image_path = potential_path
                    break
            
            # Si no encuentra con el nombre base, buscar con el nombre completo
            if yolo_processed_image_path is None:
                for ext in possible_extensions:
                    potential_path = os.path.join(yolo_save_dir, f"{image_name}")
                    if os.path.exists(potential_path):
                        yolo_processed_image_path = potential_path
                        break
            
            # Si aún no encuentra, listar archivos en el directorio para debug
            if yolo_processed_image_path is None:
                if os.path.exists(yolo_save_dir):
                    files_in_dir = os.listdir(yolo_save_dir)
                    # Buscar cualquier archivo que contenga el nombre base
                    for file in files_in_dir:
                        if base_name in file or image_name in file:
                            yolo_processed_image_path = os.path.join(yolo_save_dir, file)
                            break
                
                if yolo_processed_image_path is None:
                    raise Exception(f"No se encontró la imagen procesada por YOLO. Directorio: {yolo_save_dir}, Archivos: {files_in_dir if 'files_in_dir' in locals() else 'Directorio no existe'}")

            # Guardar imagen original
            original_image_path_temp = os.path.join(temp_dir, image_name)
            image_original = cv2.imread(original_image_path_temp)
            if image_original is None:
                raise Exception(f"No se pudo leer la imagen original temporal: {original_image_path_temp}")

            # Asegura que el nombre del archivo original guardado tenga la extensión .webp
            original_save_filename = f"original_{os.path.splitext(image_name)[0]}.webp"
            original_save_path = os.path.join("Original", original_save_filename)
            cv2.imwrite(
                original_save_path,
                image_original,
                [cv2.IMWRITE_WEBP_QUALITY, settings.webp_quality]
            )

            # Guardar imagen procesada
            # Lee la imagen que YOLO guardó
            processed_image = cv2.imread(yolo_processed_image_path)
            if processed_image is None:
                raise Exception(f"No se pudo leer la imagen procesada por YOLO: {yolo_processed_image_path}")

            # Determina el nombre final para la imagen procesada (ej. OIP.webp, no OIP.webp.webp)
            processed_save_filename = f"{os.path.splitext(image_name)[0]}.webp"
            processed_save_path = os.path.join("Resultados", processed_save_filename)

            cv2.imwrite(
                processed_save_path,
                processed_image,
                [cv2.IMWRITE_WEBP_QUALITY, settings.webp_quality]
            )

            # Eliminar el archivo temporal generado por YOLO
            if os.path.exists(yolo_processed_image_path):
                os.remove(yolo_processed_image_path)

        except Exception as e:
            raise Exception(f"Error al guardar las imágenes: {e}")

    def _validate_extension(self, filename: str) -> bool:
        """Valida la extensión de un archivo."""
        try:
            # os.path.splitext devuelve una tupla (root, ext)
            # ext incluye el punto, por ejemplo '.jpg'
            _, extension = os.path.splitext(filename)
            return extension.lower().lstrip('.') in settings.allowed_extensions
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
