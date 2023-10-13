from ultralytics import YOLO
from dotenv import load_dotenv
import os
from PIL import Image
import tempfile
import shutil
from typing import List, Tuple, Any
from fastapi import UploadFile


# Cargar variables de entorno
load_dotenv()

# Cargar el modelo YOLO
try:
    model = YOLO(os.getenv("MODEL"))
except Exception as e:
    raise Exception(f"Error al cargar el modelo: {e}")

def procesar_imagen(imagen: Image.Image, confianza: float, iou: float, cpu: int) -> tuple:
    try:
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as temp_file:
            imagen.save(temp_file.name)
            input_image = Image.open(temp_file.name)
            
            device = "cpu" if cpu == 1 else None
            
            results = model.predict(input_image, conf=confianza, iou=iou, save=True, project="./", name="Resultados", exist_ok=True, device=device)
            results = results[0].boxes.numpy()

        if results.conf.size > 0:
            conf = round(results.conf[0], 2)
            deteccion = True
            procesada = os.path.basename(temp_file.name)
        else:
            conf = 0
            deteccion = False
            procesada = os.path.basename(temp_file.name)

        return deteccion, float(conf), procesada  # Aquí devolvemos la ruta a la imagen procesada

    except Exception as e:
        raise Exception(f"Error al procesar la imagen: {e}")

    finally:
        if os.path.exists(temp_file.name):
            os.remove(temp_file.name)
            
def procesar_imagen2(imagenes: List[Any], confianza: float, iou: float, cpu: int) -> Tuple[List[bool], List[float], List[str]]:
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            processed_image_names = []
            for imagen in imagenes:
                image_path = os.path.join(temp_dir, imagen.filename)
                with open(image_path, "wb") as buffer:
                    shutil.copyfileobj(imagen.file, buffer)
                processed_image_names.append(os.path.basename(image_path))

            device = "cpu" if cpu == 1 else None

            # Procesar todas las imágenes en el directorio temporal de una vez
            results = model.predict(temp_dir, conf=confianza, iou=iou, save=True, project="./", name="Resultados", exist_ok=True, device=device)
            
            detecciones = []
            confs = []

            for res in results:
                boxes = res.boxes.numpy()
                if boxes.conf.size > 0:
                    conf = round(boxes.conf[0], 2)
                    deteccion = True
                else:
                    conf = 0
                    deteccion = False
                detecciones.append(deteccion)
                confs.append(float(conf))

            return detecciones, confs, processed_image_names

    except Exception as e:
        raise Exception(f"Error al procesar las imágenes: {e}")