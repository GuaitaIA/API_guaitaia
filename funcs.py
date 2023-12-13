# Importaciones de librerías estándar de Python
import json  # Para manejar datos en formato JSON
import os  # Para interactuar con el sistema operativo
from datetime import datetime  # Para manejar fechas y horas
import uuid  # Para generar IDs únicos
from typing import List, Tuple, Any  # Para tipado estático
from io import BytesIO  # Para manejo de operaciones de entrada y salida basadas en bytes

# Importaciones para manejo de imágenes
import cv2  # Para operaciones de visión por computadora
from PIL import Image  # Para manejo de imágenes
import base64  # Para decodificar base64

# Importaciones de terceros
from ultralytics import YOLO  # Librería de detección de objetos YOLO
import requests  # Para realizar peticiones HTTP

# Importaciones de manejo de archivos temporales
import tempfile  # Para la creación de archivos temporales
import shutil  # Para operaciones de manejo de archivos de alto nivel

# Importaciones de manejo de variables de entorno
# Para cargar las variables de entorno del archivo .env
from dotenv import load_dotenv

# Importaciones locales o personalizadas
import models as mod  # Módulo local para base de datos
import utils  # Módulo local de utilidades

# Carga de variables de entorno desde un archivo .env
load_dotenv()


# Cargar el modelo YOLO
try:
    model = YOLO(os.getenv("MODELO"))
except Exception as e:
    raise Exception(f"Error al cargar el modelo: {e}")


# Constantes para la calidad de imagen WEBP
WEBP_QUALITY = int(os.getenv("WEBP_QUALITY"))


async def procesar_imagen_multiple(imagenes: List[Any], confianza: float, iou: float, cpu: int, current_user: mod.User) -> Tuple[List[bool], List[float], List[str]]:
    """
    Procesa múltiples imágenes para detección de objetos.

    Args:
    - imagenes: Lista de imágenes en diferentes formatos (URL, base64, archivo).
    - confianza: Umbral de confianza para la detección de objetos.
    - iou: Umbral de Intersection Over Union para la detección.
    - cpu: Flag para indicar si se utiliza la CPU o no.
    - current_user: Objeto de usuario actual.

    Returns:
    - Una tupla de listas con booleans de detección, confianzas y nombres de imágenes procesadas.
    """

    # Inicialización de contadores para estadísticas de detección
    countDetections = 0
    countNotDetections = 0
    processed_image_names = []

    # Usar un directorio temporal para trabajar con las imágenes
    with tempfile.TemporaryDirectory() as temp_dir:
        for imagen in imagenes:
            image_path = await process_image_input(imagen, temp_dir)
            processed_image_names.append(os.path.basename(image_path))

        # Determinar el dispositivo de procesamiento basado en la entrada del usuario
        device = "cpu" if cpu == 1 else 0

        # Llamada al modelo de predicción con las imágenes procesadas
        predictions = model.predict(temp_dir, conf=confianza, iou=iou, save=True, project="./",
                                    name="Resultados", exist_ok=True, device=device, imgsz=(800, 480), augment=True)

        # Lista para almacenar los resultados de las detecciones
        detecciones = []

        for index, prediction in enumerate(predictions):
            deteccion, conf = await process_prediction(prediction, temp_dir, processed_image_names[index])
            if deteccion:
                countDetections += 1
                
                original = "original_" + \
                processed_image_names[index] + ".webp"
                procesada = processed_image_names[index] + ".webp"
                await utils.insert_detection(current_user, datetime.now(), original, procesada, conf)
            else:
                countNotDetections += 1

            detecciones.append({
                "detection": deteccion,
                "conf": float(conf) if deteccion else None,
                "procesada": processed_image_names[index] + ".webp" if deteccion else None,
                "original": "original_" + processed_image_names[index] + ".webp" if deteccion else None,
                "fecha": str(datetime.now().date().isoformat()),
                "hora": str(datetime.now().time().isoformat()) if deteccion else None
            })

        # Registrar los resultados en la base de datos
        await utils.insert_results(current_user, 'multiples', countDetections, countNotDetections)

        # Convertir la lista 'detecciones' en una cadena JSON
        return json.dumps(detecciones)


async def process_image_input(imagen, temp_dir):
    """
    Procesa la entrada de la imagen para determinar si es una URL, una cadena base64 o un archivo.
    Guarda la imagen en un directorio temporal en formato WEBP.

    Args:
    - imagen: La imagen a procesar.
    - temp_dir: El directorio temporal donde se guardará la imagen.

    Returns:
    - La ruta al archivo de la imagen procesada.
    """
    try:
        if isinstance(imagen, str) and imagen.startswith('http'):
            # Si es una URL, descargar y guardar la imagen
            if utils.es_extension_permitida(imagen):
                response = requests.get(imagen)
                image_path = os.path.join(temp_dir, os.path.basename(imagen))
                with open(image_path, "wb") as buffer:
                    buffer.write(response.content)
            else:
                raise ValueError(
                    "La URL no corresponde a una imagen con extensión permitida.")

        elif isinstance(imagen, str) and not imagen.startswith('http'):
            # Si es una cadena base64, decodificar y guardar la imagen
            image_data = base64.b64decode(imagen)
            image = Image.open(BytesIO(image_data))
            image_filename = f"image_{uuid.uuid4()}.webp"
            image_path = os.path.join(temp_dir, image_filename)
            image.save(image_path, 'WEBP')
        else:
            # Si es un archivo, validar y copiar al directorio temporal
            if utils.validar_extension(imagen.filename):
                image_path = os.path.join(temp_dir, imagen.filename)
                with open(image_path, "wb") as buffer:
                    shutil.copyfileobj(imagen.file, buffer)
            else:
                raise ValueError("Formato de imagen no soportado.")
        return image_path
    except Exception as e:
        raise Exception(f"Error al procesar la entrada de imagen: {e}")


async def process_prediction(prediction, temp_dir, image_name):
    """
    Procesa la predicción hecha por el modelo para cada imagen.

    Args:
    - prediction: La predicción retornada por el modelo.
    - temp_dir: El directorio temporal donde se guarda la imagen original.
    - image_name: El nombre de la imagen procesada.

    Returns:
    - Un booleano que indica si hubo detección y la confianza de la detección.
    """
    try:
        boxes = prediction.boxes.cpu().numpy()
        if boxes.conf.size > 0:
            # Si hay detección, procesar y guardar la imagen resultante
            conf = round(boxes.conf[0], 2)
            await save_processed_images(temp_dir, image_name)
            return True, conf
        else:
            # Si no hay detección, retornar False
            return False, None
    except Exception as e:
        raise Exception(f"Error al procesar la predicción: {e}")


async def save_processed_images(temp_dir, image_name):
    """
    Guarda las imágenes originales y procesadas en formato WEBP.

    Args:
    - temp_dir: El directorio temporal donde se guardan las imágenes.
    - image_name: El nombre de la imagen procesada.
    """
    try:
        # Guardar la imagen original
        image = cv2.imread(os.path.join(temp_dir, image_name))
        cv2.imwrite(os.path.join("./", "Original", f"original_{image_name}.webp"), image, [
                    cv2.IMWRITE_WEBP_QUALITY, WEBP_QUALITY])

        # Guardar la imagen procesada
        processed_image = cv2.imread(
            os.path.join("./", "Resultados", image_name))
        cv2.imwrite(os.path.join("./", "Resultados",
                    f"{image_name}.webp"), processed_image, [cv2.IMWRITE_WEBP_QUALITY, WEBP_QUALITY])
        os.remove(os.path.join("./", "Resultados", image_name))
    except Exception as e:
        raise Exception(f"Error al guardar las imágenes: {e}")
