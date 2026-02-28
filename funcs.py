# Importaciones de librerias estandar de Python
import os  # Para interactuar con el sistema operativo
import asyncio  # Para operaciones asincronas
import logging  # Para registro de eventos
import socket  # Para resolucion de nombres de host
import ipaddress  # Para validacion de direcciones IP
import uuid  # Para generar IDs unicos
from datetime import datetime  # Para manejar fechas y horas
from typing import List, Tuple, Any  # Para tipado estatico
from io import BytesIO  # Para manejo de operaciones de entrada y salida basadas en bytes
from urllib.parse import urlparse  # Para parseo de URLs

# Importaciones para manejo de imagenes
import cv2  # Para operaciones de vision por computadora
from PIL import Image  # Para manejo de imagenes
import base64  # Para decodificar base64

# Importaciones de terceros
from ultralytics import YOLO  # Libreria de deteccion de objetos YOLO
import requests  # Para realizar peticiones HTTP
from fastapi import HTTPException  # Para excepciones HTTP

# Importaciones de manejo de archivos temporales
import tempfile  # Para la creacion de archivos temporales
import shutil  # Para operaciones de manejo de archivos de alto nivel

# Importaciones de manejo de variables de entorno
from dotenv import load_dotenv

# Importaciones locales o personalizadas
import models as mod  # Modulo local para base de datos
import utils  # Modulo local de utilidades

# Carga de variables de entorno desde un archivo .env
load_dotenv()

# Configurar logger
logger = logging.getLogger(__name__)

# Cargar el modelo YOLO
try:
    model = YOLO(os.getenv("MODELO"))
except Exception as e:
    raise Exception(f"Error al cargar el modelo: {e}")


# Constantes para la calidad de imagen WEBP
WEBP_QUALITY = int(os.getenv("WEBP_QUALITY"))

# Limite maximo de descarga (50 MB)
MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024


def validate_image_url(url: str) -> bool:
    """
    Valida que una URL de imagen no apunte a recursos internos (SSRF protection).

    Args:
    - url: La URL a validar.

    Returns:
    - True si la URL es segura.

    Raises:
    - HTTPException: Si la URL apunta a una IP privada, loopback o link-local.
    """
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="URL no permitida: esquema invalido")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="URL no permitida: hostname vacio")

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail="URL no permitida: no se pudo resolver el hostname")

    for addr_info in addr_infos:
        ip = ipaddress.ip_address(addr_info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise HTTPException(status_code=400, detail="URL no permitida: direccion IP restringida")

    return True


async def procesar_imagen_multiple(imagenes: List[Any], confianza: float, iou: float, cpu: int, current_user: mod.User) -> List[dict]:
    """
    Procesa multiples imagenes para deteccion de objetos.

    Args:
    - imagenes: Lista de imagenes en diferentes formatos (URL, base64, archivo).
    - confianza: Umbral de confianza para la deteccion de objetos.
    - iou: Umbral de Intersection Over Union para la deteccion.
    - cpu: Flag para indicar si se utiliza la CPU o no.
    - current_user: Objeto de usuario actual.

    Returns:
    - Una lista de diccionarios con los resultados de cada deteccion.
    """

    logger.info("Inicio de procesamiento de %d imagenes para usuario %s", len(imagenes), current_user.email)

    # Inicializacion de contadores para estadisticas de deteccion
    countDetections = 0
    countNotDetections = 0
    processed_image_names = []

    # Usar un directorio temporal para trabajar con las imagenes
    with tempfile.TemporaryDirectory() as temp_dir:
        for imagen in imagenes:
            image_path = await process_image_input(imagen, temp_dir)
            processed_image_names.append(os.path.basename(image_path))

        # Determinar el dispositivo de procesamiento basado en la entrada del usuario
        device = "cpu" if cpu == 1 else 0

        # Llamada al modelo de prediccion con las imagenes procesadas (no bloqueante)
        predictions = await asyncio.to_thread(
            model.predict, temp_dir, conf=confianza, iou=iou, save=True, project="./",
            name="Resultados", exist_ok=True, device=device, imgsz=(800, 480), augment=True
        )

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

        logger.info("Procesamiento completado: %d detecciones, %d sin deteccion", countDetections, countNotDetections)

        # Retornar la lista directamente (FastAPI la serializa a JSON)
        return detecciones


async def process_image_input(imagen, temp_dir):
    """
    Procesa la entrada de la imagen para determinar si es una URL, una cadena base64 o un archivo.
    Guarda la imagen en un directorio temporal en formato WEBP.

    Args:
    - imagen: La imagen a procesar.
    - temp_dir: El directorio temporal donde se guardara la imagen.

    Returns:
    - La ruta al archivo de la imagen procesada.
    """
    try:
        if isinstance(imagen, str) and imagen.startswith('http'):
            # Validar URL contra SSRF
            validate_image_url(imagen)

            # Si es una URL, descargar y guardar la imagen
            if utils.es_extension_permitida(imagen):
                response = await asyncio.to_thread(requests.get, imagen, timeout=15)
                response.raise_for_status()

                if len(response.content) > MAX_DOWNLOAD_SIZE:
                    raise ValueError("La imagen descargada excede el limite de 50MB.")

                # Generar nombre seguro con UUID
                parsed_url = urlparse(imagen)
                ext = os.path.splitext(parsed_url.path)[1].lower()
                safe_filename = f"{uuid.uuid4().hex}{ext}"
                image_path = os.path.join(temp_dir, safe_filename)

                with open(image_path, "wb") as buffer:
                    buffer.write(response.content)
            else:
                raise ValueError(
                    "La URL no corresponde a una imagen con extension permitida.")

        elif isinstance(imagen, str) and not imagen.startswith('http'):
            # Si es una cadena base64, decodificar y guardar la imagen
            image_data = base64.b64decode(imagen)
            image = Image.open(BytesIO(image_data))
            image_filename = f"image_{uuid.uuid4().hex}.webp"
            image_path = os.path.join(temp_dir, image_filename)

            def _save_image():
                image.save(image_path, 'WEBP')

            await asyncio.to_thread(_save_image)
        else:
            # Si es un archivo, validar y copiar al directorio temporal
            if utils.validar_extension(imagen.filename):
                # Sanitizar filename: usar UUID + extension original
                original_ext = os.path.splitext(os.path.basename(imagen.filename))[1].lower()
                safe_filename = f"{uuid.uuid4().hex}{original_ext}"
                image_path = os.path.join(temp_dir, safe_filename)

                def _copy_file():
                    with open(image_path, "wb") as buffer:
                        shutil.copyfileobj(imagen.file, buffer)

                await asyncio.to_thread(_copy_file)
            else:
                raise ValueError("Formato de imagen no soportado.")
        return image_path
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error al procesar la entrada de imagen: %s", e)
        raise Exception(f"Error al procesar la entrada de imagen: {e}")


async def process_prediction(prediction, temp_dir, image_name):
    """
    Procesa la prediccion hecha por el modelo para cada imagen.

    Args:
    - prediction: La prediccion retornada por el modelo.
    - temp_dir: El directorio temporal donde se guarda la imagen original.
    - image_name: El nombre de la imagen procesada.

    Returns:
    - Un booleano que indica si hubo deteccion y la confianza de la deteccion.
    """
    try:
        boxes = prediction.boxes.cpu().numpy()
        if boxes.conf.size > 0:
            # Si hay deteccion, tomar la confianza maxima
            conf = round(float(boxes.conf.max()), 2)
            await save_processed_images(temp_dir, image_name)
            return True, conf
        else:
            # Si no hay deteccion, retornar False
            return False, None
    except Exception as e:
        logger.error("Error al procesar la prediccion: %s", e)
        raise Exception(f"Error al procesar la prediccion: {e}")


async def save_processed_images(temp_dir, image_name):
    """
    Guarda las imagenes originales y procesadas en formato WEBP.

    Args:
    - temp_dir: El directorio temporal donde se guardan las imagenes.
    - image_name: El nombre de la imagen procesada.
    """
    try:
        # Guardar la imagen original
        original_path = os.path.join(temp_dir, image_name)
        image = await asyncio.to_thread(cv2.imread, original_path)

        original_output = os.path.join("./", "Original", f"original_{image_name}.webp")
        await asyncio.to_thread(
            cv2.imwrite, original_output, image,
            [cv2.IMWRITE_WEBP_QUALITY, WEBP_QUALITY]
        )

        # Guardar la imagen procesada
        processed_input = os.path.join("./", "Resultados", image_name)
        processed_image = await asyncio.to_thread(cv2.imread, processed_input)

        processed_output = os.path.join("./", "Resultados", f"{image_name}.webp")
        await asyncio.to_thread(
            cv2.imwrite, processed_output, processed_image,
            [cv2.IMWRITE_WEBP_QUALITY, WEBP_QUALITY]
        )

        os.remove(os.path.join("./", "Resultados", image_name))
    except Exception as e:
        logger.error("Error al guardar las imagenes: %s", e)
        raise Exception(f"Error al guardar las imagenes: {e}")
