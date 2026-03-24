import asyncio
import base64
import glob
import ipaddress
import os
import shutil
import socket
import tempfile
import uuid
from datetime import datetime
from io import BytesIO
from typing import Any
from urllib.parse import urlparse

import cv2
import requests
from dotenv import load_dotenv
from fastapi import HTTPException
from PIL import Image

import models as mod
import utils

load_dotenv()

MODEL_EXTENSIONS = {".engine", ".onnx", ".pt", ".pth"}
MAX_DOWNLOAD_SIZE = 50 * 1024 * 1024
WEBP_QUALITY = int(os.getenv("WEBP_QUALITY", "80"))

loaded_models: dict[str, Any] = {}
model_load_errors: dict[str, str] = {}


def get_model_directory() -> str:
    configured_model = os.getenv("MODELO")
    if configured_model:
        configured_path = configured_model
        if not os.path.isabs(configured_path):
            configured_path = os.path.abspath(
                os.path.join(os.path.dirname(__file__), configured_path)
            )

        model_dir = os.path.dirname(configured_path)
        if os.path.isdir(model_dir):
            return model_dir

    return os.path.abspath(os.path.join(os.path.dirname(__file__), "model"))


def get_available_models() -> list[dict[str, str]]:
    model_dir = get_model_directory()
    if not os.path.isdir(model_dir):
        return []

    models = []
    for file_name in sorted(os.listdir(model_dir)):
        file_path = os.path.join(model_dir, file_name)
        _, extension = os.path.splitext(file_name)
        if not os.path.isfile(file_path) or extension.lower() not in MODEL_EXTENSIONS:
            continue
        models.append({"name": file_name, "path": file_path})

    return models


def get_default_model_name() -> str | None:
    configured_model = os.getenv("MODELO")
    if configured_model:
        configured_name = os.path.basename(configured_model)
        available_model_names = {model["name"] for model in get_available_models()}
        if configured_name in available_model_names:
            return configured_name

    available_models = get_available_models()
    if not available_models:
        return None

    return available_models[0]["name"]


def get_model_path(model_name: str | None = None) -> tuple[str, str]:
    selected_model_name = model_name or get_default_model_name()
    if not selected_model_name:
        raise RuntimeError(f"No se encontraron modelos en {get_model_directory()!r}")

    for model_info in get_available_models():
        if model_info["name"] == selected_model_name:
            return model_info["path"], model_info["name"]

    raise RuntimeError(f"No se encontro el modelo seleccionado: {selected_model_name}")


def get_model(model_name: str | None = None):
    model_path, normalized_model_name = get_model_path(model_name)

    if normalized_model_name in loaded_models:
        return loaded_models[normalized_model_name]

    if normalized_model_name in model_load_errors:
        raise RuntimeError(model_load_errors[normalized_model_name])

    try:
        from ultralytics import YOLO

        loaded_models[normalized_model_name] = YOLO(model_path)
        return loaded_models[normalized_model_name]
    except Exception as exc:
        model_load_errors[normalized_model_name] = (
            f"Error al cargar el modelo {normalized_model_name}: {exc}"
        )
        raise RuntimeError(model_load_errors[normalized_model_name]) from exc


def validate_image_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise HTTPException(status_code=400, detail="URL no permitida: esquema invalido")

    hostname = parsed.hostname
    if not hostname:
        raise HTTPException(status_code=400, detail="URL no permitida: hostname vacio")

    try:
        addr_infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise HTTPException(
            status_code=400,
            detail="URL no permitida: no se pudo resolver el hostname",
        ) from exc

    for addr_info in addr_infos:
        ip = ipaddress.ip_address(addr_info[4][0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            raise HTTPException(
                status_code=400,
                detail="URL no permitida: direccion IP restringida",
            )

    return True


async def procesar_imagen_multiple(
    imagenes: list[Any],
    confianza: float,
    iou: float,
    cpu: int,
    current_user: mod.User,
    model_name: str | None = None,
) -> list[dict[str, Any]]:
    count_detections = 0
    count_not_detections = 0
    processed_image_names: list[str] = []

    with tempfile.TemporaryDirectory() as temp_dir:
        for imagen in imagenes:
            image_path = await process_image_input(imagen, temp_dir)
            processed_image_names.append(os.path.basename(image_path))

        device = "cpu" if cpu == 1 else 0
        yolo_model = get_model(model_name)
        predictions = await asyncio.to_thread(
            yolo_model.predict,
            temp_dir,
            conf=confianza,
            iou=iou,
            save=True,
            project="./",
            name="Resultados",
            exist_ok=True,
            device=device,
            imgsz=(800, 480),
            augment=True,
        )

        detecciones = []
        for index, prediction in enumerate(predictions):
            deteccion, conf, original_file_name, processed_file_name = await process_prediction(
                prediction, temp_dir, processed_image_names[index]
            )
            now = datetime.now()

            if deteccion:
                count_detections += 1
                await utils.insert_detection(
                    current_user,
                    now,
                    original_file_name,
                    processed_file_name,
                    conf,
                )
            else:
                count_not_detections += 1

            detecciones.append(
                {
                    "detection": deteccion,
                    "conf": float(conf) if deteccion else None,
                    "procesada": processed_file_name if deteccion else None,
                    "original": original_file_name if deteccion else None,
                    "fecha": now.date().isoformat(),
                    "hora": now.time().isoformat() if deteccion else None,
                }
            )

        await utils.insert_results(
            current_user,
            "multiples",
            count_detections,
            count_not_detections,
        )
        return detecciones


async def process_image_input(imagen: Any, temp_dir: str) -> str:
    try:
        if isinstance(imagen, str) and imagen.startswith("http"):
            validate_image_url(imagen)
            if not utils.es_extension_permitida(imagen):
                raise ValueError(
                    "La URL no corresponde a una imagen con extension permitida."
                )

            response = await asyncio.to_thread(requests.get, imagen, timeout=15)
            response.raise_for_status()

            if len(response.content) > MAX_DOWNLOAD_SIZE:
                raise ValueError("La imagen descargada excede el limite de 50MB.")

            ext = os.path.splitext(urlparse(imagen).path)[1].lower() or ".jpg"
            image_path = os.path.join(temp_dir, f"{uuid.uuid4().hex}{ext}")

            def _write_downloaded_file() -> None:
                with open(image_path, "wb") as buffer:
                    buffer.write(response.content)

            await asyncio.to_thread(_write_downloaded_file)
            return image_path

        if isinstance(imagen, str):
            image_data = base64.b64decode(imagen)
            image = Image.open(BytesIO(image_data))
            image_filename = f"image_{uuid.uuid4().hex}.webp"
            image_path = os.path.join(temp_dir, image_filename)
            await asyncio.to_thread(image.save, image_path, "WEBP")
            return image_path

        if not utils.validar_extension(imagen.filename):
            raise ValueError("Formato de imagen no soportado.")

        original_ext = os.path.splitext(os.path.basename(imagen.filename))[1].lower()
        safe_filename = f"{uuid.uuid4().hex}{original_ext}"
        image_path = os.path.join(temp_dir, safe_filename)

        def _copy_file() -> None:
            with open(image_path, "wb") as buffer:
                shutil.copyfileobj(imagen.file, buffer)

        await asyncio.to_thread(_copy_file)
        return image_path
    except HTTPException:
        raise
    except Exception as exc:
        raise Exception(f"Error al procesar la entrada de imagen: {exc}") from exc


async def process_prediction(
    prediction: Any,
    temp_dir: str,
    image_name: str,
) -> tuple[bool, float | None, str | None, str | None]:
    try:
        boxes = prediction.boxes.cpu().numpy()
        if boxes.conf.size == 0:
            return False, None, None, None

        conf = round(float(boxes.conf.max()), 2)
        original_file_name, processed_file_name = await save_processed_images(
            temp_dir,
            image_name,
            prediction.save_dir,
        )
        return True, conf, original_file_name, processed_file_name
    except Exception as exc:
        raise Exception(f"Error al procesar la prediccion: {exc}") from exc


def find_processed_image_path(save_dir: str, image_name: str) -> str:
    image_stem, _ = os.path.splitext(image_name)
    matching_files = sorted(glob.glob(os.path.join(save_dir, f"{image_stem}.*")))
    if not matching_files:
        raise FileNotFoundError(
            f"No se encontro la imagen procesada para {image_name!r} en {save_dir!r}"
        )

    return matching_files[0]


async def save_processed_images(
    temp_dir: str,
    image_name: str,
    save_dir: str,
) -> tuple[str, str]:
    try:
        os.makedirs("./Original", exist_ok=True)
        os.makedirs("./Resultados", exist_ok=True)

        image_stem, _ = os.path.splitext(image_name)
        original_input = os.path.join(temp_dir, image_name)
        processed_input = find_processed_image_path(save_dir, image_name)

        original_file_name = f"original_{image_stem}.webp"
        processed_file_name = f"{image_stem}.webp"

        original_output = os.path.join("./Original", original_file_name)
        processed_output = os.path.join("./Resultados", processed_file_name)

        original_image = await asyncio.to_thread(cv2.imread, original_input)
        await asyncio.to_thread(
            cv2.imwrite,
            original_output,
            original_image,
            [cv2.IMWRITE_WEBP_QUALITY, WEBP_QUALITY],
        )

        processed_image = await asyncio.to_thread(cv2.imread, processed_input)
        await asyncio.to_thread(
            cv2.imwrite,
            processed_output,
            processed_image,
            [cv2.IMWRITE_WEBP_QUALITY, WEBP_QUALITY],
        )

        if os.path.exists(processed_input):
            os.remove(processed_input)
        return original_file_name, processed_file_name
    except Exception as exc:
        raise Exception(f"Error al guardar las imagenes: {exc}") from exc
