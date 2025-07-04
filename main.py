# app/main.py
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1.api import api_router
import os

# Directorios que deben existir
DIRECTORIES_TO_CREATE = ["Resultados", "Original"]

# Verificar y crear directorios si no existen
for directory in DIRECTORIES_TO_CREATE:
    if not os.path.exists(directory):
        os.makedirs(directory)
        print(f"Directorio '{directory}' creado exitosamente.")
    else:
        print(f"Directorio '{directory}' ya existe.")

# Metadatos para etiquetas utilizadas en la documentación de la API OpenAPI
tags_metadata = [
    {
        "name": "Authentication",
        "description": "Operaciones de autenticación para los usuarios."
    },
    {
        "name": "Users",
        "description": "Operaciones para crear y actualizar usuarios."
    },
    {
        "name": "Wildfire Detection",
        "description": "Procesar imágenes y vectores en formato base64 para la detección de incendios."
    },
    {
        "name": "Results",
        "description": "Obtener los resultados de las detecciones de incendios."
    }
]

# Inicializar la aplicación FastAPI
app = FastAPI(
    title=settings.project_name,
    description=settings.description,
    version=settings.version,
    openapi_tags=tags_metadata
)

# Lista de orígenes permitidos en la política CORS
origins = ["*"]

# Configuración del middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir el router de la API v1
app.include_router(api_router, prefix=settings.api_v1_str)

# Montar directorios estáticos
app.mount("/imagenes", StaticFiles(directory="Resultados"), name="imagenes_resultados")
app.mount("/imagenes_original", StaticFiles(directory="Original"), name="imagenes_originales")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
