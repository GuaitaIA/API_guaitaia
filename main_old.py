from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from datetime import datetime
from PIL import Image
from typing import List

import funcs as fc 

tags_metadata = [
    {
        "name": "Individual detection",
        "description": "Process images individually."
    },
    {
        "name": "Multiple detection",
        "description": "Process images multiple ways."
    },
]

app = FastAPI(
    title="GuaitaIA",
    description="AI smoke plume detection in the forest",
    version="0.0.1 beta",
    openapi_tags=tags_metadata
)

EXTENSIONES_PERMITIDAS = {"jpg", "jpeg", "png"}

def validar_extension(filename: str) -> bool:
    try:
        nombre, extension = filename.rsplit('.', 1)
        return extension.lower() in EXTENSIONES_PERMITIDAS
    except ValueError:
        return False

# Configuración de CORS
origins = [
    "*"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.mount("/imagenes", StaticFiles(directory="Resultados"), name="imagenes")


@app.post(
    "/detectar_incendio/", 
    tags=["Individual detection"],
    responses={
        # 404: {"model": Message, "description": "The item was not found"},
        200: {
            "description": "Item requested by ID",
            "content": {
                "application/json": {
                    "example": {
                        "detecciones": True,
                        "confianza": 0.8399999737739563,
                        "imagen_procesada": "tmpyoaewshv.jpg",
                        "fecha": "2023-10-19",
                        "hora": "09:33:40.461835",
                        "GPU": 1
                    }
                }
            },
        },
    },
)
async def detectar_incendio(
    imagen: UploadFile = File(...),
    confianza: float = Form(...),
    iou: float = Form(...),
    cpu: int = Form(...)
):
    if not validar_extension(imagen.filename):
        raise HTTPException(status_code=400, detail="Formato de imagen no permitido")

    try:
        image = Image.open(imagen.file)
        detecciones, valor_confianza, nombre_resultado = fc.procesar_imagen(image, confianza, iou, cpu)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar la imagen: {e}")

    ahora = datetime.now()
 
    return {
        "detecciones": detecciones,
        "confianza": valor_confianza,
        "imagen_procesada": nombre_resultado,
        "fecha": ahora.date().isoformat(),
        "hora": ahora.time().isoformat(),
        "GPU": cpu,
    }


@app.post("/detectar_incendios_multiples/", tags=["Multiple detection"])
async def detectar_incendios_multiples(
    imagenes: List[UploadFile] = File(...),
    confianza: float = Form(...),
    iou: float = Form(...),
    cpu: int = Form(...)
):
    for imagen in imagenes:
        if not validar_extension(imagen.filename):
            raise HTTPException(status_code=400, detail="Formato de imagen no permitido")
    
    try:
        detecciones, valor_confianza, nombres_resultados = fc.procesar_imagen2(imagenes, confianza, iou, cpu)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al procesar las imágenes: {e}")

    ahora = datetime.now()

    return {
        "detecciones": detecciones,
        "confianza": valor_confianza,
        "imagenes_procesadas": nombres_resultados,
        "fecha": ahora.date().isoformat(),
        "hora": ahora.time().isoformat(),
        "GPU": cpu,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
