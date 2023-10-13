from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from datetime import datetime
from PIL import Image
from typing import List

import funcs as fc 

app = FastAPI()

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


@app.post("/detectar_incendio/")
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


@app.post("/detectar_incendios_multiples/")
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
