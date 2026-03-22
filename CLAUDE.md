# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GuaitaIA - API REST con FastAPI para detección de humo de incendios forestales usando YOLO (modelo ONNX). Python 3.8+, PostgreSQL, autenticación JWT con control de acceso por roles y horarios.

## Common Commands

```bash
# Instalar dependencias
pip install -r requirements.txt

# Iniciar servidor de desarrollo
uvicorn main:app --host 0.0.0.0 --port 8000 --reload

# Iniciar PostgreSQL y pgAdmin con Docker
docker-compose up -d

# Migraciones de base de datos
alembic upgrade head                          # Aplicar todas las migraciones
alembic revision --autogenerate -m "mensaje"  # Generar nueva migración
alembic downgrade -1                          # Revertir última migración
```

**No hay test suite configurado.**

## Architecture

El proyecto es un monolito de 4 archivos Python principales:

- **main.py** — App FastAPI, definición de endpoints, configuración CORS y montaje de archivos estáticos. Todos los endpoints están aquí.
- **utils.py** — Operaciones de base de datos (asyncpg), autenticación JWT, funciones de estadísticas y CRUD de usuarios.
- **funcs.py** — Pipeline de procesamiento de imágenes: acepta archivos/URLs/base64, ejecuta inferencia YOLO, guarda resultados como WEBP.
- **models.py** — Modelos SQLAlchemy (User, para Alembic) y Pydantic (Token, TokenData).

### Database

PostgreSQL con 4 tablas gestionadas por Alembic (`alembic/versions/`):
- **users** — Autenticación, roles (superadmin/user), FK a zones
- **zones** — Zonas horarias con horas de inicio/fin para control de acceso temporal
- **results** — Estadísticas agregadas de detecciones por usuario/fecha
- **detections** — Registros individuales de detección con URLs de imágenes y confianza

Las conexiones async usan asyncpg directamente (no SQLAlchemy async). SQLAlchemy solo se usa para Alembic.

### Authentication Flow

OAuth2 Password Bearer → JWT (HS256). Tres niveles de dependencia en endpoints:
1. `get_current_active_user` — Usuario autenticado y activo
2. `get_current_user_is_superadmin` — Solo superadmin
3. `get_current_user_time` — Usuario activo + dentro de horario permitido (zona horaria)

### Image Processing Pipeline (funcs.py)

`procesar_imagen_multiple()` es la función central:
1. Recibe imágenes (UploadFile, URL http, o base64)
2. Ejecuta YOLO con umbrales de confianza e IoU configurables
3. Guarda originales y procesadas en formato WEBP (calidad configurable via `WEBP_QUALITY`)
4. Inserta detecciones en BD y retorna JSON con resultados

Las imágenes procesadas se sirven como estáticos: `/imagenes` → `./Resultados/`, `/imagenes_original` → `./Original/`.

## Configuration

Variables de entorno en `.env` (ver `env.txt` como plantilla):
- `MODELO` — Ruta al modelo YOLO ONNX (e.g., `./model/guaitaia2.onnx`)
- `SECRET_KEY`, `ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES` — Config JWT
- `DB_USER`, `DB_PASSWORD`, `DB_DATABASE`, `DB_HOST`, `DB_PORT` — Conexión asyncpg
- `SQLALCHEMY_DATABASE_URL` — Conexión para Alembic
- `WEBP_QUALITY` — Calidad de compresión WEBP (0-100)

La cadena de conexión en `alembic.ini` debe coincidir con las variables de BD del `.env`.

## Key Conventions

- Idioma del proyecto: español (documentación, comentarios, nombres de endpoints)
- Las extensiones de imagen permitidas son: jpg, jpeg, png, webp
- El token de expiración se calcula en **semanas** (no minutos, pese al nombre de la variable)
- El usuario superadmin inicial se crea en la migración `4f86c2991b06` con email `admin@admin.com`
- Docker Compose expone PostgreSQL en puerto 5432 y pgAdmin en 8888
