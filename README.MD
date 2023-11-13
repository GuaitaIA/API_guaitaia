# GUAITA-IA

## Descripción General

Bienvenido al proyecto GUAITA-IA. Esta API utiliza el poder de YOLO (You Only Look Once) para el procesamiento de imágenes para la detección de incendios forestales. Mediante nuestra API, puedes analizar rápidamente imágenes para identificar potenciales incendios y contribuir a una respuesta rápida y eficaz.

## Primeros Pasos

Antes de comenzar con las capacidades de inferencia, deberás configurar tu entorno y configurar los archivos necesarios. Sigue los pasos a continuación para comenzar:

### Configuración del Entorno

1. Asegúrate de tener **Python 3.8+** instalado en tu sistema.
2. Instala los paquetes de Python necesarios ejecutando `pip install -r requirements.txt`.
3. Necesitarás una instancia de base de datos **PostgreSQL** en funcionamiento. Instala PostgreSQL si aún no lo has hecho.

### Archivos de Configuración

#### Archivo .env

Crea un archivo `.env` en la raíz del directorio del proyecto con el siguiente contenido, reemplazando los valores de los marcadores de posición con tus credenciales de la base de datos:

~~~
DATABASE_USER="tu_usuario"
DATABASE_PASSWORD="tu_contraseña"
DATABASE_HOST="localhost"
DATABASE_PORT="5433"
DATABASE_DB="guaitaia"

MODELO="tu/ruta/al/modelo/IA"
SECRET_KEY="tu_secret_key"
ALGORITH="HS256"
ACCESS_TOKEN_EXPIRE_MINUTES="tiempo_token_expira_en_minutos"

SQLALCHEMY_DATABASE_URL="postgresql://postgres:postgres@localhost:5433/guaitaia"

WEBP_QUALITY="calidad_imagenes_salida_de_0_a_100"

~~~

#### Conexión a la Base de Datos

Actualiza los siguientes archivos con tus cadenas de conexión a la base de datos:

- `alembic.ini`:
  ```ini
  sqlalchemy.url = postgresql://tu_usuario:tu_contraseña@localhost:5433/guaitaia
- `main.py`:
    ```ini
SQLALCHEMY_DATABASE_URL = "postgresql://tu_usuario:tu_contraseña@localhost:5433/guaitaia"

- `utils.py`:
    ```ini
conn = await asyncpg.connect(
    user="tu_usuario",
    password="tu_contraseña",
    database="guaitaia",
    host="localhost",
    port="5433"
)

## Migraciones de Base de Datos

Para generar y aplicar migarciones de base de datos, utiliza los siguientes comandos:
- Para generar una nueva migración:
    ```ini
    alembic revision --autogenerate -m "Tu mensaje aquí"
- Para aplicar migraciones a la base de datos:
    ```ini
    alembic upgrade head
- Para revertir la última migración:
    ```ini
    alembic downgrade -1
- Para revertir una migración específica:
    ```ini
    alembic downgrade <id_de_migración>
    
### Encriptación
Para generar contraseñas encriptadas, utiliza la herramienta en línea de [bcrypt.online](https://bcrypt.online)

## Iniciando la API
- Para iniciar el proyecto:
    ```ini
    uvicorn main:app --host 0.0.0.0 --port 9000 --reload
- En segundo plano:
    ```ini
    nohup uvicorn main:app --host 0.0.0.0 --port 9000 --reload &

## Acceso a la API y Base de Datos
- La documentación de la API y la interfaz de pruebas están disponibles en:
    - <http://89.233.108.38:9000/docs>
    - Para acceder a la base de datos a través de pgAdmin: <http://89.233.108.38:8888>
    
## ENDPOINT

### Argumentos

~~~
    """
    Endpoint para la detección de incendios en múltiples imágenes.

    Acepta imágenes directamente, urls a imágenes o como strings codificados en base64.
    Requiere parámetros para la confianza, IoU y el uso de CPU o GPU.

    Args:
    - current_user: Usuario actual que ha pasado la autenticación.
    - imagenes: Lista de imágenes subidas (opcional).
    - imagenes_strings: Lista de strings base64 de imágenes (opcional).
    - confianza: Umbral de confianza para la detección.
    - iou: Umbral de IoU para la detección.
    - cpu: 1 para procesar utilizando CPU o 0 para utilizar GPU.

    Returns:
    - Un JSON con los resultados de la detección.

    Raises:
    - HTTPException: Si no se proporcionan imágenes o si hay un error al procesarlas.
    """
~~~
### Llamada a la API
- Imágen como input:
    ```ini
    curl -X 'POST' \
      'http://89.233.108.38:9000/detectar_incendios/' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer <token>' \
      -H 'Content-Type: multipart/form-data' \
      -F 'imagenes=@imagen.jpg;type=image/jpeg' \
      -F 'confianza=0.5' \
      -F 'iou=0.5' \
      -F 'cpu=1'
      
- Url como input:
    ```ini
    curl -X 'POST' \
      'http://89.233.108.38:9000/detectar_incendios/' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer <token>' \
      -H 'Content-Type: multipart/form-data' \
      -F 'imagenes_string=https://tu_url/a/tu/imagen' \
      -F 'confianza=0.5' \
      -F 'iou=0.5' \
      -F 'cpu=1'
- Base64 como input:
    ```ini
    curl -X 'POST' \
      'http://89.233.108.38:9000/detectar_incendios/' \
      -H 'accept: application/json' \
      -H 'Authorization: Bearer <token>' \
      -H 'Content-Type: multipart/form-data' \
      -F 'imagenes_string=<string_base64>' \
      -F 'confianza=0.5' \
      -F 'iou=0.5' \
      -F 'cpu=1'
      
### Response
```ini
[
  {
    "detection": true,
    "conf": 0.75,
    "procesada": "nombre_archivo_procesado.webp",
    "original": "nombre_archivo_original.webp",
    "fecha": "2023-11-13",
    "hora": "00:29:50.879494"
  }
]
