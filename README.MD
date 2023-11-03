Configurar entorno

Configurar el archivo .env

Tenemos que tener instalada una base de datos postgres i crear una base de datos.

Cambiar los siguientes archivos para apuntar a la base de datos que tengamos

alembic.ini
sqlalchemy.url = postgresql://postgres:postgres@localhost:5433/guaitaia

main.py
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:postgres@localhost:5433/guaitaia"

funcs.py
conn = await asyncpg.connect(
    user="postgres",
    password="postgres",
    database="guaitaia",
    host="localhost",
    port="5433"
)

Para poder generar las tablas se tiene que ejecutar este comando

Generate migration
alembic upgrade head

Delete migration
alembic downgrade -1
alembic downgrade 8ac14e223d1e

Para generar passwords encriptados lo podemos hacer desde aqui
https://bcrypt.online/

Iniciar proyecto
nohup python main.py &


http://89.233.108.38:8000/docs -> API
http://89.233.108.38:8888 -> pgadmin (Acceder a la base de datos)