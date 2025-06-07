# setup_database.py
import asyncio
import asyncpg
import subprocess
import sys
from app.core.config import settings

async def check_database_connection():
    """Verificar conexión a la base de datos."""
    print("🔍 Verificando conexión a la base de datos...")
    
    try:
        conn = await asyncpg.connect(
            user=settings.db_user,
            password=settings.db_password,
            host=settings.db_host,
            port=settings.db_port,
            database="guaitaia"  # Conectar a la BD por defecto primero
        )
        print("✅ Conexión a PostgreSQL exitosa")
        await conn.close()
        return True
    except Exception as e:
        print(f"❌ Error conectando a PostgreSQL: {e}")
        return False

async def create_database_if_not_exists():
    """Crear la base de datos si no existe."""
    print(f"🗄️ Verificando si la base de datos '{settings.db_name}' existe...")
    
    try:
        # Conectar a la BD por defecto
        conn = await asyncpg.connect(
            user=settings.db_user,
            password=settings.db_password,
            host=settings.db_host,
            port=settings.db_port,
            database="postgres"
        )
        
        # Verificar si la BD existe
        result = await conn.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", 
            settings.db_name
        )
        
        if result:
            print(f"✅ La base de datos '{settings.db_name}' ya existe")
        else:
            print(f"📝 Creando base de datos '{settings.db_name}'...")
            await conn.execute(f'CREATE DATABASE "{settings.db_name}"')
            print(f"✅ Base de datos '{settings.db_name}' creada exitosamente")
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creando base de datos: {e}")
        return False

async def test_app_database_connection():
    """Probar conexión con la configuración de la app."""
    print(f"🧪 Probando conexión a '{settings.db_name}'...")
    
    try:
        conn = await asyncpg.connect(
            user=settings.db_user,
            password=settings.db_password,
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name
        )
        print("✅ Conexión a la base de datos de la app exitosa")
        await conn.close()
        return True
    except Exception as e:
        print(f"❌ Error conectando a la base de datos de la app: {e}")
        return False

def run_alembic_migrations():
    """Ejecutar migraciones de Alembic."""
    print("🔄 Ejecutando migraciones de Alembic...")
    
    try:
        # Generar migración inicial si no existe
        result = subprocess.run([
            sys.executable, "-m", "alembic", "revision", "--autogenerate", 
            "-m", "Initial migration"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Migración generada")
        else:
            print(f"ℹ️ Migración: {result.stdout}")
        
        # Aplicar migraciones
        result = subprocess.run([
            sys.executable, "-m", "alembic", "upgrade", "head"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Migraciones aplicadas exitosamente")
            return True
        else:
            print(f"❌ Error aplicando migraciones: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"❌ Error ejecutando Alembic: {e}")
        return False

async def create_initial_data():
    """Crear datos iniciales (usuario admin, zonas, etc.)."""
    print("👤 Creando datos iniciales...")
    
    try:
        from app.core.security import get_password_hash
        
        conn = await asyncpg.connect(
            user=settings.db_user,
            password=settings.db_password,
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name
        )
        
        # Crear zona horaria por defecto
        zone_exists = await conn.fetchval(
            "SELECT 1 FROM zones WHERE id = 1"
        )
        
        if not zone_exists:
            await conn.execute("""
                INSERT INTO zones (id, timezone, start_time, end_time) 
                VALUES (1, 'UTC', 6, 18)
            """)
            print("✅ Zona horaria por defecto creada")
        
        # Crear usuario admin por defecto
        admin_exists = await conn.fetchval(
            "SELECT 1 FROM users WHERE email = 'admin@guaitaia.com'"
        )
        
        if not admin_exists:
            hashed_password = get_password_hash("admin123")
            await conn.execute("""
                INSERT INTO users (email, hashed_password, role, is_active, zones_id) 
                VALUES ('admin@guaitaia.com', $1, 'superadmin', true, 1)
            """, hashed_password)
            print("✅ Usuario admin creado (admin@guaitaia.com / admin123)")
        
        await conn.close()
        return True
        
    except Exception as e:
        print(f"❌ Error creando datos iniciales: {e}")
        return False

async def main():
    """Configuración completa de la base de datos."""
    print("🚀 CONFIGURACIÓN DE BASE DE DATOS")
    print("=" * 50)
    
    # Paso 1: Verificar conexión a PostgreSQL
    if not await check_database_connection():
        print("\n❌ No se puede conectar a PostgreSQL")
        print("Asegúrate de que PostgreSQL esté ejecutándose en el puerto 5433")
        return False
    
    # Paso 2: Crear base de datos si no existe
    if not await create_database_if_not_exists():
        return False
    
    # Paso 3: Probar conexión a la BD de la app
    if not await test_app_database_connection():
        return False
    
    # Paso 4: Ejecutar migraciones
    if not run_alembic_migrations():
        return False
    
    # Paso 5: Crear datos iniciales
    if not await create_initial_data():
        return False
    
    print("\n✅ ¡Base de datos configurada exitosamente!")
    print("\n📋 Información de acceso:")
    print(f"Base de datos: {settings.db_name}")
    print(f"Host: {settings.db_host}:{settings.db_port}")
    print("Usuario admin: admin@guaitaia.com")
    print("Contraseña admin: admin123")
    
    return True

if __name__ == "__main__":
    success = asyncio.run(main())
    if success:
        print("\n🧪 Ahora puedes ejecutar los tests:")
        print("python -m pytest tests/ -v")
    else:
        print("\n❌ Configuración de base de datos falló")
