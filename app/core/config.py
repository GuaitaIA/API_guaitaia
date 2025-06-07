# app/core/config.py (CORREGIDO para Pydantic V2)
from pydantic_settings import BaseSettings
from pydantic import ConfigDict
from typing import Optional
import os

class Settings(BaseSettings):
    # Database - Nombres que coinciden con tu .env
    sqlalchemy_database_url: str
    db_user: str
    db_password: str
    db_database: str
    db_host: str = "localhost"
    db_port: int = 5432
    
    # Security
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 100
    
    # AI Model - Nombre que coincide con tu .env
    modelo: str
    webp_quality: int = 90
    
    # API
    api_v1_str: str = "/api/v1"
    project_name: str = "GuaitaIA"
    version: str = "0.0.1 beta"
    description: str = "Detección de humo de incendios forestales mediante IA"
    
    # Extensions
    allowed_extensions: set = {"jpg", "jpeg", "png", "webp"}
    
    # Propiedades calculadas para mantener compatibilidad
    @property
    def database_url(self) -> str:
        """Alias para sqlalchemy_database_url"""
        return self.sqlalchemy_database_url
    
    @property
    def db_name(self) -> str:
        """Alias para db_database"""
        return self.db_database
    
    @property
    def model_path(self) -> str:
        """Alias para modelo"""
        return self.modelo
    
    # Pydantic V2 config
    model_config = ConfigDict(
        env_file=".env",
        case_sensitive=False
    )

settings = Settings()
