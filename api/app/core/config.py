# api/app/core/config.py

from pydantic_settings import BaseSettings
from pydantic import AnyHttpUrl
from typing import List


class Settings(BaseSettings):
    PROJECT_NAME: str = "WAF Admin API"
    PROJECT_VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"

    DATABASE_URL: str
    REDIS_URL: str
    JWT_SECRET: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440

    CORS_ORIGINS: List[AnyHttpUrl]
    port: int = 8001  # Bunu ekle!

    class Config:
        env_file = ".env"
        env_file_encoding = 'utf-8'


settings = Settings()