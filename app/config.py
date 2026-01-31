from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")

    openai_api_key: str = ""
    secret_key: str = "dev-secret-change-me"
    database_url: str = "sqlite:///./data/sion.db"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60 * 24


settings = Settings()

# Ensure data directory exists
data_dir = Path("data")
data_dir.mkdir(exist_ok=True)
