"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Validated control-plane settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="WG_",
        extra="ignore",
    )

    app_name: str = "Woland Guard Control Plane"
    app_version: str = "0.1.0"
    app_env: Literal["development", "test", "production"] = "development"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "woland_guard"
    postgres_user: str = "woland_guard"
    postgres_password: SecretStr | None = None
    postgres_connect_timeout_seconds: int = 3

    ingest_max_body_bytes: int = Field(default=1_048_576, ge=1, le=10_485_760)
    ingest_rate_limit_requests: int = Field(default=60, ge=1, le=10_000)
    ingest_rate_limit_window_seconds: int = Field(default=60, ge=1, le=3_600)
    ingest_max_clock_skew_seconds: int = Field(default=300, ge=0, le=86_400)


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide validated settings object."""

    return Settings()
