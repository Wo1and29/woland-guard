"""Application configuration loaded from environment variables."""

from functools import lru_cache
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, model_validator
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

    operator_security_log_events: int = Field(default=10, ge=1, le=1_000)
    operator_security_log_window_seconds: int = Field(default=60, ge=1, le=3_600)

    web_public_origin: str = "https://localhost:8000"
    web_session_idle_seconds: int = Field(default=1_800, ge=60, le=86_400)
    web_session_absolute_seconds: int = Field(default=43_200, ge=300, le=604_800)
    web_session_touch_interval_seconds: int = Field(default=300, ge=1, le=3_600)
    web_max_form_body_bytes: int = Field(default=16_384, ge=1_024, le=65_536)
    web_login_global_limit: int = Field(default=60, ge=1, le=10_000)
    web_login_global_window_seconds: int = Field(default=60, ge=1, le=3_600)
    web_login_subject_limit: int = Field(default=5, ge=1, le=1_000)
    web_login_subject_window_seconds: int = Field(default=300, ge=1, le=86_400)
    web_login_malformed_limit: int = Field(default=10, ge=1, le=1_000)
    web_login_malformed_window_seconds: int = Field(default=60, ge=1, le=3_600)
    web_login_max_subject_buckets: int = Field(default=4_096, ge=1, le=65_536)

    outbox_poll_seconds: float = Field(default=2.0, ge=0.1, le=60.0)
    outbox_lease_seconds: float = Field(default=60.0, ge=5.0, le=3_600.0)
    outbox_adapter_timeout_seconds: float = Field(default=30.0, ge=0.1, le=3_000.0)
    outbox_recovery_interval_seconds: float = Field(default=30.0, gt=0.0, le=3_600.0)
    outbox_backoff_base_seconds: float = Field(default=5.0, ge=0.1, le=3_600.0)
    outbox_backoff_max_seconds: float = Field(default=900.0, ge=0.1, le=86_400.0)
    outbox_retry_after_cap_seconds: float = Field(default=3_600.0, ge=0.0, le=86_400.0)
    outbox_default_max_attempts: int = Field(default=5, ge=1, le=20)
    telegram_connect_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    telegram_read_timeout_seconds: float = Field(default=10.0, gt=0.0, le=60.0)
    telegram_write_timeout_seconds: float = Field(default=5.0, gt=0.0, le=60.0)
    telegram_pool_timeout_seconds: float = Field(default=1.0, gt=0.0, le=60.0)

    @model_validator(mode="after")
    def validate_outbox_timings(self) -> "Settings":
        origin = urlsplit(self.web_public_origin)
        if (
            origin.scheme not in {"http", "https"}
            or not origin.netloc
            or origin.username is not None
            or origin.password is not None
            or origin.query
            or origin.fragment
            or origin.path not in {"", "/"}
            or origin.geturl().rstrip("/") != self.web_public_origin.rstrip("/")
        ):
            raise ValueError("web public origin must be one canonical HTTP origin")
        if self.app_env == "production" and origin.scheme != "https":
            raise ValueError("production web public origin must use HTTPS")
        if self.web_session_idle_seconds > self.web_session_absolute_seconds:
            raise ValueError("web session idle lifetime must not exceed absolute lifetime")
        if self.web_session_touch_interval_seconds > self.web_session_idle_seconds:
            raise ValueError("web session touch interval must not exceed idle lifetime")
        if self.outbox_backoff_max_seconds < self.outbox_backoff_base_seconds:
            raise ValueError("outbox maximum backoff must not be below base backoff")
        if self.outbox_lease_seconds <= self.outbox_adapter_timeout_seconds:
            raise ValueError("outbox lease must exceed adapter timeout")
        if self.outbox_recovery_interval_seconds > self.outbox_lease_seconds:
            raise ValueError("outbox recovery interval must not exceed lease")
        telegram_timeout_sum = (
            self.telegram_connect_timeout_seconds
            + self.telegram_read_timeout_seconds
            + self.telegram_write_timeout_seconds
            + self.telegram_pool_timeout_seconds
        )
        if telegram_timeout_sum > self.outbox_adapter_timeout_seconds:
            raise ValueError("Telegram phase timeouts must fit the adapter timeout budget")
        return self


@lru_cache
def get_settings() -> Settings:
    """Return the process-wide validated settings object."""

    return Settings()
