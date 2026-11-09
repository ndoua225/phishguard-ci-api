from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration loaded from environment variables."""

    app_name: str = "PhishGuard CI Agent API"
    environment: str = "development"

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/phishguard"
    database_echo: bool = False

    # Security
    secret_key: str = "dev-secret-key-change-in-production"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # CORS
    cors_origins: list[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Quotas
    max_input_chars: int = 1000
    max_normalized_chars: int = 10000
    max_hermes_context_tokens: int = 2048
    max_urls_per_analysis: int = 10
    max_analyses_per_day: int = 30

    # Hermes
    hermes_enabled: bool = False
    hermes_timeout_seconds: int = 10
    hermes_max_retries: int = 0

    # TemplateExplainer
    template_version: str = "1.0.0"

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str, info: Any) -> str:
        """Ensure secret_key is not the default in production."""
        default = "dev-secret-key-change-in-production"
        if v == default:
            # Allow default only in development/test environments
            env = info.data.get("environment") if info.data else "development"
            if env != "development" and env != "test":
                from pydantic_core import PydanticCustomError
                raise PydanticCustomError(
                    "value_error",
                    "PHISHGUARD_SECRET_KEY must be set and cannot be the default value in production",
                )
        if len(v) < 32:
            from pydantic_core import PydanticCustomError
            raise PydanticCustomError(
                "value_error",
                "PHISHGUARD_SECRET_KEY must be at least 32 characters",
            )
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_prefix="PHISHGUARD_",
        extra="ignore",
    )


settings = Settings()
