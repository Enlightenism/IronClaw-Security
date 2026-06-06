from __future__ import annotations

import functools

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    app_name: str = Field(default="IronClaw-Security", alias="APP_NAME")
    app_version: str = Field(default="1.0.0", alias="APP_VERSION")
    environment: str = Field(default="development", alias="ENVIRONMENT")
    auth_required: bool = Field(default=False, alias="AUTH_REQUIRED")
    api_key: str | None = Field(default=None, alias="IRONCLAW_API_KEY")
    secret_key: str = Field(default="changeme-32-chars-minimum!!!!!", alias="IRONCLAW_SECRET_KEY")
    jwt_secret: str = Field(default="changeme-jwt-32-chars-minimum!!", alias="JWT_SECRET")
    allowed_origins: str = Field(default="http://localhost", alias="ALLOWED_ORIGINS")
    persistence_mode: str = Field(default="memory", alias="IRONCLAW_PERSISTENCE_MODE")
    supabase_url: str = Field(default="", alias="SUPABASE_URL")
    supabase_key: str = Field(default="", alias="SUPABASE_KEY")
    supabase_service_role_key: str = Field(default="", alias="SUPABASE_SERVICE_ROLE_KEY")
    supabase_anon_key: str = Field(default="", alias="SUPABASE_ANON_KEY")
    groq_enabled: bool = Field(default=False, alias="GROQ_ENABLED")
    groq_api_key: str | None = Field(default=None, alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama3-70b-8192", alias="GROQ_MODEL")
    groq_timeout_seconds: float = Field(default=60.0, alias="GROQ_TIMEOUT_SECONDS")

    model_config = {"populate_by_name": True, "extra": "ignore"}


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
