from __future__ import annotations

from collections.abc import Generator
import os

# --- Patch env BEFORE any app import so the lru_cache warms with correct values ---
os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["API_KEY"] = "test-api-key"
os.environ["IRONCLAW_SECRET_KEY"] = os.environ.get("IRONCLAW_SECRET_KEY") or "test-secret-key-32-chars-minimum!!"
os.environ["JWT_SECRET"] = os.environ.get("JWT_SECRET") or "test-jwt-secret-key-32-chars-min!"
os.environ["ALLOWED_ORIGINS"] = os.environ.get("ALLOWED_ORIGINS") or "http://testserver"
os.environ["SUPABASE_URL"] = ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = ""
os.environ["SUPABASE_KEY"] = ""
os.environ["SUPABASE_ANON_KEY"] = ""

from app.core.settings import get_settings  # noqa: E402

get_settings.cache_clear()
_settings = get_settings()

from fastapi.testclient import TestClient  # noqa: E402
import pytest  # noqa: E402

from app.main import app  # noqa: E402


def _patch_app_state(application) -> None:
    if not hasattr(application, "state"):
        return
    application.state.settings = _settings


@pytest.fixture(scope="session")
def client() -> Generator[TestClient, None, None]:
    _patch_app_state(app)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="function")
def fresh_client() -> Generator[TestClient, None, None]:
    _patch_app_state(app)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
