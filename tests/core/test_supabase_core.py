from __future__ import annotations

import pytest

from app.core import supabase as supabase_core
from app.core.supabase import (
    SupabaseClient,
    SupabaseConfigurationError,
    get_supabase_service_client,
)
from app.supabaseclient import SUPABASE_TIMEOUT_SECONDS

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_URL = "https://test.supabase.co"
_VALID_KEY = "service-role-key-abc123"


def _clear_settings_cache() -> None:
    """Bust the lru_cache on get_settings so monkeypatched env is picked up."""
    from app.core.settings import get_settings

    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# _clean_env — private helper tests via module reference
# ---------------------------------------------------------------------------


class TestCleanEnv:
    """Tests for app.core.supabase._clean_env — accessed via module reference."""

    def setup_method(self) -> None:
        # _clean_env is private; grab it directly from the module.
        from app.core import supabase as _mod

        self._fn = _mod._clean_env  # type: ignore[attr-defined]

    def test_returns_none_for_none_input(self) -> None:
        assert self._fn(None) is None

    def test_strips_leading_trailing_whitespace(self) -> None:
        assert self._fn("  hello  ") == "hello"

    def test_strips_double_quotes(self) -> None:
        assert self._fn('"my-key"') == "my-key"

    def test_strips_single_quotes(self) -> None:
        assert self._fn("'my-key'") == "my-key"

    def test_strips_whitespace_and_quotes_combined(self) -> None:
        assert self._fn('  "spaced-key"  ') == "spaced-key"

    def test_returns_none_for_blank_string(self) -> None:
        assert self._fn("   ") is None

    def test_returns_none_for_empty_string(self) -> None:
        assert self._fn("") is None

    def test_returns_none_for_quoted_empty_string(self) -> None:
        assert self._fn('""') is None

    def test_preserves_internal_whitespace(self) -> None:
        result = self._fn("  hello world  ")
        assert result == "hello world"

    def test_plain_value_unchanged(self) -> None:
        assert self._fn("plainvalue") == "plainvalue"


# ---------------------------------------------------------------------------
# get_supabase_service_client — configuration-error paths
# ---------------------------------------------------------------------------


class TestGetSupabaseServiceClientErrors:
    """get_supabase_service_client raises SupabaseConfigurationError on bad config."""

    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def test_raises_when_supabase_url_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_URL", raising=False)
        monkeypatch.delenv("NEXT_PUBLIC_SUPABASE_URL", raising=False)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="missing SUPABASE_URL"):
            get_supabase_service_client()

    def test_raises_when_service_role_key_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.delenv("SUPABASE_SERVICE_ROLE_KEY", raising=False)
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="SUPABASE_SERVICE_ROLE_KEY"):
            get_supabase_service_client()

    def test_raises_when_url_has_invalid_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", "ftp://invalid.supabase.co")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="http"):
            get_supabase_service_client()

    def test_raises_when_url_is_blank_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", "   ")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="missing SUPABASE_URL"):
            get_supabase_service_client()

    def test_raises_when_key_is_blank_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", "   ")
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="SUPABASE_SERVICE_ROLE_KEY"):
            get_supabase_service_client()

    def test_raises_when_url_is_quoted_blank(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", '""')
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="missing SUPABASE_URL"):
            get_supabase_service_client()


# ---------------------------------------------------------------------------
# get_supabase_service_client — happy paths
# ---------------------------------------------------------------------------


class TestGetSupabaseServiceClientSuccess:
    """get_supabase_service_client returns a correctly-configured SupabaseClient."""

    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def test_returns_supabase_client_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert isinstance(client, SupabaseClient)

    def test_client_config_url_is_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL + "/")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert not client.config.url.endswith("/")

    def test_client_config_url_matches_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == _VALID_URL

    def test_client_config_key_matches_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.key == _VALID_KEY

    def test_default_timeout_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.timeout == SUPABASE_TIMEOUT_SECONDS

    def test_custom_timeout_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client(timeout=42.0)
        assert client.timeout == 42.0

    def test_http_url_scheme_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", "http://localhost:54321")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url.startswith("http://")

    def test_key_with_surrounding_whitespace_is_cleaned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", f"  {_VALID_KEY}  ")
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.key == _VALID_KEY

    def test_url_with_surrounding_whitespace_is_cleaned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SUPABASE_URL", f"  {_VALID_URL}  ")
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == _VALID_URL


# ---------------------------------------------------------------------------
# Settings-resolved URL takes priority over raw env fallback
# ---------------------------------------------------------------------------


class TestSettingsUrlPriority:
    """settings.supabase_url is preferred over raw IRONCLAW_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_URL."""

    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def test_settings_url_preferred_over_ironclaw_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings_url = "https://settings-resolved.supabase.co"
        fallback_url = "https://should-not-be-used.supabase.co"

        monkeypatch.setenv("SUPABASE_URL", settings_url)
        monkeypatch.setenv("IRONCLAW_SUPABASE_URL", fallback_url)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == settings_url

    def test_ironclaw_env_used_when_supabase_url_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fallback_url = "https://ironclaw-fallback.supabase.co"

        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.setenv("IRONCLAW_SUPABASE_URL", fallback_url)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == fallback_url

    def test_next_public_url_used_as_last_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        next_url = "https://next-public.supabase.co"

        monkeypatch.delenv("SUPABASE_URL", raising=False)
        monkeypatch.delenv("IRONCLAW_SUPABASE_URL", raising=False)
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_URL", next_url)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == next_url


# ---------------------------------------------------------------------------
# __all__ completeness — every exported symbol must be importable
# ---------------------------------------------------------------------------


class TestDunderAll:
    """Every name in app.core.supabase.__all__ must be importable from that module."""

    def test_all_symbols_importable(self) -> None:
        for name in supabase_core.__all__:
            assert hasattr(supabase_core, name), f"app.core.supabase.__all__ declares {name!r} but the symbol is not present on the module"

    def test_all_contains_get_supabase_service_client(self) -> None:
        assert "get_supabase_service_client" in supabase_core.__all__

    def test_all_contains_supabase_client(self) -> None:
        assert "SupabaseClient" in supabase_core.__all__

    def test_all_contains_supabase_config(self) -> None:
        assert "SupabaseConfig" in supabase_core.__all__

    def test_all_contains_supabase_configuration_error(self) -> None:
        assert "SupabaseConfigurationError" in supabase_core.__all__

    def test_all_contains_get_supabase_client(self) -> None:
        assert "get_supabase_client" in supabase_core.__all__

    def test_all_contains_create_supabase_client(self) -> None:
        assert "create_supabase_client" in supabase_core.__all__

    def test_all_contains_get_supabase_config(self) -> None:
        assert "get_supabase_config" in supabase_core.__all__


# ---------------------------------------------------------------------------
# SupabaseConfig contract — verify config properties used downstream
# ---------------------------------------------------------------------------


class TestSupabaseConfigContract:
    """SupabaseConfig returned inside the client exposes the expected URL properties."""

    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def _make_client(self, monkeypatch: pytest.MonkeyPatch) -> SupabaseClient:
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()
        return get_supabase_service_client()

    def test_rest_url_has_correct_suffix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._make_client(monkeypatch)
        assert client.config.rest_url == f"{_VALID_URL}/rest/v1"

    def test_auth_url_has_correct_suffix(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._make_client(monkeypatch)
        assert client.config.auth_url == f"{_VALID_URL}/auth/v1"

    def test_config_is_frozen(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = self._make_client(monkeypatch)
        with pytest.raises((AttributeError, TypeError)):
            client.config.url = "https://mutated.supabase.co"  # type: ignore[misc]
