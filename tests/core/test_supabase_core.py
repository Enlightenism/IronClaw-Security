from __future__ import annotations

import pytest

from app.core import supabase as supabase_core
from app.core.supabase import (
    SupabaseClient,
    SupabaseConfigurationError,
    get_supabase_service_client,
)
from app.supabaseclient import SUPABASE_TIMEOUT_SECONDS

_VALID_URL = "https://test.supabase.co"
_VALID_KEY = "service-role-key-abc123"

_ALL_SUPABASE_ENV_VARS: tuple[str, ...] = (
    "SUPABASE_URL",
    "IRONCLAW_SUPABASE_URL",
    "NEXT_PUBLIC_SUPABASE_URL",
    "SUPABASE_SERVICE_ROLE_KEY",
    "SUPABASE_KEY",
    "IRONCLAW_SUPABASE_KEY",
    "SUPABASE_ANON_KEY",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY",
)


def _clear_settings_cache() -> None:
    from app.core.settings import get_settings

    get_settings.cache_clear()


def _clear_supabase_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ALL_SUPABASE_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    _clear_settings_cache()


def _set_service_config(
    monkeypatch: pytest.MonkeyPatch,
    *,
    url: str | None = _VALID_URL,
    key: str | None = _VALID_KEY,
) -> None:
    _clear_supabase_env(monkeypatch)
    if url is not None:
        monkeypatch.setenv("SUPABASE_URL", url)
    if key is not None:
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", key)
    _clear_settings_cache()


class TestCleanEnv:
    def setup_method(self) -> None:
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


class TestGetSupabaseServiceClientErrors:
    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def test_raises_when_supabase_url_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="missing SUPABASE_URL"):
            get_supabase_service_client()

    def test_raises_when_service_role_key_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        _clear_settings_cache()

        with pytest.raises(SupabaseConfigurationError, match="SUPABASE_SERVICE_ROLE_KEY|supabase api key"):
            get_supabase_service_client()

    def test_raises_when_url_has_invalid_scheme(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(
            monkeypatch,
            url="ftp://invalid.supabase.co",
            key=_VALID_KEY,
        )

        with pytest.raises(SupabaseConfigurationError, match="http"):
            get_supabase_service_client()

    def test_raises_when_url_is_blank_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(
            monkeypatch,
            url="   ",
            key=_VALID_KEY,
        )

        with pytest.raises(SupabaseConfigurationError, match="missing SUPABASE_URL"):
            get_supabase_service_client()

    def test_raises_when_key_is_blank_string(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(
            monkeypatch,
            url=_VALID_URL,
            key="   ",
        )

        with pytest.raises(SupabaseConfigurationError, match="SUPABASE_SERVICE_ROLE_KEY|supabase api key"):
            get_supabase_service_client()

    def test_raises_when_url_is_quoted_blank(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(
            monkeypatch,
            url='""',
            key=_VALID_KEY,
        )

        with pytest.raises(SupabaseConfigurationError, match="missing SUPABASE_URL"):
            get_supabase_service_client()


class TestGetSupabaseServiceClientSuccess:
    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def test_returns_supabase_client_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(monkeypatch)

        client = get_supabase_service_client()
        assert isinstance(client, SupabaseClient)

    def test_client_config_url_is_stripped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(monkeypatch, url=_VALID_URL + "/")

        client = get_supabase_service_client()
        assert not client.config.url.endswith("/")

    def test_client_config_url_matches_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(monkeypatch, url=_VALID_URL)

        client = get_supabase_service_client()
        assert client.config.url == _VALID_URL

    def test_client_config_key_matches_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(monkeypatch, url=_VALID_URL, key=_VALID_KEY)

        client = get_supabase_service_client()
        assert client.config.key == _VALID_KEY

    def test_default_timeout_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(monkeypatch)

        client = get_supabase_service_client()
        assert client.timeout == SUPABASE_TIMEOUT_SECONDS

    def test_custom_timeout_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(monkeypatch)

        client = get_supabase_service_client(timeout=42.0)
        assert client.timeout == 42.0

    def test_http_url_scheme_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(
            monkeypatch,
            url="http://localhost:54321",
            key=_VALID_KEY,
        )

        client = get_supabase_service_client()
        assert client.config.url.startswith("http://")

    def test_key_with_surrounding_whitespace_is_cleaned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(
            monkeypatch,
            url=_VALID_URL,
            key=f"  {_VALID_KEY}  ",
        )

        client = get_supabase_service_client()
        assert client.config.key == _VALID_KEY

    def test_url_with_surrounding_whitespace_is_cleaned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _set_service_config(
            monkeypatch,
            url=f"  {_VALID_URL}  ",
            key=_VALID_KEY,
        )

        client = get_supabase_service_client()
        assert client.config.url == _VALID_URL


class TestSettingsUrlPriority:
    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def test_settings_url_preferred_over_ironclaw_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        settings_url = "https://settings-resolved.supabase.co"
        fallback_url = "https://should-not-be-used.supabase.co"

        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_URL", settings_url)
        monkeypatch.setenv("IRONCLAW_SUPABASE_URL", fallback_url)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == settings_url

    def test_ironclaw_env_used_when_supabase_url_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fallback_url = "https://ironclaw-fallback.supabase.co"

        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("IRONCLAW_SUPABASE_URL", fallback_url)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == fallback_url

    def test_next_public_url_used_as_last_env_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        next_url = "https://next-public.supabase.co"

        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_URL", next_url)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.url == next_url

    def test_service_role_key_preferred_over_legacy_keys(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_SERVICE_ROLE_KEY", _VALID_KEY)
        monkeypatch.setenv("SUPABASE_KEY", "legacy-key-should-not-win")
        monkeypatch.setenv("IRONCLAW_SUPABASE_KEY", "ironclaw-key-should-not-win")
        monkeypatch.setenv("SUPABASE_ANON_KEY", "anon-key-should-not-win")
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", "public-anon-should-not-win")
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.key == _VALID_KEY

    def test_legacy_service_key_used_when_service_role_key_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        legacy_key = "legacy-supabase-key"

        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_KEY", legacy_key)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.key == legacy_key

    def test_ironclaw_key_used_when_primary_keys_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ironclaw_key = "ironclaw-fallback-key"

        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("IRONCLAW_SUPABASE_KEY", ironclaw_key)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.key == ironclaw_key

    def test_anon_key_used_when_server_keys_absent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        anon_key = "anon-fallback-key"

        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("SUPABASE_ANON_KEY", anon_key)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.key == anon_key

    def test_next_public_anon_key_used_as_last_key_fallback(self, monkeypatch: pytest.MonkeyPatch) -> None:
        public_anon_key = "next-public-anon-key"

        _clear_supabase_env(monkeypatch)
        monkeypatch.setenv("SUPABASE_URL", _VALID_URL)
        monkeypatch.setenv("NEXT_PUBLIC_SUPABASE_ANON_KEY", public_anon_key)
        _clear_settings_cache()

        client = get_supabase_service_client()
        assert client.config.key == public_anon_key


class TestDunderAll:
    def test_all_symbols_importable(self) -> None:
        for name in supabase_core.__all__:
            assert hasattr(
                supabase_core,
                name,
            ), f"app.core.supabase.__all__ declares {name!r} but the symbol is not present on the module"

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


class TestSupabaseConfigContract:
    def setup_method(self) -> None:
        _clear_settings_cache()

    def teardown_method(self) -> None:
        _clear_settings_cache()

    def _make_client(self, monkeypatch: pytest.MonkeyPatch) -> SupabaseClient:
        _set_service_config(monkeypatch)
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
