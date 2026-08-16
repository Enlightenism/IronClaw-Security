from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from app.services import supabase_auth
from app.services.supabase_auth import validate_token_via_supabase


class TestValidateTokenViaSupabase:
    def test_returns_none_for_blank_token(self):
        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("   ", settings=settings) is None

    def test_returns_none_when_supabase_url_is_missing(self):
        settings = SimpleNamespace(
            effective_supabase_url="",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("token", settings=settings) is None

    def test_returns_none_when_api_key_is_missing(self):
        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="",
            effective_supabase_service_role_key="",
        )

        assert validate_token_via_supabase("token", settings=settings) is None

    def test_uses_anon_key_and_returns_claims(self, monkeypatch):
        response = Mock(status_code=200)
        response.json.return_value = {
            "id": "user-123",
            "user_metadata": {"org_id": "org-123"},
            "app_metadata": {"role": "customer"},
        }
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co/",
            effective_supabase_anon_key="anon-key",
            effective_supabase_service_role_key="service-key",
        )

        result = validate_token_via_supabase(
            " bearer-token ",
            settings=settings,
            timeout=2.5,
        )

        assert result == {
            "sub": "user-123",
            "user_metadata": {"org_id": "org-123"},
            "app_metadata": {"role": "customer"},
        }
        request.assert_called_once_with(
            "https://project.supabase.co/auth/v1/user",
            headers={
                "Authorization": "Bearer bearer-token",
                "apikey": "anon-key",
            },
            timeout=2.5,
        )

    def test_falls_back_to_service_role_key(self, monkeypatch):
        response = Mock(status_code=200)
        response.json.return_value = {"id": "user-123"}
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="",
            effective_supabase_service_role_key="service-key",
        )

        result = validate_token_via_supabase("token", settings=settings)

        assert result == {
            "sub": "user-123",
            "user_metadata": {},
            "app_metadata": {},
        }
        assert request.call_args.kwargs["headers"]["apikey"] == "service-key"

    @pytest.mark.parametrize("status_code", [400, 401, 403, 404, 500, 503])
    def test_returns_none_for_non_200_response(self, monkeypatch, status_code):
        response = Mock(status_code=status_code)
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("token", settings=settings) is None

    def test_returns_none_when_response_json_is_invalid(self, monkeypatch):
        response = Mock(status_code=200)
        response.json.side_effect = ValueError("invalid json")
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("token", settings=settings) is None

    def test_returns_none_when_user_id_is_missing(self, monkeypatch):
        response = Mock(status_code=200)
        response.json.return_value = {
            "user_metadata": {},
            "app_metadata": {},
        }
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("token", settings=settings) is None

    def test_normalizes_non_dict_metadata(self, monkeypatch):
        response = Mock(status_code=200)
        response.json.return_value = {
            "id": "user-123",
            "user_metadata": None,
            "app_metadata": "invalid",
        }
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("token", settings=settings) == {
            "sub": "user-123",
            "user_metadata": {},
            "app_metadata": {},
        }

    def test_returns_none_on_httpx_error(self, monkeypatch):
        request = Mock(side_effect=httpx.TimeoutException("timed out"))
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("token", settings=settings) is None

    def test_returns_none_on_unexpected_transport_error(self, monkeypatch):
        request = Mock(side_effect=RuntimeError("transport failed"))
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert validate_token_via_supabase("token", settings=settings) is None

    def test_uses_get_settings_when_settings_are_omitted(self, monkeypatch):
        response = Mock(status_code=200)
        response.json.return_value = {"id": "user-123"}
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)
        monkeypatch.setattr(
            supabase_auth,
            "get_settings",
            lambda: SimpleNamespace(
                effective_supabase_url="https://project.supabase.co",
                effective_supabase_anon_key="anon-key",
            ),
        )

        assert validate_token_via_supabase("token") == {
            "sub": "user-123",
            "user_metadata": {},
            "app_metadata": {},
        }

    def test_returns_none_when_get_settings_fails(self, monkeypatch):
        monkeypatch.setattr(
            supabase_auth,
            "get_settings",
            Mock(side_effect=RuntimeError("settings unavailable")),
        )

        assert validate_token_via_supabase("token") is None

    @pytest.mark.parametrize("timeout", [0, -1, "invalid"])
    def test_invalid_timeout_uses_default(self, monkeypatch, timeout):
        response = Mock(status_code=401)
        request = Mock(return_value=response)
        monkeypatch.setattr(supabase_auth.httpx, "get", request)

        settings = SimpleNamespace(
            effective_supabase_url="https://project.supabase.co",
            effective_supabase_anon_key="anon-key",
        )

        assert (
            validate_token_via_supabase(
                "token",
                settings=settings,
                timeout=timeout,
            )
            is None
        )
        assert request.call_args.kwargs["timeout"] == 3.0
