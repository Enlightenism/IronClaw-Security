from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

from app.core.auth import _get_jwt_secret, _get_secret_key

# ---------------------------------------------------------------------------
# Sentinels — exact values that auth.py treats as "unconfigured"
# ---------------------------------------------------------------------------

_SECRET_KEY_SENTINEL = "changeme-32-chars-minimum!!!!!"
_JWT_SECRET_SENTINEL = "changeme-jwt-32-chars-minimum!!"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _req(settings_ns: SimpleNamespace) -> SimpleNamespace:
    """Minimal fake Request with app.state.settings populated."""
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=settings_ns)))


def _req_no_settings() -> SimpleNamespace:
    """Fake Request with no settings attribute on state."""
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))


def _req_null_settings() -> SimpleNamespace:
    """Fake Request where settings is explicitly None."""
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(settings=None)))


def _patch_no_fallback():
    """Prevent _get_settings from falling through to the real cached Settings()."""
    return patch("app.core.auth.get_settings", side_effect=RuntimeError("no fallback"))


# ---------------------------------------------------------------------------
# _get_secret_key — sentinel treated as unconfigured
# ---------------------------------------------------------------------------


class TestGetSecretKeySentinelAuthSecrets:
    def test_exact_sentinel_returns_none(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key=_SECRET_KEY_SENTINEL))) is None

    def test_empty_string_returns_none(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key=""))) is None

    def test_whitespace_only_returns_none(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key="   "))) is None

    def test_tab_whitespace_returns_none(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key="\t\n"))) is None

    def test_none_value_returns_none(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key=None))) is None

    def test_integer_value_returns_none(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key=42))) is None

    def test_missing_attribute_on_settings_returns_none(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace())) is None

    def test_missing_settings_on_state_returns_none(self) -> None:
        with _patch_no_fallback():
            assert _get_secret_key(_req_no_settings()) is None

    def test_null_settings_returns_none(self) -> None:
        with _patch_no_fallback():
            assert _get_secret_key(_req_null_settings()) is None

    def test_get_settings_raises_returns_none(self) -> None:
        req = _req_null_settings()
        with patch("app.core.auth.get_settings", side_effect=RuntimeError("offline")):
            assert _get_secret_key(req) is None


# ---------------------------------------------------------------------------
# _get_secret_key — real non-default value is returned as-is
# ---------------------------------------------------------------------------


class TestGetSecretKeyRealValueAuthSecrets:
    def test_real_key_is_returned(self) -> None:
        real = "ironclaw-real-secret-key-xyzabc!"
        assert _get_secret_key(_req(SimpleNamespace(secret_key=real))) == real

    def test_leading_whitespace_stripped(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key="  stripped-key"))) == "stripped-key"

    def test_trailing_whitespace_stripped(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key="stripped-key  "))) == "stripped-key"

    def test_both_ends_whitespace_stripped(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key="  both-ends  "))) == "both-ends"

    def test_internal_spaces_preserved(self) -> None:
        key = "key with internal spaces"
        assert _get_secret_key(_req(SimpleNamespace(secret_key=key))) == key

    def test_minimum_one_char_key_returned(self) -> None:
        assert _get_secret_key(_req(SimpleNamespace(secret_key="x"))) == "x"

    def test_long_key_returned_intact(self) -> None:
        long_key = "a" * 256
        assert _get_secret_key(_req(SimpleNamespace(secret_key=long_key))) == long_key

    def test_key_with_special_chars_returned(self) -> None:
        special = "k3y!@#$%^&*()-_=+[]{}|;':\",./<>?"
        assert _get_secret_key(_req(SimpleNamespace(secret_key=special))) == special


# ---------------------------------------------------------------------------
# _get_jwt_secret — sentinel treated as unconfigured
# ---------------------------------------------------------------------------


class TestGetJwtSecretSentinelAuthSecrets:
    def test_exact_sentinel_returns_none(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=_JWT_SECRET_SENTINEL))) is None

    def test_empty_string_returns_none(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=""))) is None

    def test_whitespace_only_returns_none(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret="   "))) is None

    def test_tab_whitespace_returns_none(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret="\t\n"))) is None

    def test_none_value_returns_none(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=None))) is None

    def test_integer_value_returns_none(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=99))) is None

    def test_missing_attribute_on_settings_returns_none(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace())) is None

    def test_missing_settings_on_state_returns_none(self) -> None:
        with _patch_no_fallback():
            assert _get_jwt_secret(_req_no_settings()) is None

    def test_null_settings_returns_none(self) -> None:
        with _patch_no_fallback():
            assert _get_jwt_secret(_req_null_settings()) is None

    def test_get_settings_raises_returns_none(self) -> None:
        req = _req_null_settings()
        with patch("app.core.auth.get_settings", side_effect=RuntimeError("offline")):
            assert _get_jwt_secret(req) is None


# ---------------------------------------------------------------------------
# _get_jwt_secret — real non-default value is returned as-is
# ---------------------------------------------------------------------------


class TestGetJwtSecretRealValueAuthSecrets:
    def test_real_jwt_secret_is_returned(self) -> None:
        real = "ironclaw-real-jwt-secret-xyzabc!"
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=real))) == real

    def test_leading_whitespace_stripped(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret="  stripped-jwt"))) == "stripped-jwt"

    def test_trailing_whitespace_stripped(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret="stripped-jwt  "))) == "stripped-jwt"

    def test_both_ends_whitespace_stripped(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret="  both-ends  "))) == "both-ends"

    def test_internal_spaces_preserved(self) -> None:
        secret = "jwt with internal spaces"
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=secret))) == secret

    def test_minimum_one_char_secret_returned(self) -> None:
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret="x"))) == "x"

    def test_long_secret_returned_intact(self) -> None:
        long_secret = "b" * 256
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=long_secret))) == long_secret

    def test_secret_with_special_chars_returned(self) -> None:
        special = "jwt!@#$%^&*()-_=+[]{}|;':\",./<>?"
        assert _get_jwt_secret(_req(SimpleNamespace(jwt_secret=special))) == special


# ---------------------------------------------------------------------------
# Isolation — secret_key does not affect jwt_secret and vice versa
# ---------------------------------------------------------------------------


class TestSecretsIsolation:
    def test_real_secret_key_sentinel_jwt_secret(self) -> None:
        req = _req(SimpleNamespace(secret_key="real-secret", jwt_secret=_JWT_SECRET_SENTINEL))
        assert _get_secret_key(req) == "real-secret"
        assert _get_jwt_secret(req) is None

    def test_sentinel_secret_key_real_jwt_secret(self) -> None:
        req = _req(SimpleNamespace(secret_key=_SECRET_KEY_SENTINEL, jwt_secret="real-jwt"))
        assert _get_secret_key(req) is None
        assert _get_jwt_secret(req) == "real-jwt"

    def test_both_real_returns_both(self) -> None:
        req = _req(SimpleNamespace(secret_key="real-secret", jwt_secret="real-jwt"))
        assert _get_secret_key(req) == "real-secret"
        assert _get_jwt_secret(req) == "real-jwt"

    def test_both_sentinels_both_return_none(self) -> None:
        req = _req(
            SimpleNamespace(
                secret_key=_SECRET_KEY_SENTINEL,
                jwt_secret=_JWT_SECRET_SENTINEL,
            )
        )
        assert _get_secret_key(req) is None
        assert _get_jwt_secret(req) is None

    def test_both_empty_both_return_none(self) -> None:
        req = _req(SimpleNamespace(secret_key="", jwt_secret=""))
        assert _get_secret_key(req) is None
        assert _get_jwt_secret(req) is None

    def test_changing_secret_key_does_not_change_jwt_result(self) -> None:
        req1 = _req(SimpleNamespace(secret_key="key-a", jwt_secret="jwt-a"))
        req2 = _req(SimpleNamespace(secret_key="key-b", jwt_secret="jwt-a"))
        assert _get_jwt_secret(req1) == _get_jwt_secret(req2)

    def test_changing_jwt_secret_does_not_change_secret_key_result(self) -> None:
        req1 = _req(SimpleNamespace(secret_key="key-a", jwt_secret="jwt-a"))
        req2 = _req(SimpleNamespace(secret_key="key-a", jwt_secret="jwt-b"))
        assert _get_secret_key(req1) == _get_secret_key(req2)

    def test_only_secret_key_present_jwt_returns_none(self) -> None:
        req = _req(SimpleNamespace(secret_key="real-secret"))
        assert _get_secret_key(req) == "real-secret"
        assert _get_jwt_secret(req) is None

    def test_only_jwt_secret_present_secret_key_returns_none(self) -> None:
        req = _req(SimpleNamespace(jwt_secret="real-jwt"))
        assert _get_secret_key(req) is None
        assert _get_jwt_secret(req) == "real-jwt"

    def test_functions_are_called_independently_no_shared_state(self) -> None:
        req = _req(
            SimpleNamespace(
                secret_key="ironclaw-secret-xyz",
                jwt_secret="ironclaw-jwt-xyz",
            )
        )
        sk = _get_secret_key(req)
        jk = _get_jwt_secret(req)
        assert sk != jk
        assert sk == "ironclaw-secret-xyz"
        assert jk == "ironclaw-jwt-xyz"
