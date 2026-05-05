from __future__ import annotations

import importlib
import sys

import pytest


def _reload_ironclawskill_errors():
    sys.modules.pop("ironclawskill.errors", None)
    return importlib.import_module("ironclawskill.errors")


def test_errors_module_exports_canonical_exception_classes():
    errors = _reload_ironclawskill_errors()

    expected_names = (
        "ErrorContext",
        "IronClawSkillError",
        "SkillConfigurationError",
        "SkillValidationError",
        "SkillAuthenticationError",
        "SkillAuthorizationError",
        "SkillPolicyBlockedError",
        "SkillReviewRequiredError",
        "SkillProviderUnavailableError",
        "SkillTimeoutError",
        "SkillExecutionFailedError",
        "SkillRateLimitError",
        "ProviderAuthenticationError",
        "ProviderExecutionError",
        "ProviderConfigurationError",
        "ProviderUnavailableError",
        "IronClawConfigurationError",
        "IronClawRuntimeError",
        "builderrorcontext",
    )

    for name in expected_names:
        assert hasattr(errors, name), f"ironclawskill.errors is missing export: {name}"


def test_canonical_exception_hierarchy_is_stable():
    errors = _reload_ironclawskill_errors()

    assert issubclass(errors.IronClawSkillError, Exception)

    assert issubclass(errors.SkillConfigurationError, errors.IronClawSkillError)
    assert issubclass(errors.SkillValidationError, errors.IronClawSkillError)
    assert issubclass(errors.SkillAuthenticationError, errors.IronClawSkillError)
    assert issubclass(errors.SkillAuthorizationError, errors.IronClawSkillError)
    assert issubclass(errors.SkillPolicyBlockedError, errors.IronClawSkillError)
    assert issubclass(errors.SkillReviewRequiredError, errors.IronClawSkillError)
    assert issubclass(errors.SkillProviderUnavailableError, errors.IronClawSkillError)
    assert issubclass(errors.SkillTimeoutError, errors.IronClawSkillError)
    assert issubclass(errors.SkillExecutionFailedError, errors.IronClawSkillError)
    assert issubclass(errors.SkillRateLimitError, errors.IronClawSkillError)

    assert issubclass(errors.ProviderAuthenticationError, errors.SkillAuthenticationError)
    assert issubclass(errors.ProviderExecutionError, errors.SkillExecutionFailedError)
    assert issubclass(errors.ProviderConfigurationError, errors.SkillConfigurationError)
    assert issubclass(errors.ProviderUnavailableError, errors.SkillProviderUnavailableError)

    assert issubclass(errors.IronClawConfigurationError, errors.SkillConfigurationError)
    assert issubclass(errors.IronClawRuntimeError, errors.IronClawSkillError)


def test_imported_exception_symbols_remain_identical_across_imports():
    # First import through the canonical package path
    errors_first = importlib.import_module("ironclawskill.errors")

    imported_skill_error = errors_first.IronClawSkillError
    imported_provider_config_error = errors_first.ProviderConfigurationError
    imported_runtime_error = errors_first.IronClawRuntimeError

    # Import the same module again via import_module; CPython will reuse the
    # existing module object and its class identities from sys.modules.
    errors_second = importlib.import_module("ironclawskill.errors")

    assert errors_second.IronClawSkillError is imported_skill_error
    assert errors_second.ProviderConfigurationError is imported_provider_config_error
    assert errors_second.IronClawRuntimeError is imported_runtime_error


@pytest.mark.parametrize(
    ("name", "statuscode", "errorcode", "retryable"),
    [
        ("SkillConfigurationError", 500, "skillconfigurationerror", False),
        ("SkillValidationError", 400, "skillvalidationerror", False),
        ("SkillAuthenticationError", 401, "skillauthenticationerror", False),
        ("SkillAuthorizationError", 403, "skillauthorizationerror", False),
        ("SkillPolicyBlockedError", 403, "skillpolicyblocked", False),
        ("SkillReviewRequiredError", 202, "skillreviewrequired", False),
        ("SkillProviderUnavailableError", 502, "skillproviderunavailable", True),
        ("SkillTimeoutError", 504, "skilltimeout", True),
        ("SkillExecutionFailedError", 502, "skillexecutionfailed", False),
        ("SkillRateLimitError", 429, "skillratelimited", True),
        ("ProviderAuthenticationError", 401, "providerauthenticationerror", False),
        ("ProviderExecutionError", 502, "providerexecutionerror", False),
        ("ProviderConfigurationError", 500, "providerconfigurationerror", False),
        ("ProviderUnavailableError", 502, "providerunavailableerror", True),
        ("IronClawConfigurationError", 500, "ironclawconfigurationerror", False),
        ("IronClawRuntimeError", 500, "ironclawruntimeerror", False),
    ],
)
def test_exception_defaults_are_stable(name, statuscode, errorcode, retryable):
    errors = _reload_ironclawskill_errors()

    exc_type = getattr(errors, name)
    exc = exc_type("boom")

    assert exc.statuscode == statuscode
    assert exc.errorcode == errorcode
    assert exc.retryable is retryable
    assert str(exc) == "boom"


def test_builderrorcontext_returns_expected_shape():
    errors = _reload_ironclawskill_errors()
    contracts = importlib.import_module("ironclawskill.contracts")

    context = errors.builderrorcontext(
        requestid="req_123",
        provider=contracts.SkillProvider.OPENCLAW,
        operation="scan",
        risk=contracts.RiskLevel.HIGH,
        metadata={"source": "pytest"},
    )

    assert context.requestid == "req_123"
    assert context.provider is contracts.SkillProvider.OPENCLAW
    assert context.operation == "scan"
    assert context.risk is contracts.RiskLevel.HIGH
    assert dict(context.metadata) == {"source": "pytest"}


def test_exception_todict_shape_is_stable():
    errors = _reload_ironclawskill_errors()
    contracts = importlib.import_module("ironclawskill.contracts")

    context = errors.builderrorcontext(
        requestid="req_456",
        provider=contracts.SkillProvider.CLAUDE,
        operation="execute",
        risk=contracts.RiskLevel.CRITICAL,
        metadata={"layer": "runtime"},
    )
    exc = errors.ProviderExecutionError(
        "provider transport failed",
        context=context,
        details={"phase": "dispatch"},
    )

    payload = exc.todict()

    assert isinstance(payload, dict)
    assert "error" in payload
    assert payload["error"]["code"] == "providerexecutionerror"
    assert payload["error"]["message"] == "provider transport failed"
    assert payload["error"]["status"] == 502
    assert payload["error"]["provider"] == contracts.SkillProvider.CLAUDE.value
    assert payload["error"]["operation"] == "execute"
    assert payload["error"]["risk"] == contracts.RiskLevel.CRITICAL.value
    assert payload["error"]["requestid"] == "req_456"
    assert payload["error"]["metadata"] == {"layer": "runtime"}
    assert payload["error"]["details"] == {"phase": "dispatch"}