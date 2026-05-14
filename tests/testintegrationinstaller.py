from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from app.services.integrationinstaller import build_integration_installer


@dataclass(slots=True)
class _VerificationResult:
    ok: bool = True
    allowed: bool = True
    runtime: str = "openclaw"
    verdict: str = "allow"
    matched_rules: list[str] | None = None
    reasons: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.matched_rules is None:
            self.matched_rules = []
        if self.reasons is None:
            self.reasons = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "allowed": self.allowed,
            "runtime": self.runtime,
            "verdict": self.verdict,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class _RegistryInstallResult:
    ok: bool = True
    installed: bool = True
    runtime: str = "openclaw"
    adapter: str = "openclaw"
    status: str = "installed"
    matched_rules: list[str] | None = None
    reasons: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.matched_rules is None:
            self.matched_rules = []
        if self.reasons is None:
            self.reasons = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "installed": self.installed,
            "runtime": self.runtime,
            "adapter": self.adapter,
            "status": self.status,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
        }


@dataclass(slots=True)
class _ActivateResult:
    ok: bool = True
    active: bool = True
    runtime: str = "openclaw"
    status: str = "active"
    matched_rules: list[str] | None = None
    reasons: list[dict[str, Any]] | None = None

    def __post_init__(self) -> None:
        if self.matched_rules is None:
            self.matched_rules = []
        if self.reasons is None:
            self.reasons = []

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "active": self.active,
            "runtime": self.runtime,
            "status": self.status,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
        }


class _IntegrationVerifierStub:
    def __init__(self, result: _VerificationResult | None = None) -> None:
        self.result = result or _VerificationResult()
        self.calls: list[dict[str, Any]] = []

    def verify(self, **kwargs: Any) -> _VerificationResult:
        self.calls.append(dict(kwargs))
        return self.result


class _IntegrationRegistryStub:
    def __init__(
        self,
        install_result: _RegistryInstallResult | None = None,
        activate_result: _ActivateResult | None = None,
    ) -> None:
        self.install_result = install_result or _RegistryInstallResult()
        self.activate_result = activate_result or _ActivateResult()
        self.install_calls: list[dict[str, Any]] = []
        self.activate_calls: list[dict[str, Any]] = []

    def install_runtime(self, **kwargs: Any) -> _RegistryInstallResult:
        self.install_calls.append(dict(kwargs))
        return self.install_result

    def activate_runtime(self, **kwargs: Any) -> _ActivateResult:
        self.activate_calls.append(dict(kwargs))
        return self.activate_result


def _build(
    *,
    verification: _VerificationResult | None = None,
    install_result: _RegistryInstallResult | None = None,
    activate_result: _ActivateResult | None = None,
):
    verifier = _IntegrationVerifierStub(verification)
    registry = _IntegrationRegistryStub(install_result, activate_result)
    installer = build_integration_installer(
        integration_verifier=verifier,
        integration_registry=registry,
    )
    return installer, verifier, registry


def _bundle() -> dict[str, Any]:
    return {
        "bundle_id": "bundle-001",
        "version": "2026.04.25",
        "policy": {
            "default_verdict": "allow",
            "rules": [{"id": "safe-rule", "action": "allow"}],
        },
        "metadata": {"issuer": "ironclaw"},
    }


def test_installer_verifies_then_installs_runtime():
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=True,
            allowed=True,
            runtime="openclaw",
            verdict="allow",
            matched_rules=["bundle:verified", "adapter:ready"],
        ),
        install_result=_RegistryInstallResult(
            ok=True,
            installed=True,
            runtime="openclaw",
            adapter="openclaw",
            status="installed",
            matched_rules=["install:complete"],
        ),
        activate_result=_ActivateResult(
            ok=True,
            active=True,
            runtime="openclaw",
            status="active",
            matched_rules=["activate:complete"],
        ),
    )

    result = installer.install(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
        context={"organization_id": "org-001"},
        activate=True,
    )

    assert result.ok is True
    assert result.installed is True
    assert result.active is True
    assert result.runtime == "openclaw"
    assert result.status in {"active", "installed"}
    assert "bundle:verified" in result.matched_rules
    assert "install:complete" in result.matched_rules
    assert "activate:complete" in result.matched_rules
    assert len(verifier.calls) == 1
    assert len(registry.install_calls) == 1
    assert len(registry.activate_calls) == 1


def test_installer_stops_when_verification_fails():
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=False,
            allowed=False,
            runtime="claude",
            verdict="block",
            matched_rules=["signature_mismatch"],
            reasons=[{"label": "Bad signature", "details": "Bundle verification failed"}],
        ),
    )

    result = installer.install(
        runtime="claude",
        bundle=_bundle(),
        signature="bad-signature",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
    )

    assert result.ok is False
    assert result.installed is False
    assert result.active is False
    assert result.verdict in {"block", "reject"}
    assert "signature_mismatch" in result.matched_rules
    assert len(verifier.calls) == 1
    assert len(registry.install_calls) == 0
    assert len(registry.activate_calls) == 0


def test_installer_returns_install_result_without_activation_when_activate_false():
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=True,
            allowed=True,
            runtime="groq",
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        install_result=_RegistryInstallResult(
            ok=True,
            installed=True,
            runtime="groq",
            adapter="groq",
            status="installed",
            matched_rules=["install:complete"],
        ),
    )

    result = installer.install(
        runtime="groq",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
        activate=False,
    )

    assert result.ok is True
    assert result.installed is True
    assert result.active is False
    assert result.runtime == "groq"
    assert "install:complete" in result.matched_rules
    assert len(registry.install_calls) == 1
    assert len(registry.activate_calls) == 0


def test_installer_reports_install_failure():
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=True,
            allowed=True,
            runtime="future-runtime",
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        install_result=_RegistryInstallResult(
            ok=False,
            installed=False,
            runtime="future-runtime",
            adapter="future-runtime",
            status="failed",
            matched_rules=["install:failed"],
            reasons=[{"label": "Install failed", "details": "Adapter install error"}],
        ),
    )

    result = installer.install(
        runtime="future-runtime",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
    )

    assert result.ok is False
    assert result.installed is False
    assert result.active is False
    assert result.verdict in {"error", "block", "failed"}
    assert "install:failed" in result.matched_rules
    assert len(registry.install_calls) == 1
    assert len(registry.activate_calls) == 0


def test_installer_reports_activation_failure_after_successful_install():
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=True,
            allowed=True,
            runtime="openclaw",
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        install_result=_RegistryInstallResult(
            ok=True,
            installed=True,
            runtime="openclaw",
            adapter="openclaw",
            status="installed",
            matched_rules=["install:complete"],
        ),
        activate_result=_ActivateResult(
            ok=False,
            active=False,
            runtime="openclaw",
            status="activation_failed",
            matched_rules=["activate:failed"],
            reasons=[{"label": "Activation failed", "details": "Runtime did not come online"}],
        ),
    )

    result = installer.install(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
        activate=True,
    )

    assert result.ok is False
    assert result.installed is True
    assert result.active is False
    assert "install:complete" in result.matched_rules
    assert "activate:failed" in result.matched_rules
    assert len(registry.install_calls) == 1
    assert len(registry.activate_calls) == 1


def test_installer_passes_all_material_to_verifier_and_registry():
    installer, verifier, registry = _build()

    result = installer.install(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install.runtime",
        context={"organization_id": "org-001", "environment": "prod"},
        activate=True,
    )

    assert result.ok is True
    assert verifier.calls[0]["runtime"] == "openclaw"
    assert verifier.calls[0]["bundle"]["bundle_id"] == "bundle-001"
    assert verifier.calls[0]["action"] == "install.runtime"
    assert verifier.calls[0]["context"]["environment"] == "prod"
    assert registry.install_calls[0]["runtime"] == "openclaw"
    assert registry.install_calls[0]["context"]["organization_id"] == "org-001"
    assert registry.activate_calls[0]["runtime"] == "openclaw"


def test_missing_runtime_is_rejected_early():
    installer, verifier, registry = _build()

    result = installer.install(
        runtime="",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
    )

    assert result.ok is False
    assert result.installed is False
    assert result.active is False
    assert result.verdict == "block"
    assert "missing_runtime" in result.matched_rules
    assert len(verifier.calls) == 0
    assert len(registry.install_calls) == 0


def test_missing_bundle_is_rejected_early():
    installer, verifier, registry = _build()

    result = installer.install(
        runtime="openclaw",
        bundle=None,
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
    )

    assert result.ok is False
    assert result.installed is False
    assert result.active is False
    assert result.verdict == "block"
    assert "missing_bundle" in result.matched_rules
    assert len(verifier.calls) == 0
    assert len(registry.install_calls) == 0


def test_missing_signature_is_rejected_early():
    installer, verifier, registry = _build()

    result = installer.install(
        runtime="openclaw",
        bundle=_bundle(),
        signature="",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
    )

    assert result.ok is False
    assert result.installed is False
    assert result.active is False
    assert result.verdict == "block"
    assert "missing_signature" in result.matched_rules
    assert len(verifier.calls) == 0


@pytest.mark.parametrize("runtime_name", ["openclaw", "claude", "groq", "future-runtime"])
def test_installer_supports_cross_platform_runtimes(runtime_name: str):
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=True,
            allowed=True,
            runtime=runtime_name,
            verdict="allow",
            matched_rules=["bundle:verified"],
        ),
        install_result=_RegistryInstallResult(
            ok=True,
            installed=True,
            runtime=runtime_name,
            adapter=runtime_name,
            status="installed",
            matched_rules=["install:complete"],
        ),
    )

    result = installer.install(
        runtime=runtime_name,
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
        activate=False,
    )

    assert result.ok is True
    assert result.runtime == runtime_name
    assert verifier.calls[0]["runtime"] == runtime_name
    assert registry.install_calls[0]["runtime"] == runtime_name


def test_result_as_dict_contains_component_sections():
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=True,
            allowed=True,
            runtime="openclaw",
            verdict="allow",
            matched_rules=["bundle:verified"],
            reasons=[{"label": "Verified", "details": "Signature valid"}],
        ),
        install_result=_RegistryInstallResult(
            ok=True,
            installed=True,
            runtime="openclaw",
            adapter="openclaw",
            status="installed",
            matched_rules=["install:complete"],
        ),
        activate_result=_ActivateResult(
            ok=True,
            active=True,
            runtime="openclaw",
            status="active",
            matched_rules=["activate:complete"],
        ),
    )

    result = installer.install(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
        activate=True,
    )
    body = result.as_dict()

    assert body["ok"] is True
    assert body["installed"] is True
    assert body["active"] is True
    assert body["runtime"] == "openclaw"
    assert isinstance(body["matchedrules"], list)
    assert isinstance(body["reasons"], list)
    assert isinstance(body["verification"], dict)
    assert isinstance(body["installation"], dict)
    assert isinstance(body["activation"], dict)


def test_rules_and_reasons_are_deduplicated_across_steps():
    repeated_reason = {"label": "Same", "details": "duplicate", "score": 10}
    installer, verifier, registry = _build(
        verification=_VerificationResult(
            ok=True,
            allowed=True,
            runtime="openclaw",
            verdict="allow",
            matched_rules=["dup-rule", "dup-rule"],
            reasons=[repeated_reason, repeated_reason],
        ),
        install_result=_RegistryInstallResult(
            ok=True,
            installed=True,
            runtime="openclaw",
            adapter="openclaw",
            status="installed",
            matched_rules=["dup-rule"],
            reasons=[repeated_reason],
        ),
        activate_result=_ActivateResult(
            ok=True,
            active=True,
            runtime="openclaw",
            status="active",
            matched_rules=["dup-rule"],
            reasons=[repeated_reason],
        ),
    )

    result = installer.install(
        runtime="openclaw",
        bundle=_bundle(),
        signature="signed-bundle",
        secret="ironclaw-secret",
        manifest={"bundleid": "bundle-001", "version": "2026.04.25"},
        action="install",
        activate=True,
    )

    assert result.matched_rules.count("dup-rule") == 1
    duplicates = [item for item in result.reasons if item.get("label") == "Same" and item.get("details") == "duplicate"]
    assert len(duplicates) == 1
