from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# Protocols
# ---------------------------------------------------------------------------


@runtime_checkable
class _VerifierProtocol(Protocol):
    def verify(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class _RegistryProtocol(Protocol):
    def install_runtime(self, **kwargs: Any) -> Any: ...
    def activate_runtime(self, **kwargs: Any) -> Any: ...


# ---------------------------------------------------------------------------
# Install result — used by build_integration_installer / IntegrationInstaller
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class IntegrationInstallResult:
    ok: bool
    installed: bool
    active: bool
    runtime: str
    status: str
    verdict: str
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    _verification: dict[str, Any] = field(default_factory=dict)
    _installation: dict[str, Any] = field(default_factory=dict)
    _activation: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "installed": self.installed,
            "active": self.active,
            "runtime": self.runtime,
            "status": self.status,
            "verdict": self.verdict,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
            "verification": dict(self._verification),
            "installation": dict(self._installation),
            "activation": dict(self._activation),
        }


# ---------------------------------------------------------------------------
# Route-layer install result — used by get_integration_installer()
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class InstallStep:
    stepid: str
    label: str
    completed: bool
    detail: str


@dataclass(slots=True)
class RouteInstallResult:
    integrationid: str
    status: str
    installed: bool
    installedat: str | None
    requestedby: str
    steps: list[InstallStep]
    summary: str


# ---------------------------------------------------------------------------
# Guard helpers
# ---------------------------------------------------------------------------


def _deduplicate_rules(rules: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _deduplicate_reasons(reasons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    for item in reasons:
        if item not in seen:
            seen.append(item)
    return seen


def _blocked(
    *,
    runtime: str,
    rule: str,
    reason_label: str,
    reason_details: str,
) -> IntegrationInstallResult:
    return IntegrationInstallResult(
        ok=False,
        installed=False,
        active=False,
        runtime=runtime,
        status="blocked",
        verdict="block",
        matched_rules=[rule],
        reasons=[{"label": reason_label, "details": reason_details}],
    )


# ---------------------------------------------------------------------------
# Installer — used by build_integration_installer
# ---------------------------------------------------------------------------


class IntegrationInstaller:
    def __init__(
        self,
        *,
        integration_verifier: _VerifierProtocol,
        integration_registry: _RegistryProtocol,
    ) -> None:
        self._verifier = integration_verifier
        self._registry = integration_registry

    def install(
        self,
        *,
        runtime: str,
        bundle: Any,
        signature: str,
        secret: str,
        manifest: dict[str, Any],
        action: str = "install",
        context: dict[str, Any] | None = None,
        activate: bool = True,
    ) -> IntegrationInstallResult:
        ctx = dict(context or {})

        if not (runtime or "").strip():
            return _blocked(
                runtime=runtime,
                rule="missing_runtime",
                reason_label="Missing runtime",
                reason_details="runtime must not be blank",
            )
        if bundle is None:
            return _blocked(
                runtime=runtime,
                rule="missing_bundle",
                reason_label="Missing bundle",
                reason_details="bundle must not be None",
            )
        if not (signature or "").strip():
            return _blocked(
                runtime=runtime,
                rule="missing_signature",
                reason_label="Missing signature",
                reason_details="signature must not be blank",
            )

        verification = self._verifier.verify(
            runtime=runtime,
            bundle=bundle,
            signature=signature,
            secret=secret,
            manifest=manifest,
            action=action,
            context=ctx,
        )
        v_dict = verification.as_dict() if hasattr(verification, "as_dict") else {}
        v_rules: list[str] = list(getattr(verification, "matched_rules", []) or [])
        v_reasons: list[dict[str, Any]] = list(getattr(verification, "reasons", []) or [])

        if not getattr(verification, "ok", False) or not getattr(verification, "allowed", False):
            return IntegrationInstallResult(
                ok=False,
                installed=False,
                active=False,
                runtime=runtime,
                status="blocked",
                verdict=getattr(verification, "verdict", "block"),
                matched_rules=_deduplicate_rules(v_rules),
                reasons=_deduplicate_reasons(v_reasons),
                _verification=v_dict,
            )

        install_result = self._registry.install_runtime(
            runtime=runtime,
            bundle=bundle,
            manifest=manifest,
            action=action,
            context=ctx,
        )
        i_dict = install_result.as_dict() if hasattr(install_result, "as_dict") else {}
        i_rules: list[str] = list(getattr(install_result, "matched_rules", []) or [])
        i_reasons: list[dict[str, Any]] = list(getattr(install_result, "reasons", []) or [])

        if not getattr(install_result, "ok", False) or not getattr(install_result, "installed", False):
            merged_rules = _deduplicate_rules(v_rules + i_rules)
            merged_reasons = _deduplicate_reasons(v_reasons + i_reasons)
            return IntegrationInstallResult(
                ok=False,
                installed=False,
                active=False,
                runtime=runtime,
                status=getattr(install_result, "status", "failed"),
                verdict=getattr(install_result, "verdict", "error") if hasattr(install_result, "verdict") else "error",
                matched_rules=merged_rules,
                reasons=merged_reasons,
                _verification=v_dict,
                _installation=i_dict,
            )

        if not activate:
            merged_rules = _deduplicate_rules(v_rules + i_rules)
            merged_reasons = _deduplicate_reasons(v_reasons + i_reasons)
            return IntegrationInstallResult(
                ok=True,
                installed=True,
                active=False,
                runtime=runtime,
                status=getattr(install_result, "status", "installed"),
                verdict="allow",
                matched_rules=merged_rules,
                reasons=merged_reasons,
                _verification=v_dict,
                _installation=i_dict,
            )

        activate_result = self._registry.activate_runtime(
            runtime=runtime,
            bundle=bundle,
            context=ctx,
        )
        a_dict = activate_result.as_dict() if hasattr(activate_result, "as_dict") else {}
        a_rules: list[str] = list(getattr(activate_result, "matched_rules", []) or [])
        a_reasons: list[dict[str, Any]] = list(getattr(activate_result, "reasons", []) or [])

        merged_rules = _deduplicate_rules(v_rules + i_rules + a_rules)
        merged_reasons = _deduplicate_reasons(v_reasons + i_reasons + a_reasons)

        if not getattr(activate_result, "ok", False) or not getattr(activate_result, "active", False):
            return IntegrationInstallResult(
                ok=False,
                installed=True,
                active=False,
                runtime=runtime,
                status=getattr(activate_result, "status", "activation_failed"),
                verdict="error",
                matched_rules=merged_rules,
                reasons=merged_reasons,
                _verification=v_dict,
                _installation=i_dict,
                _activation=a_dict,
            )

        return IntegrationInstallResult(
            ok=True,
            installed=True,
            active=True,
            runtime=runtime,
            status=getattr(activate_result, "status", "active"),
            verdict="allow",
            matched_rules=merged_rules,
            reasons=merged_reasons,
            _verification=v_dict,
            _installation=i_dict,
            _activation=a_dict,
        )


# ---------------------------------------------------------------------------
# Factory — build_integration_installer
# ---------------------------------------------------------------------------


def build_integration_installer(
    *,
    integration_verifier: _VerifierProtocol,
    integration_registry: _RegistryProtocol,
) -> IntegrationInstaller:
    return IntegrationInstaller(
        integration_verifier=integration_verifier,
        integration_registry=integration_registry,
    )


# ---------------------------------------------------------------------------
# Route-layer installer — used by app/api/integrations.py
# ---------------------------------------------------------------------------


class _RouteInstaller:
    def install_integration(
        self,
        integrationid: str,
        *,
        requestedby: str = "system",
    ) -> RouteInstallResult | None:
        from app.services.integrationregistry import get_integration_registry

        registry = get_integration_registry()
        record = registry.install_integration(integrationid)
        if record is None:
            return None

        from datetime import UTC, datetime

        now = datetime.now(UTC).isoformat()
        steps: list[InstallStep] = [
            InstallStep(
                stepid="step-preflight",
                label="Pre-flight check",
                completed=True,
                detail="integration record located",
            ),
            InstallStep(
                stepid="step-install",
                label="Install runtime",
                completed=True,
                detail=f"installed at {record.installedat or now}",
            ),
        ]
        return RouteInstallResult(
            integrationid=record.integrationid,
            status=record.status,
            installed=True,
            installedat=record.installedat or now,
            requestedby=requestedby,
            steps=steps,
            summary=f"integration {record.integrationid} installed successfully",
        )


_route_installer = _RouteInstaller()


def get_integration_installer() -> _RouteInstaller:
    return _route_installer
