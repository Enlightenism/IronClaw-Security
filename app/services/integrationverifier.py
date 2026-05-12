from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, runtime_checkable

from app.services.integrationregistry import (
    CapabilityName,
    IntegrationRecord,
    get_integration_registry,
)

# ---------------------------------------------------------------------------
# Existing verification types
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class IntegrationVerificationCheck:
    checkid: str
    label: str
    passed: bool
    detail: str


@dataclass(slots=True)
class IntegrationVerificationResult:
    integrationid: str
    platform: str
    status: str
    verified: bool
    verifiedat: str | None
    requestedby: str
    strict: bool
    checks: list[IntegrationVerificationCheck] = field(default_factory=list)
    missingcapabilities: list[CapabilityName] = field(default_factory=list)
    summary: str = ""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class IntegrationVerifier:
    def verify_integration(
        self,
        integrationid: str,
        *,
        strict: bool = False,
        requestedby: str = "system",
    ) -> IntegrationVerificationResult | None:
        normalizedintegrationid = integrationid.strip().lower()
        normalizedrequestedby = requestedby.strip() or "system"

        if not normalizedintegrationid:
            return None

        registry = get_integration_registry()
        record = registry.get_integration(normalizedintegrationid)
        if record is None:
            return None

        checks = self._build_checks(record)
        missingcapabilities = self._collect_missing_capabilities(record)
        verified = all(check.passed for check in checks) and (
            not strict or not missingcapabilities
        )

        status = "ready" if verified else "degraded"
        registry.update_status(record.integrationid, status, verified=verified)

        updated_record = registry.get_integration(record.integrationid)
        verifiedat = updated_record.verifiedat if updated_record is not None else None

        return IntegrationVerificationResult(
            integrationid=record.integrationid,
            platform=record.platform,
            status=status,
            verified=verified,
            verifiedat=verifiedat if verified else None,
            requestedby=normalizedrequestedby,
            strict=strict,
            checks=checks,
            missingcapabilities=missingcapabilities,
            summary=self._build_summary(
                record=record,
                strict=strict,
                verified=verified,
                missingcapabilities=missingcapabilities,
            ),
        )

    def _build_checks(
        self,
        record: IntegrationRecord,
    ) -> list[IntegrationVerificationCheck]:
        return [
            IntegrationVerificationCheck(
                checkid="manifest-route",
                label="Manifest route registered",
                passed=record.manifestroute.startswith("/"),
                detail=record.manifestroute,
            ),
            IntegrationVerificationCheck(
                checkid="settings-route",
                label="Settings route registered",
                passed=record.settingsroute.startswith("/"),
                detail=record.settingsroute,
            ),
            IntegrationVerificationCheck(
                checkid="verification-route",
                label="Verification route registered",
                passed=record.verificationroute.startswith("/"),
                detail=record.verificationroute,
            ),
            IntegrationVerificationCheck(
                checkid="adapter-module",
                label="Adapter module declared",
                passed=bool(record.adaptermodule.strip()),
                detail=record.adaptermodule,
            ),
            IntegrationVerificationCheck(
                checkid="installed-state",
                label="Integration installation state present",
                passed=record.installedat is not None,
                detail=record.installedat or "not-installed",
            ),
        ]

    def _collect_missing_capabilities(
        self,
        record: IntegrationRecord,
    ) -> list[CapabilityName]:
        required_capabilities: tuple[CapabilityName, ...] = (
            "prompt_guard",
            "tool_guard",
            "execution_control",
            "telemetry",
        )
        available = {
            capability.name
            for capability in record.capabilities
            if capability.enabled
        }
        return [
            capability_name
            for capability_name in required_capabilities
            if capability_name not in available
        ]

    def _build_summary(
        self,
        *,
        record: IntegrationRecord,
        strict: bool,
        verified: bool,
        missingcapabilities: list[CapabilityName],
    ) -> str:
        if verified:
            return (
                f"Integration {record.integrationid} passed verification "
                f"with strict={'on' if strict else 'off'}."
            )
        if missingcapabilities:
            return (
                f"Integration {record.integrationid} is missing required capabilities: "
                + ", ".join(missingcapabilities)
                + "."
            )
        return (
            f"Integration {record.integrationid} failed one or more verification checks."
        )


_verifier = IntegrationVerifier()


def get_integration_verifier() -> IntegrationVerifier:
    return _verifier


def verify_integration(
    integrationid: str,
    *,
    strict: bool = False,
    requestedby: str = "system",
) -> IntegrationVerificationResult | None:
    return _verifier.verify_integration(
        integrationid,
        strict=strict,
        requestedby=requestedby,
    )


# ---------------------------------------------------------------------------
# DI verifier — build_integration_verifier for testintegrationverifier.py
# ---------------------------------------------------------------------------


@runtime_checkable
class _BundleSigningProtocol(Protocol):
    def verify_bundle(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class _ReleasePolicyProtocol(Protocol):
    def evaluate(self, **kwargs: Any) -> Any: ...


@runtime_checkable
class _AdapterRegistryProtocol(Protocol):
    def verify_runtime(self, **kwargs: Any) -> Any: ...


def _dedup_rules(rules: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for r in rules:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _dedup_reasons(reasons: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: list[dict[str, Any]] = []
    for item in reasons:
        if item not in seen:
            seen.append(item)
    return seen


@dataclass(slots=True)
class _DIVerifyResult:
    ok: bool
    allowed: bool
    runtime: str
    verdict: str
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    _bundle_verification: dict[str, Any] = field(default_factory=dict)
    _rollout_evaluation: dict[str, Any] = field(default_factory=dict)
    _adapter_verification: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "allowed": self.allowed,
            "runtime": self.runtime,
            "verdict": self.verdict,
            "matchedrules": list(self.matched_rules),
            "reasons": list(self.reasons),
            "bundleverification": dict(self._bundle_verification),
            "rolloutevaluation": dict(self._rollout_evaluation),
            "adapterverification": dict(self._adapter_verification),
        }


def _blocked_early(
    *,
    runtime: str,
    rule: str,
    reason_label: str,
    reason_details: str,
) -> _DIVerifyResult:
    return _DIVerifyResult(
        ok=False,
        allowed=False,
        runtime=runtime,
        verdict="block",
        matched_rules=[rule],
        reasons=[{"label": reason_label, "details": reason_details}],
    )


class _DIIntegrationVerifier:
    def __init__(
        self,
        *,
        policy_bundle_signing_service: _BundleSigningProtocol,
        release_policy_service: _ReleasePolicyProtocol,
        adapter_registry: _AdapterRegistryProtocol,
    ) -> None:
        self._signing = policy_bundle_signing_service
        self._release = release_policy_service
        self._adapter = adapter_registry

    def verify(
        self,
        *,
        runtime: str,
        bundle: Any,
        signature: str,
        secret: str,
        manifest: dict[str, Any],
        action: str = "execute",
        context: dict[str, Any] | None = None,
    ) -> _DIVerifyResult:
        ctx = dict(context or {})

        if not (runtime or "").strip():
            return _blocked_early(
                runtime=runtime,
                rule="missing_runtime",
                reason_label="Missing runtime",
                reason_details="runtime must not be blank",
            )
        if bundle is None:
            return _blocked_early(
                runtime=runtime,
                rule="missing_bundle",
                reason_label="Missing bundle",
                reason_details="bundle must not be None",
            )
        if not (signature or "").strip():
            return _blocked_early(
                runtime=runtime,
                rule="missing_signature",
                reason_label="Missing signature",
                reason_details="signature must not be blank",
            )

        # --- bundle verification ---
        bv = self._signing.verify_bundle(
            runtime=runtime,
            bundle=bundle,
            signature=signature,
            secret=secret,
            manifest=manifest,
            action=action,
            context=ctx,
        )
        bv_dict = bv.as_dict() if hasattr(bv, "as_dict") else {}
        bv_rules: list[str] = list(getattr(bv, "matched_rules", []) or [])
        bv_reasons: list[dict[str, Any]] = list(getattr(bv, "reasons", []) or [])

        if not getattr(bv, "valid", False) or not getattr(bv, "allowed", False):
            return _DIVerifyResult(
                ok=False,
                allowed=False,
                runtime=runtime,
                verdict=getattr(bv, "verdict", "block"),
                matched_rules=_dedup_rules(bv_rules),
                reasons=_dedup_reasons(bv_reasons),
                _bundle_verification=bv_dict,
            )

        # --- rollout evaluation ---
        rv = self._release.evaluate(
            runtime=runtime,
            bundle=bundle,
            action=action,
            context=ctx,
        )
        rv_dict = rv.as_dict() if hasattr(rv, "as_dict") else {}
        rv_rules: list[str] = list(getattr(rv, "matched_rules", []) or [])
        rv_reasons: list[dict[str, Any]] = list(getattr(rv, "reasons", []) or [])

        if not getattr(rv, "enabled", False) or not getattr(rv, "allowed", False):
            merged_rules = _dedup_rules(bv_rules + rv_rules)
            merged_reasons = _dedup_reasons(bv_reasons + rv_reasons)
            return _DIVerifyResult(
                ok=False,
                allowed=False,
                runtime=runtime,
                verdict=getattr(rv, "verdict", "block"),
                matched_rules=merged_rules,
                reasons=merged_reasons,
                _bundle_verification=bv_dict,
                _rollout_evaluation=rv_dict,
            )

        # --- adapter verification ---
        av = self._adapter.verify_runtime(
            runtime=runtime,
            bundle=bundle,
            action=action,
            context=ctx,
        )
        av_dict = av.as_dict() if hasattr(av, "as_dict") else {}
        av_rules: list[str] = list(getattr(av, "matched_rules", []) or [])
        av_reasons: list[dict[str, Any]] = list(getattr(av, "reasons", []) or [])

        merged_rules = _dedup_rules(bv_rules + rv_rules + av_rules)
        merged_reasons = _dedup_reasons(bv_reasons + rv_reasons + av_reasons)

        if not getattr(av, "ok", False) or not getattr(av, "installed", False):
            return _DIVerifyResult(
                ok=False,
                allowed=False,
                runtime=runtime,
                verdict=getattr(av, "verdict", "block") if hasattr(av, "verdict") else "block",
                matched_rules=merged_rules,
                reasons=merged_reasons,
                _bundle_verification=bv_dict,
                _rollout_evaluation=rv_dict,
                _adapter_verification=av_dict,
            )

        return _DIVerifyResult(
            ok=True,
            allowed=True,
            runtime=runtime,
            verdict="allow",
            matched_rules=merged_rules,
            reasons=merged_reasons,
            _bundle_verification=bv_dict,
            _rollout_evaluation=rv_dict,
            _adapter_verification=av_dict,
        )

    def allow(
        self,
        *,
        runtime: str,
        bundle: Any,
        signature: str,
        secret: str,
        manifest: dict[str, Any],
        action: str = "execute",
        context: dict[str, Any] | None = None,
    ) -> bool:
        result = self.verify(
            runtime=runtime,
            bundle=bundle,
            signature=signature,
            secret=secret,
            manifest=manifest,
            action=action,
            context=context,
        )
        return result.ok and result.allowed


def build_integration_verifier(
    *,
    policy_bundle_signing_service: _BundleSigningProtocol,
    release_policy_service: _ReleasePolicyProtocol,
    adapter_registry: _AdapterRegistryProtocol,
) -> _DIIntegrationVerifier:
    return _DIIntegrationVerifier(
        policy_bundle_signing_service=policy_bundle_signing_service,
        release_policy_service=release_policy_service,
        adapter_registry=adapter_registry,
    )