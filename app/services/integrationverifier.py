from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.services.integrationregistry import (
    CapabilityName,
    IntegrationRecord,
    get_integration_registry,
)


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