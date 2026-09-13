from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.services.integration_registry import (
    CapabilityName,
    IntegrationRecord,
    IntegrationRegistry,
    get_integration,
    get_integration_registry,
)

VerificationState = Literal["pass", "warn", "fail"]

_REQUIRED_CAPABILITIES: tuple[CapabilityName, ...] = (
    "prompt_interception",
    "tool_interception",
    "execution_interception",
    "telemetry",
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class VerificationCheckResult:
    name: str
    state: VerificationState
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "state": self.state,
            "message": self.message,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class IntegrationVerificationResult:
    integration_id: str
    slug: str
    platform: str
    status: str
    verified: bool
    checked_at: str
    checks: list[VerificationCheckResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    requested_by: str | None = None
    strict: bool = False
    missing_capabilities: list[CapabilityName] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "integration_id": self.integration_id,
            "slug": self.slug,
            "platform": self.platform,
            "status": self.status,
            "verified": self.verified,
            "checked_at": self.checked_at,
            "checks": [check.to_dict() for check in self.checks],
            "metadata": dict(self.metadata),
            "requested_by": self.requested_by,
            "strict": self.strict,
            "missing_capabilities": list(self.missing_capabilities),
            "summary": self.summary,
        }


def _collect_missing_capabilities(record: IntegrationRecord) -> list[CapabilityName]:
    available = {cap.name for cap in record.capabilities if cap.enabled}
    return [capability for capability in _REQUIRED_CAPABILITIES if capability not in available]


def _derive_verification_status(
    *,
    checks: list[VerificationCheckResult],
    missing_capabilities: list[CapabilityName],
    strict: bool,
) -> str:
    if any(check.state == "fail" for check in checks):
        return "blocked"
    if missing_capabilities and strict:
        return "blocked"
    if any(check.state == "warn" for check in checks):
        return "degraded"
    if checks:
        return "ready"
    return "unknown"


def verify_integration(
    registry: IntegrationRegistry,
    integration_id: str,
    *,
    requested_by: str | None = None,
    strict: bool = False,
    extra_metadata: dict[str, Any] | None = None,
) -> IntegrationVerificationResult:
    record = get_integration(registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    missing_capabilities = _collect_missing_capabilities(record)
    checks = _build_verification_checks(record, strict=strict, missing_capabilities=missing_capabilities)
    verified = all(check.state != "fail" for check in checks) and any(check.state == "pass" for check in checks)
    if strict and missing_capabilities:
        verified = False

    metadata = dict(extra_metadata or {})
    if requested_by:
        metadata["requested_by"] = requested_by
    if strict:
        metadata["strict"] = True
    if missing_capabilities:
        metadata["missing_capabilities"] = list(missing_capabilities)

    status = _derive_verification_status(
        checks=checks,
        missing_capabilities=missing_capabilities,
        strict=strict,
    )
    summary = (
        f"Integration '{record.slug}' verification passed with a ready status."
        if verified
        else (f"Integration '{record.slug}' verification is degraded; missing required capabilities: {', '.join(missing_capabilities)}." if missing_capabilities else f"Integration '{record.slug}' verification requires attention.")
    )

    return IntegrationVerificationResult(
        integration_id=record.integration_id,
        slug=record.slug,
        platform=record.platform,
        status=status,
        verified=verified,
        checked_at=_utc_now(),
        checks=checks,
        metadata=metadata,
        requested_by=requested_by or "system",
        strict=strict,
        missing_capabilities=missing_capabilities,
        summary=summary,
    )


def _build_verification_checks(
    record: IntegrationRecord,
    *,
    strict: bool,
    missing_capabilities: list[CapabilityName],
) -> list[VerificationCheckResult]:
    checks: list[VerificationCheckResult] = []

    checks.append(
        VerificationCheckResult(
            name="integration-registered",
            state="pass",
            message=f"Integration '{record.slug}' is registered.",
        ),
    )

    checks.append(
        VerificationCheckResult(
            name="command-available",
            state="pass" if bool(record.command_name) else "warn",
            message="Install command is available." if record.command_name else "Install command is not registered yet.",
            metadata={"command_name": record.command_name},
        ),
    )

    checks.append(
        VerificationCheckResult(
            name="entrypoint-declared",
            state="pass" if bool(record.entrypoint) else "warn",
            message="Adapter entrypoint is declared." if record.entrypoint else "Adapter entrypoint is missing.",
            metadata={"entrypoint": record.entrypoint},
        ),
    )

    checks.append(
        VerificationCheckResult(
            name="install-target-declared",
            state="pass" if bool(record.install_target) else "warn",
            message="Install target is declared." if record.install_target else "Install target is missing.",
            metadata={"install_target": record.install_target},
        ),
    )

    enabled_capabilities = [item.name for item in record.capabilities if item.enabled]
    checks.append(
        VerificationCheckResult(
            name="capabilities-present",
            state="fail" if not enabled_capabilities else ("fail" if missing_capabilities and strict else "pass"),
            message=("Integration capabilities are present." if enabled_capabilities and not missing_capabilities else "Required integration capabilities are missing."),
            metadata={"capabilities": enabled_capabilities, "missing_capabilities": list(missing_capabilities)},
        ),
    )

    is_active = record.status == "active"
    checks.append(
        VerificationCheckResult(
            name="status-active",
            state="pass" if is_active else ("fail" if strict else "warn"),
            message="Integration is active." if is_active else f"Integration status is '{record.status}'.",
            metadata={"status": record.status},
        ),
    )

    if missing_capabilities:
        checks.append(
            VerificationCheckResult(
                name="required-capabilities",
                state="fail" if strict else "warn",
                message=("Required security capabilities are missing: " + ", ".join(missing_capabilities) if missing_capabilities else "Required capabilities are present."),
                metadata={"missing_capabilities": list(missing_capabilities)},
            )
        )

    return checks


def summarize_verification_result(
    result: IntegrationVerificationResult,
) -> dict[str, Any]:
    pass_count = sum(1 for check in result.checks if check.state == "pass")
    warn_count = sum(1 for check in result.checks if check.state == "warn")
    fail_count = sum(1 for check in result.checks if check.state == "fail")

    return {
        "integration_id": result.integration_id,
        "slug": result.slug,
        "platform": result.platform,
        "status": result.status,
        "verified": result.verified,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "checked_at": result.checked_at,
    }


class IntegrationVerifier:
    def __init__(self, registry: IntegrationRegistry | None = None) -> None:
        self._registry = registry or get_integration_registry()

    def verify_integration(
        self,
        integration_id: str,
        *,
        strict: bool = False,
        requestedby: str | None = None,
        extra_metadata: dict[str, Any] | None = None,
    ) -> Any:
        result = verify_integration(
            self._registry,
            integration_id,
            requested_by=requestedby,
            strict=strict,
            extra_metadata=extra_metadata,
        )
        return type(
            "VerifierResponse",
            (),
            {
                "integrationid": result.integration_id,
                "status": result.status,
                "verified": result.verified,
                "verifiedat": result.checked_at,
                "requestedby": requestedby or "system",
                "strict": strict,
                "checks": [
                    type(
                        "VerificationCheck",
                        (),
                        {
                            "checkid": check.name,
                            "label": check.name,
                            "passed": check.state == "pass",
                            "detail": check.message,
                        },
                    )()
                    for check in result.checks
                ],
                "missingcapabilities": [],
                "summary": (f"Integration '{result.slug}' verification {'passed' if result.verified else 'requires attention'}."),
            },
        )()


def get_integration_verifier() -> IntegrationVerifier:
    return IntegrationVerifier()
