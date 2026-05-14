from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from app.services.integration_registry import (
    IntegrationRecord,
    IntegrationRegistry,
    get_integration,
)

VerificationState = Literal["pass", "warn", "fail"]


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
        }


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

    checks = _build_verification_checks(record, strict=strict)
    verified = all(check.state != "fail" for check in checks) and any(check.state == "pass" for check in checks)

    metadata = dict(extra_metadata or {})
    if requested_by:
        metadata["requested_by"] = requested_by
    if strict:
        metadata["strict"] = True

    return IntegrationVerificationResult(
        integration_id=record.integration_id,
        slug=record.slug,
        platform=record.platform,
        status=record.status,
        verified=verified,
        checked_at=_utc_now(),
        checks=checks,
        metadata=metadata,
    )


def _build_verification_checks(
    record: IntegrationRecord,
    *,
    strict: bool,
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
            state="pass" if enabled_capabilities else "fail",
            message="Integration capabilities are present." if enabled_capabilities else "No enabled capabilities are registered.",
            metadata={"capabilities": enabled_capabilities},
        ),
    )

    checks.append(
        VerificationCheckResult(
            name="status-active",
            state="pass" if record.status == "active" else ("fail" if strict else "warn"),
            message="Integration is active." if record.status == "active" else f"Integration status is '{record.status}'.",
            metadata={"status": record.status},
        ),
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
