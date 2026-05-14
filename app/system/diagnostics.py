from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled", "ok", "healthy", "ready"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled", "error", "failed", "down"}:
            return False
    if isinstance(value, (int, float)):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        candidate = candidate.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return default
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return default


@dataclass(frozen=True, slots=True)
class DiagnosticCheck:
    name: str
    category: str
    status: str
    healthy: bool
    message: str = ""
    observed_value: str = ""
    expected_value: str = ""
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "healthy": self.healthy,
            "message": self.message,
            "observed_value": self.observed_value,
            "expected_value": self.expected_value,
            "checked_at": _isoformat(self.checked_at),
        }


@dataclass(frozen=True, slots=True)
class SystemDiagnostics:
    service: str = "ironclaw-security"
    environment: str = "local"
    version: str = "dev"
    overall_status: str = "healthy"
    healthy: bool = True
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_percent: float = 0.0
    latency_ms: float = 0.0
    policy_bundle_loaded: bool = True
    sandbox_ready: bool = True
    telemetry_ready: bool = True
    review_queue_ready: bool = True
    database_ready: bool = True
    warnings: tuple[str, ...] = ()
    failures: tuple[str, ...] = ()
    checks: tuple[DiagnosticCheck, ...] = ()
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "version": self.version,
            "overall_status": self.overall_status,
            "healthy": self.healthy,
            "cpu_percent": self.cpu_percent,
            "memory_percent": self.memory_percent,
            "disk_percent": self.disk_percent,
            "latency_ms": self.latency_ms,
            "policy_bundle_loaded": self.policy_bundle_loaded,
            "sandbox_ready": self.sandbox_ready,
            "telemetry_ready": self.telemetry_ready,
            "review_queue_ready": self.review_queue_ready,
            "database_ready": self.database_ready,
            "warnings": list(self.warnings),
            "failures": list(self.failures),
            "checks": [check.to_dict() for check in self.checks],
            "checked_at": _isoformat(self.checked_at),
        }


def _normalize_check(item: Any) -> DiagnosticCheck | None:
    if not isinstance(item, dict):
        return None

    status = _coerce_str(item.get("status"), "unknown").lower() or "unknown"
    healthy = _coerce_bool(item.get("healthy"), status in {"ok", "pass", "healthy", "ready"})
    checked_at = _coerce_datetime(item.get("checked_at"), _utc_now()) or _utc_now()

    return DiagnosticCheck(
        name=_coerce_str(item.get("name"), "unnamed-check") or "unnamed-check",
        category=_coerce_str(item.get("category"), "system") or "system",
        status=status,
        healthy=healthy,
        message=_coerce_str(item.get("message")),
        observed_value=_coerce_str(item.get("observed_value")),
        expected_value=_coerce_str(item.get("expected_value")),
        checked_at=checked_at,
    )


def _default_checks(now: datetime) -> tuple[DiagnosticCheck, ...]:
    return (
        DiagnosticCheck(
            name="policy-bundle",
            category="policy",
            status="healthy",
            healthy=True,
            message="Policy bundle loaded.",
            observed_value="loaded",
            expected_value="loaded",
            checked_at=now,
        ),
        DiagnosticCheck(
            name="sandbox-runtime",
            category="runtime",
            status="healthy",
            healthy=True,
            message="Sandbox runtime ready.",
            observed_value="ready",
            expected_value="ready",
            checked_at=now,
        ),
        DiagnosticCheck(
            name="telemetry-pipeline",
            category="telemetry",
            status="healthy",
            healthy=True,
            message="Telemetry pipeline operational.",
            observed_value="ready",
            expected_value="ready",
            checked_at=now,
        ),
        DiagnosticCheck(
            name="review-queue",
            category="review",
            status="healthy",
            healthy=True,
            message="Review queue available.",
            observed_value="ready",
            expected_value="ready",
            checked_at=now,
        ),
        DiagnosticCheck(
            name="database-connection",
            category="persistence",
            status="healthy",
            healthy=True,
            message="Database connection verified.",
            observed_value="ready",
            expected_value="ready",
            checked_at=now,
        ),
    )


def default_system_diagnostics() -> SystemDiagnostics:
    now = _utc_now()
    return SystemDiagnostics(checks=_default_checks(now), checked_at=now)


def build_system_diagnostics(
    data: dict[str, Any] | None = None,
    *,
    baseline: SystemDiagnostics | None = None,
) -> SystemDiagnostics:
    source = data or {}
    current = baseline or default_system_diagnostics()
    checked_at = _coerce_datetime(source.get("checked_at"), _utc_now()) or _utc_now()

    raw_checks = source.get("checks")
    checks: tuple[DiagnosticCheck, ...]
    if isinstance(raw_checks, list):
        normalized = tuple(check for item in raw_checks if (check := _normalize_check(item)) is not None)
        checks = normalized or current.checks
    else:
        checks = current.checks

    policy_bundle_loaded = _coerce_bool(source.get("policy_bundle_loaded"), current.policy_bundle_loaded)
    sandbox_ready = _coerce_bool(source.get("sandbox_ready"), current.sandbox_ready)
    telemetry_ready = _coerce_bool(source.get("telemetry_ready"), current.telemetry_ready)
    review_queue_ready = _coerce_bool(source.get("review_queue_ready"), current.review_queue_ready)
    database_ready = _coerce_bool(source.get("database_ready"), current.database_ready)

    warnings = tuple(_coerce_str(item) for item in (source.get("warnings") if isinstance(source.get("warnings"), list) else list(current.warnings)) if _coerce_str(item))
    failures = tuple(_coerce_str(item) for item in (source.get("failures") if isinstance(source.get("failures"), list) else list(current.failures)) if _coerce_str(item))

    derived_healthy = all(
        (
            policy_bundle_loaded,
            sandbox_ready,
            telemetry_ready,
            review_queue_ready,
            database_ready,
            not failures,
            all(check.healthy for check in checks),
        ),
    )
    derived_status = "healthy" if derived_healthy and not warnings else "degraded" if derived_healthy else "unhealthy"

    overall_status = _coerce_str(source.get("overall_status"), derived_status).lower() or derived_status
    healthy = _coerce_bool(source.get("healthy"), derived_healthy)

    return SystemDiagnostics(
        service=_coerce_str(source.get("service"), current.service) or current.service,
        environment=_coerce_str(source.get("environment"), current.environment) or current.environment,
        version=_coerce_str(source.get("version"), current.version) or current.version,
        overall_status=overall_status,
        healthy=healthy,
        cpu_percent=max(0.0, min(100.0, _coerce_float(source.get("cpu_percent"), current.cpu_percent))),
        memory_percent=max(0.0, min(100.0, _coerce_float(source.get("memory_percent"), current.memory_percent))),
        disk_percent=max(0.0, min(100.0, _coerce_float(source.get("disk_percent"), current.disk_percent))),
        latency_ms=max(0.0, _coerce_float(source.get("latency_ms"), current.latency_ms)),
        policy_bundle_loaded=policy_bundle_loaded,
        sandbox_ready=sandbox_ready,
        telemetry_ready=telemetry_ready,
        review_queue_ready=review_queue_ready,
        database_ready=database_ready,
        warnings=warnings,
        failures=failures,
        checks=checks,
        checked_at=checked_at,
    )


def diagnostics_summary(diagnostics: SystemDiagnostics) -> dict[str, Any]:
    healthy_checks = sum(1 for check in diagnostics.checks if check.healthy)
    degraded_checks = sum(1 for check in diagnostics.checks if check.status in {"warn", "warning", "degraded"})
    failed_checks = sum(1 for check in diagnostics.checks if not check.healthy)

    return {
        "service": diagnostics.service,
        "environment": diagnostics.environment,
        "version": diagnostics.version,
        "overall_status": diagnostics.overall_status,
        "healthy": diagnostics.healthy,
        "resource_usage": {
            "cpu_percent": diagnostics.cpu_percent,
            "memory_percent": diagnostics.memory_percent,
            "disk_percent": diagnostics.disk_percent,
            "latency_ms": diagnostics.latency_ms,
        },
        "dependencies": {
            "policy_bundle_loaded": diagnostics.policy_bundle_loaded,
            "sandbox_ready": diagnostics.sandbox_ready,
            "telemetry_ready": diagnostics.telemetry_ready,
            "review_queue_ready": diagnostics.review_queue_ready,
            "database_ready": diagnostics.database_ready,
        },
        "check_totals": {
            "total": len(diagnostics.checks),
            "healthy": healthy_checks,
            "degraded": degraded_checks,
            "failed": failed_checks,
        },
        "warnings": list(diagnostics.warnings),
        "failures": list(diagnostics.failures),
        "checked_at": _isoformat(diagnostics.checked_at),
    }
