from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from importlib import import_module
from typing import Any

_CHECK_STATUS_PASS = "pass"
_CHECK_STATUS_WARN = "warn"
_CHECK_STATUS_FAIL = "fail"


def _string(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    lowered = str(value).strip().lower()
    if lowered in {"1", "true", "yes", "y", "on", "enabled"}:
        return True
    if lowered in {"0", "false", "no", "n", "off", "disabled"}:
        return False
    return default


def _safe_call(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> tuple[bool, Any]:
    try:
        return True, fn(*args, **kwargs)
    except Exception as exc:
        return False, exc


def _coerce_check(
    *,
    name: str,
    passed: bool,
    status: str | None = None,
    summary: str = "",
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolved_status = status or (_CHECK_STATUS_PASS if passed else _CHECK_STATUS_FAIL)
    return {
        "name": name,
        "passed": bool(passed),
        "status": resolved_status,
        "summary": summary or name,
        "details": details or {},
    }


def _score_from_checks(checks: list[dict[str, Any]]) -> int:
    if not checks:
        return 0

    total = 0.0
    for check in checks:
        status = _string(check.get("status")).lower()
        if status == _CHECK_STATUS_PASS:
            total += 1.0
        elif status == _CHECK_STATUS_WARN:
            total += 0.5
        else:
            total += 0.0
    return int(round((total / len(checks)) * 100))


def _overall_status(checks: list[dict[str, Any]]) -> str:
    if not checks:
        return _CHECK_STATUS_FAIL
    if any(not check.get("passed", False) and check.get("status") == _CHECK_STATUS_FAIL for check in checks):
        return _CHECK_STATUS_FAIL
    if any(check.get("status") == _CHECK_STATUS_WARN for check in checks):
        return _CHECK_STATUS_WARN
    return _CHECK_STATUS_PASS


def _optional_import(module_name: str) -> Any | None:
    try:
        return import_module(module_name)
    except Exception:
        return None


@dataclass(slots=True)
class DeploymentReadinessService:
    app: Any | None = None
    expected_services: tuple[str, ...] = field(
        default_factory=lambda: (
            "history_service",
            "scanner_service",
            "guard_service",
            "action_policy_service",
            "action_decision_service",
        ),
    )

    def evaluate(self) -> dict[str, Any]:
        checks = [
            self.check_app_state(),
            self.check_persistence_backend(),
            self.check_persistence_health(),
            self.check_migration_readiness(),
            self.check_service_wiring(),
        ]

        score = _score_from_checks(checks)
        status = _overall_status(checks)

        return {
            "ready": status != _CHECK_STATUS_FAIL,
            "status": status,
            "score": score,
            "checks": checks,
            "summary": {
                "total": len(checks),
                "passed": sum(1 for item in checks if item.get("status") == _CHECK_STATUS_PASS),
                "warn": sum(1 for item in checks if item.get("status") == _CHECK_STATUS_WARN),
                "failed": sum(1 for item in checks if item.get("status") == _CHECK_STATUS_FAIL),
            },
        }

    def run(self) -> dict[str, Any]:
        return self.evaluate()

    def check_app_state(self) -> dict[str, Any]:
        if self.app is None:
            return _coerce_check(
                name="app_state",
                passed=False,
                summary="FastAPI app instance is not attached.",
                details={"app_attached": False},
            )

        state = getattr(self.app, "state", None)
        settings_present = hasattr(state, "settings") if state is not None else False

        if not settings_present:
            return _coerce_check(
                name="app_state",
                passed=False,
                summary="App state is missing settings.",
                details={"app_attached": True, "settings_present": False},
            )

        return _coerce_check(
            name="app_state",
            passed=True,
            summary="App state is configured.",
            details={"app_attached": True, "settings_present": True},
        )

    def check_service_wiring(self) -> dict[str, Any]:
        if self.app is None or getattr(self.app, "state", None) is None:
            return _coerce_check(
                name="service_wiring",
                passed=False,
                summary="Cannot verify service wiring without app state.",
            )

        state = self.app.state
        missing = [name for name in self.expected_services if not hasattr(state, name)]

        if missing:
            return _coerce_check(
                name="service_wiring",
                passed=False,
                summary="One or more required services are not wired into app state.",
                details={"missing_services": missing},
            )

        return _coerce_check(
            name="service_wiring",
            passed=True,
            summary="Required app services are wired.",
            details={"services": list(self.expected_services)},
        )

    def check_persistence_backend(self) -> dict[str, Any]:
        module = _optional_import("app.persistencebootstrap")
        if module is None:
            return _coerce_check(
                name="persistence_backend",
                passed=False,
                summary="Persistence bootstrap module is unavailable.",
            )

        build_store = getattr(module, "build_store", None)
        if not callable(build_store):
            return _coerce_check(
                name="persistence_backend",
                passed=False,
                summary="Persistence bootstrap does not expose build_store.",
            )

        ok, result = _safe_call(build_store)
        if not ok:
            return _coerce_check(
                name="persistence_backend",
                passed=False,
                summary="Persistence backend could not be constructed.",
                details={"error": str(result)},
            )

        backend_name = _string(getattr(result, "backend_name", "unknown"), "unknown")
        status = _CHECK_STATUS_PASS
        summary = "Persistence backend is available."

        if backend_name == "memory":
            status = _CHECK_STATUS_WARN
            summary = "Persistence backend is available, but using memory fallback."
        elif backend_name == "unknown":
            status = _CHECK_STATUS_WARN
            summary = "Persistence backend was created, but backend identity is unknown."

        return _coerce_check(
            name="persistence_backend",
            passed=True,
            status=status,
            summary=summary,
            details={"backend_name": backend_name},
        )

    def check_persistence_health(self) -> dict[str, Any]:
        module = _optional_import("app.persistencebootstrap")
        if module is None:
            return _coerce_check(
                name="persistence_health",
                passed=False,
                summary="Persistence bootstrap module is unavailable.",
            )

        build_store = getattr(module, "build_store", None)
        if not callable(build_store):
            return _coerce_check(
                name="persistence_health",
                passed=False,
                summary="Persistence bootstrap does not expose build_store.",
            )

        ok, store = _safe_call(build_store)
        if not ok:
            return _coerce_check(
                name="persistence_health",
                passed=False,
                summary="Persistence backend could not be constructed.",
                details={"error": str(store)},
            )

        healthcheck = getattr(store, "healthcheck", None)
        if not callable(healthcheck):
            return _coerce_check(
                name="persistence_health",
                passed=False,
                summary="Persistence backend does not expose healthcheck.",
                details={"backend_name": _string(getattr(store, "backend_name", "unknown"), "unknown")},
            )

        ok, health_result = _safe_call(healthcheck)
        if not ok:
            return _coerce_check(
                name="persistence_health",
                passed=False,
                summary="Persistence healthcheck raised an exception.",
                details={"error": str(health_result)},
            )

        passed = _bool(health_result, default=False)
        return _coerce_check(
            name="persistence_health",
            passed=passed,
            summary="Persistence healthcheck passed." if passed else "Persistence healthcheck failed.",
            details={"backend_name": _string(getattr(store, "backend_name", "unknown"), "unknown")},
        )

    def check_migration_readiness(self) -> dict[str, Any]:
        module = _optional_import("app.persistencebootstrap")
        if module is None:
            return _coerce_check(
                name="migration_readiness",
                passed=False,
                summary="Persistence bootstrap module is unavailable.",
            )

        migration_function_names = (
            "readiness_report",
            "migration_readiness_report",
            "get_migration_readiness",
            "check_migration_readiness",
            "migration_health",
            "get_persistence_readiness",
        )

        for function_name in migration_function_names:
            fn = getattr(module, function_name, None)
            if not callable(fn):
                continue

            ok, result = _safe_call(fn)
            if not ok:
                return _coerce_check(
                    name="migration_readiness",
                    passed=False,
                    summary="Migration readiness check raised an exception.",
                    details={"function": function_name, "error": str(result)},
                )

            if isinstance(result, dict):
                ready = _bool(
                    result.get("ready"),
                    default=_bool(result.get("ok"), default=_bool(result.get("passed"), default=False)),
                )
                warnings = result.get("warnings") or []
                status = _CHECK_STATUS_PASS if ready else _CHECK_STATUS_FAIL
                summary = "Migration readiness checks passed." if ready else "Migration readiness checks failed."
                if ready and warnings:
                    status = _CHECK_STATUS_WARN
                    summary = "Migration readiness passed with warnings."
                return _coerce_check(
                    name="migration_readiness",
                    passed=ready,
                    status=status,
                    summary=summary,
                    details={"function": function_name, "report": result},
                )

            ready = _bool(result, default=False)
            return _coerce_check(
                name="migration_readiness",
                passed=ready,
                summary="Migration readiness checks passed." if ready else "Migration readiness checks failed.",
                details={"function": function_name, "result": result},
            )

        migration_module_candidates = (
            "app.services.persistencebootstrap",
            "app.persistence",
            "app.migrations",
        )

        available_modules = [name for name in migration_module_candidates if _optional_import(name) is not None]

        if available_modules:
            return _coerce_check(
                name="migration_readiness",
                passed=True,
                status=_CHECK_STATUS_WARN,
                summary="Migration modules exist, but no explicit readiness function was found.",
                details={"modules": available_modules},
            )

        return _coerce_check(
            name="migration_readiness",
            passed=False,
            summary="No migration readiness integration was found.",
            details={
                "expected_functions": list(migration_function_names),
                "high_risk_note": "Database migrations are a high-risk deployment step and should be explicitly validated.",
            },
        )


def build_deployment_readiness_service(app: Any | None = None) -> DeploymentReadinessService:
    return DeploymentReadinessService(app=app)


def create_deployment_readiness_service(app: Any | None = None) -> DeploymentReadinessService:
    return build_deployment_readiness_service(app=app)


def get_deployment_readiness_service(app: Any | None = None) -> DeploymentReadinessService:
    return build_deployment_readiness_service(app=app)
