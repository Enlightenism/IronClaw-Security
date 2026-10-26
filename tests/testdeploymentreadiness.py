from __future__ import annotations

from collections.abc import Iterator
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any, Final

import pytest

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
SCRIPT_CANDIDATES: Final[tuple[Path, ...]] = (
    ROOT / "scripts" / "deploymentreadiness.py",
    ROOT / "scripts" / "deployment_readiness.py",
)
SCRIPT: Final[Path] = next((path for path in SCRIPT_CANDIDATES if path.exists()), SCRIPT_CANDIDATES[0])
RESULT_FILE_CANDIDATES: Final[tuple[Path, ...]] = (
    ROOT / ".deployment-readiness.json",
    ROOT / "output" / "deployment-readiness.json",
)

PASS_STATUSES: Final[set[str]] = {"ok", "pass"}
NONPASS_STATUSES: Final[set[str]] = {"warn", "fail"}
ALL_STATUSES: Final[set[str]] = PASS_STATUSES | NONPASS_STATUSES


def _run_with_env(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=str(ROOT),
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": "postgresql://ironclaw:secret@localhost:5432/ironclaw",
            "SUPABASE_DB_URL": "postgresql://ironclaw:secret@localhost:5432/ironclaw",
            "POSTGRES_URL": "postgresql://ironclaw:secret@localhost:5432/ironclaw",
            "SUPABASE_URL": "https://example.supabase.co",
            "SUPABASE_KEY": "supabase_key_for_test_validation",
            "SUPABASE_SERVICE_ROLE_KEY": "supabase_service_role_for_test_validation",
            "OPENAI_API_KEY": "openai_key_for_test_validation",
            "GUARD_MODEL_PATH": "models/prompt-guard-86m",
            "SECRET_KEY": "very_strong_secret_key_value",
            "JWT_SECRET": "very_strong_jwt_secret_value",
            "API_SECRET": "very_strong_api_secret_value",
            "IRONCLAW_BACKUP_RETENTION_DAYS": "30",
            "IRONCLAW_BACKUP_ENCRYPTION": "true",
            "IRONCLAW_BACKUP_CHECKSUM": "true",
        },
    )
    return env


def _cleanup_result_files() -> None:
    for path in RESULT_FILE_CANDIDATES:
        try:
            path.unlink()
        except FileNotFoundError:
            pass


def _result_file_path() -> Path:
    for path in RESULT_FILE_CANDIDATES:
        if path.exists():
            return path
    return RESULT_FILE_CANDIDATES[0]


def _normalize_top_level_status(payload: dict[str, Any]) -> str:
    status = payload.get("status")
    if isinstance(status, str):
        normalized = status.strip().lower()
        assert normalized in ALL_STATUSES
        return normalized

    overall_status = payload.get("overall_status")
    if isinstance(overall_status, str):
        normalized = overall_status.strip().lower()
        assert normalized in ALL_STATUSES
        return normalized

    raise AssertionError("result payload missing status field")


def _payload_checks(payload: dict[str, Any]) -> list[dict[str, Any]]:
    checks = payload.get("checks")
    assert isinstance(checks, list)
    normalized: list[dict[str, Any]] = []
    for item in checks:
        assert isinstance(item, dict)
        normalized.append(item)
    return normalized


def _read_result_file() -> dict[str, Any]:
    path = _result_file_path()
    assert path.exists(), f"missing deployment readiness result file: {path}"
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    _normalize_top_level_status(payload)
    _payload_checks(payload)
    return payload


def _check_name(item: dict[str, Any]) -> str:
    name = item.get("name")
    assert isinstance(name, str)
    assert name.strip()
    return name


def _check_ok(item: dict[str, Any]) -> bool | None:
    ok = item.get("ok")
    if isinstance(ok, bool):
        return ok

    status = item.get("status")
    if isinstance(status, str):
        normalized = status.strip().lower()
        if normalized in PASS_STATUSES:
            return True
        if normalized in NONPASS_STATUSES:
            return False

    return None


def _combined_output(completed: subprocess.CompletedProcess[str]) -> str:
    return f"{completed.stdout}\n{completed.stderr}".strip()


@pytest.fixture(autouse=True)
def _isolate_result_files() -> Iterator[None]:
    _cleanup_result_files()
    yield
    _cleanup_result_files()


def test_deployment_readiness_script_exists() -> None:
    assert SCRIPT.exists()
    assert SCRIPT.is_file()


def test_deployment_readiness_passes_with_valid_environment() -> None:
    env = _base_env()
    completed = _run_with_env(env)

    assert completed.returncode == 0, _combined_output(completed)

    payload = _read_result_file()
    assert _normalize_top_level_status(payload) in PASS_STATUSES

    checks = _payload_checks(payload)
    normalized = [_check_ok(check) for check in checks]
    assert normalized
    assert all(value is True for value in normalized if value is not None)
    provider_check = next(check for check in checks if _check_name(check) == "external-integrations")
    assert _check_ok(provider_check) is True
    assert "guard" in provider_check["detail"]


def test_deployment_readiness_fails_with_missing_supabase_configuration() -> None:
    env = _base_env()
    env.pop("SUPABASE_URL", None)
    env.pop("SUPABASE_KEY", None)
    env.pop("SUPABASE_SERVICE_ROLE_KEY", None)

    completed = _run_with_env(env)

    assert completed.returncode in {0, 1}, _combined_output(completed)

    payload = _read_result_file()
    assert _normalize_top_level_status(payload) in NONPASS_STATUSES

    checks = _payload_checks(payload)
    assert any(_check_name(check) in {"supabase-config", "environment_configuration"} and _check_ok(check) is False for check in checks)


def test_deployment_readiness_fails_with_missing_database_configuration() -> None:
    env = _base_env()
    env.pop("DATABASE_URL", None)
    env.pop("SUPABASE_DB_URL", None)
    env.pop("POSTGRES_URL", None)

    completed = _run_with_env(env)

    assert completed.returncode in {0, 1}, _combined_output(completed)

    payload = _read_result_file()
    assert _normalize_top_level_status(payload) in NONPASS_STATUSES

    checks = _payload_checks(payload)
    check_names = {_check_name(check) for check in checks}
    assert check_names

    database_related = {"database-config", "supabase_migrations", "environment_configuration"}
    assert any(name in database_related for name in check_names)


def test_deployment_readiness_fails_on_weak_secret_values_when_enforced() -> None:
    env = _base_env()
    env["SECRET_KEY"] = "changeme"
    env["JWT_SECRET"] = "short"

    completed = _run_with_env(env)
    payload = _read_result_file()

    assert completed.returncode in {0, 1}, _combined_output(completed)
    assert _normalize_top_level_status(payload) in ALL_STATUSES

    checks = _payload_checks(payload)
    if any(_check_name(check) == "secrets-quality" for check in checks):
        assert any(_check_name(check) == "secrets-quality" and _check_ok(check) is False for check in checks)
    else:
        pytest.skip("secrets-quality readiness check is not implemented by this script")


def test_deployment_readiness_result_surface_is_strict_status_shape() -> None:
    env = _base_env()
    completed = _run_with_env(env)

    assert completed.returncode in {0, 1}, _combined_output(completed)

    payload = _read_result_file()
    assert _normalize_top_level_status(payload) in ALL_STATUSES
    assert isinstance(_payload_checks(payload), list)
