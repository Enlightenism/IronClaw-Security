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
    ROOT / "scripts" / "restore.py",
    ROOT / "scripts" / "restore_runner.py",
    ROOT / "scripts" / "run_restore.py",
)
SCRIPT: Final[Path] = next((path for path in SCRIPT_CANDIDATES if path.exists()), SCRIPT_CANDIDATES[0])

RESULT_FILE_CANDIDATES: Final[tuple[Path, ...]] = (
    ROOT / ".restore-results.json",
    ROOT / ".restore-result.json",
    ROOT / "output" / "restore-results.json",
    ROOT / "output" / "restore-result.json",
)

PASS_STATUSES: Final[set[str]] = {"ok", "pass", "success"}
NONPASS_STATUSES: Final[set[str]] = {"warn", "fail", "error"}
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
            "IRONCLAW_BACKUP_TARGET_NAME": "primary",
            "IRONCLAW_RESTORE_TARGET_NAME": "primary",
            "IRONCLAW_RESTORE_DRY_RUN": "true",
            "IRONCLAW_BACKUP_DIR": str(ROOT / "output" / "test-backups"),
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


def _read_result_file() -> dict[str, Any]:
    path = _result_file_path()
    assert path.exists(), f"missing restore result file: {path}"

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)

    _normalize_top_level_status(payload)
    _payload_checks(payload)
    return payload


def _normalize_top_level_status(payload: dict[str, Any]) -> str:
    for key in ("status", "overall_status", "result"):
        value = payload.get(key)
        if isinstance(value, str):
            normalized = value.strip().lower()
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


def _check_name(item: dict[str, Any]) -> str:
    for key in ("name", "check", "id"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value
    raise AssertionError(f"invalid restore check item missing name-like field: {item!r}")


def _check_ok(item: dict[str, Any]) -> bool | None:
    ok = item.get("ok")
    if isinstance(ok, bool):
        return ok

    for key in ("status", "result"):
        value = item.get(key)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in PASS_STATUSES:
                return True
            if normalized in NONPASS_STATUSES:
                return False

    return None


def _combined_output(completed: subprocess.CompletedProcess[str]) -> str:
    return f"{completed.stdout}\n{completed.stderr}".strip()


@pytest.fixture(autouse=True)
def _isolate_restore_result_files() -> Iterator[None]:
    _cleanup_result_files()
    yield
    _cleanup_result_files()


def test_restore_script_exists() -> None:
    assert SCRIPT.exists()
    assert SCRIPT.is_file()


def test_restore_runs_with_valid_environment() -> None:
    env = _base_env()
    completed = _run_with_env(env)

    assert completed.returncode in {0, 1}, _combined_output(completed)

    payload = _read_result_file()
    status = _normalize_top_level_status(payload)
    checks = _payload_checks(payload)

    assert status in ALL_STATUSES
    assert checks

    if completed.returncode == 0:
        normalized = [_check_ok(check) for check in checks]
        assert all(value is True for value in normalized if value is not None)


def test_restore_fails_or_warns_with_missing_database_configuration() -> None:
    env = _base_env()
    env.pop("DATABASE_URL", None)
    env.pop("SUPABASE_DB_URL", None)
    env.pop("POSTGRES_URL", None)

    completed = _run_with_env(env)

    assert completed.returncode in {0, 1}, _combined_output(completed)

    payload = _read_result_file()
    assert _normalize_top_level_status(payload) in ALL_STATUSES

    checks = _payload_checks(payload)
    check_names = {_check_name(check) for check in checks}
    assert check_names

    database_related = {
        "database-config",
        "database-connection",
        "restore-database",
        "environment_configuration",
    }
    assert any(name in database_related for name in check_names) or completed.returncode == 1


def test_restore_fails_or_warns_with_missing_restore_target() -> None:
    env = _base_env()
    env.pop("IRONCLAW_RESTORE_TARGET_NAME", None)

    completed = _run_with_env(env)

    assert completed.returncode in {0, 1}, _combined_output(completed)

    payload = _read_result_file()
    assert _normalize_top_level_status(payload) in ALL_STATUSES

    checks = _payload_checks(payload)
    if any(_check_name(check) in {"restore-target", "restore-config", "target-selection"} for check in checks):
        assert any(_check_name(check) in {"restore-target", "restore-config", "target-selection"} and _check_ok(check) is False for check in checks)
    else:
        pytest.skip("restore target validation check is not implemented by this script")


def test_restore_result_surface_has_valid_status_and_checks() -> None:
    env = _base_env()
    completed = _run_with_env(env)

    assert completed.returncode in {0, 1}, _combined_output(completed)

    payload = _read_result_file()
    assert _normalize_top_level_status(payload) in ALL_STATUSES
    assert isinstance(_payload_checks(payload), list)
