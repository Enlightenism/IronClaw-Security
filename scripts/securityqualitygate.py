from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
RESULT_FILE: Final[Path] = ROOT / ".security-quality-gate.json"
APP_DIR: Final[Path] = ROOT / "app"
TESTS_DIR: Final[Path] = ROOT / "tests"
REQUIREMENTS_FILE: Final[Path] = ROOT / "requirements.txt"

MIN_COVERAGE_DEFAULT: Final[int] = 80


@dataclass(slots=True)
class GateCheckResult:
    name: str
    ok: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value is None:
        return default
    try:
        parsed = int(value.strip())
    except (AttributeError, TypeError, ValueError):
        return default
    return parsed


def _record(results: list[GateCheckResult], name: str, ok: bool, detail: str) -> None:
    entry = GateCheckResult(name=name, ok=ok, detail=detail)
    results.append(entry)
    label = "OK" if ok else "FAIL"
    print(f"[{label}] {name}: {detail}")


def _trim_output(stdout: str, stderr: str, fallback: str) -> str:
    detail = (stdout + "\n" + stderr).strip()
    if not detail:
        return fallback
    return detail[-1200:]


def _run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=str(ROOT),
        text=True,
        capture_output=True,
        check=False,
        env=os.environ.copy(),
    )


def _tool_exists(name: str) -> bool:
    return shutil.which(name) is not None


def _check_project_surface(results: list[GateCheckResult]) -> None:
    required = [APP_DIR, TESTS_DIR, REQUIREMENTS_FILE]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        _record(results, "project-surface", False, f"missing: {', '.join(missing)}")
        return
    _record(results, "project-surface", True, "app, tests, and requirements are present")


def _check_pytest(results: list[GateCheckResult]) -> None:
    completed = _run([sys.executable, "-m", "pytest", "-q"])
    if completed.returncode == 0:
        _record(results, "pytest", True, "test suite passed")
        return

    _record(
        results,
        "pytest",
        False,
        _trim_output(completed.stdout, completed.stderr, "pytest failed"),
    )


def _check_coverage(results: list[GateCheckResult], min_coverage: int) -> None:
    completed = _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "--cov=app",
            f"--cov-fail-under={min_coverage}",
            "--cov-report=term-missing:skip-covered",
            "-q",
        ],
    )
    if completed.returncode == 0:
        _record(results, "coverage", True, f"coverage meets fail-under {min_coverage}%")
        return

    _record(
        results,
        "coverage",
        False,
        _trim_output(completed.stdout, completed.stderr, "coverage gate failed"),
    )


def _check_bandit(results: list[GateCheckResult]) -> None:
    if _tool_exists("bandit"):
        cmd = ["bandit", "-q", "-r", "app"]
    else:
        cmd = [sys.executable, "-m", "bandit", "-q", "-r", "app"]

    completed = _run(cmd)
    if completed.returncode == 0:
        _record(results, "bandit", True, "no Bandit issues detected at current threshold")
        return

    if "No module named bandit" in completed.stderr:
        _record(results, "bandit", False, "bandit is not installed")
        return

    _record(
        results,
        "bandit",
        False,
        _trim_output(completed.stdout, completed.stderr, "bandit reported security findings"),
    )


def _check_pip_audit(results: list[GateCheckResult]) -> None:
    if _tool_exists("pip-audit"):
        cmd = ["pip-audit", "-r", str(REQUIREMENTS_FILE), "--strict"]
    else:
        cmd = [sys.executable, "-m", "pip_audit", "-r", str(REQUIREMENTS_FILE), "--strict"]

    completed = _run(cmd)
    if completed.returncode == 0:
        _record(results, "pip-audit", True, "no known dependency vulnerabilities found")
        return

    if "No module named pip_audit" in completed.stderr:
        _record(results, "pip-audit", False, "pip-audit is not installed")
        return

    _record(
        results,
        "pip-audit",
        False,
        _trim_output(completed.stdout, completed.stderr, "pip-audit found vulnerabilities"),
    )


def _write_result(results: list[GateCheckResult], ok: bool, min_coverage: int) -> None:
    RESULT_FILE.write_text(
        json.dumps(
            {
                "status": "ok" if ok else "fail",
                "generated_at": datetime.now(UTC).isoformat(),
                "minimum_coverage": min_coverage,
                "checks": [item.to_dict() for item in results],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> None:
    _ = argv
    min_coverage = _env_int("IRONCLAW_MIN_COVERAGE", MIN_COVERAGE_DEFAULT)

    results: list[GateCheckResult] = []

    _check_project_surface(results)
    _check_pytest(results)
    _check_coverage(results, min_coverage)
    _check_bandit(results)
    _check_pip_audit(results)

    ok = all(item.ok for item in results)
    _write_result(results, ok, min_coverage)

    print("SECURITY QUALITY GATE: OK" if ok else "SECURITY QUALITY GATE: FAIL")
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
