from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / ".reports"
DEFAULT_REPORT_PATH = DEFAULT_OUTPUT_DIR / "security-quality-gate.json"


@dataclass(slots=True)
class GateCheck:
    name: str
    command: list[str]
    required: bool = True
    category: str = "general"
    env: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class GateResult:
    name: str
    category: str
    required: bool
    command: list[str]
    returncode: int
    duration_seconds: float
    status: str
    stdout: str
    stderr: str


def _python_executable() -> str:
    return sys.executable or "python"


def _base_env() -> dict[str, str]:
    env = os.environ.copy()
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return env


def _command_exists(command_name: str) -> bool:
    from shutil import which

    return which(command_name) is not None


def _build_checks() -> list[GateCheck]:
    python_exe = _python_executable()

    checks: list[GateCheck] = [
        GateCheck(
            name="pytest",
            command=[python_exe, "-m", "pytest", "-q"],
            required=True,
            category="tests",
        ),
        GateCheck(
            name="pytest-warnings-as-errors",
            command=[python_exe, "-m", "pytest", "-q", "-W", "error"],
            required=True,
            category="warnings",
        ),
        GateCheck(
            name="ruff",
            command=["ruff", "check", "."],
            required=False,
            category="lint",
        ),
        GateCheck(
            name="mypy",
            command=["mypy", "app"],
            required=False,
            category="types",
        ),
        GateCheck(
            name="bandit",
            command=["bandit", "-r", "app", "-x", "tests,.venv"],
            required=False,
            category="security",
        ),
        GateCheck(
            name="semgrep",
            command=["semgrep", "--config", "auto", "--error", "app"],
            required=False,
            category="security",
        ),
    ]

    filtered_checks: list[GateCheck] = []
    for check in checks:
        command_name = check.command[0]
        if command_name == python_exe or _command_exists(command_name):
            filtered_checks.append(check)
        else:
            filtered_checks.append(
                GateCheck(
                    name=check.name,
                    command=check.command,
                    required=False,
                    category=f"{check.category}-missing-tool",
                    env={"IRONCLAW_SKIP_REASON": f"missing dependency: {command_name}"},
                ),
            )
    return filtered_checks


def _run_check(check: GateCheck) -> GateResult:
    skip_reason = check.env.get("IRONCLAW_SKIP_REASON")
    if skip_reason:
        return GateResult(
            name=check.name,
            category=check.category,
            required=check.required,
            command=check.command,
            returncode=0,
            duration_seconds=0.0,
            status="skipped",
            stdout="",
            stderr=skip_reason,
        )

    started = time.perf_counter()
    completed = subprocess.run(
        check.command,
        check=False,
        cwd=PROJECT_ROOT,
        env={**_base_env(), **check.env},
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    duration = time.perf_counter() - started

    status = "passed" if completed.returncode == 0 else "failed"
    return GateResult(
        name=check.name,
        category=check.category,
        required=check.required,
        command=check.command,
        returncode=completed.returncode,
        duration_seconds=duration,
        status=status,
        stdout=completed.stdout.strip(),
        stderr=completed.stderr.strip(),
    )


def _summarize_results(results: Sequence[GateResult]) -> dict[str, object]:
    failed_required = [result for result in results if result.required and result.status == "failed"]
    failed_optional = [result for result in results if not result.required and result.status == "failed"]
    skipped = [result for result in results if result.status == "skipped"]
    passed = [result for result in results if result.status == "passed"]

    overall_status = "passed" if not failed_required else "failed"

    return {
        "overall_status": overall_status,
        "passed": len(passed),
        "failed_required": len(failed_required),
        "failed_optional": len(failed_optional),
        "skipped": len(skipped),
    }


def _result_to_dict(result: GateResult) -> dict[str, object]:
    return {
        "name": result.name,
        "category": result.category,
        "required": result.required,
        "command": result.command,
        "command_display": " ".join(shlex.quote(part) for part in result.command),
        "returncode": result.returncode,
        "duration_seconds": round(result.duration_seconds, 3),
        "status": result.status,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _write_report(results: Sequence[GateResult], report_path: Path) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "project_root": str(PROJECT_ROOT),
        "summary": _summarize_results(results),
        "results": [_result_to_dict(result) for result in results],
    }
    report_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _print_console_summary(results: Sequence[GateResult], report_path: Path) -> None:
    summary = _summarize_results(results)
    print("\nIronClaw Security Quality Gate")
    print("=" * 32)
    print(f"Overall: {summary['overall_status']}")
    print(f"Passed: {summary['passed']}")
    print(f"Failed required: {summary['failed_required']}")
    print(f"Failed optional: {summary['failed_optional']}")
    print(f"Skipped: {summary['skipped']}")
    print(f"Report: {report_path}")

    for result in results:
        print(f"\n[{result.status.upper()}] {result.name} ({result.category})")
        print(f"Command: {' '.join(shlex.quote(part) for part in result.command)}")
        if result.stderr:
            print(f"stderr: {result.stderr[:1000]}")
        if result.stdout:
            print(f"stdout: {result.stdout[:1000]}")


def main() -> int:
    report_path = Path(os.getenv("IRONCLAW_GATE_REPORT", DEFAULT_REPORT_PATH))
    checks = _build_checks()
    results = [_run_check(check) for check in checks]

    _write_report(results, report_path)
    _print_console_summary(results, report_path)

    summary = _summarize_results(results)
    return 0 if summary["overall_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
