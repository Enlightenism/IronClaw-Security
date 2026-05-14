from __future__ import annotations

from pathlib import Path

import pytest

from scripts import security_quality_gate as gate


def test_summarize_results_marks_failed_when_required_check_fails() -> None:
    results = [
        gate.GateResult(
            name="pytest",
            category="tests",
            required=True,
            command=["python", "-m", "pytest", "-q"],
            returncode=0,
            duration_seconds=1.2,
            status="passed",
            stdout="",
            stderr="",
        ),
        gate.GateResult(
            name="bandit",
            category="security",
            required=True,
            command=["bandit", "-r", "app"],
            returncode=1,
            duration_seconds=0.7,
            status="failed",
            stdout="issue found",
            stderr="",
        ),
    ]

    summary = gate._summarize_results(results)

    assert summary["overall_status"] == "failed"
    assert summary["passed"] == 1
    assert summary["failed_required"] == 1
    assert summary["failed_optional"] == 0
    assert summary["skipped"] == 0


def test_summarize_results_allows_optional_failures() -> None:
    results = [
        gate.GateResult(
            name="pytest",
            category="tests",
            required=True,
            command=["python", "-m", "pytest", "-q"],
            returncode=0,
            duration_seconds=0.5,
            status="passed",
            stdout="",
            stderr="",
        ),
        gate.GateResult(
            name="mypy",
            category="types",
            required=False,
            command=["mypy", "app"],
            returncode=1,
            duration_seconds=0.3,
            status="failed",
            stdout="type issue",
            stderr="",
        ),
    ]

    summary = gate._summarize_results(results)

    assert summary["overall_status"] == "passed"
    assert summary["passed"] == 1
    assert summary["failed_required"] == 0
    assert summary["failed_optional"] == 1
    assert summary["skipped"] == 0


def test_result_to_dict_exposes_display_command() -> None:
    result = gate.GateResult(
        name="ruff",
        category="lint",
        required=False,
        command=["ruff", "check", "."],
        returncode=0,
        duration_seconds=0.25,
        status="passed",
        stdout="All checks passed!",
        stderr="",
    )

    payload = gate._result_to_dict(result)

    assert payload["name"] == "ruff"
    assert payload["category"] == "lint"
    assert payload["required"] is False
    assert payload["command"] == ["ruff", "check", "."]
    assert payload["command_display"] == "ruff check ."
    assert payload["returncode"] == 0
    assert payload["status"] == "passed"


def test_write_report_creates_json_payload(tmp_path: Path) -> None:
    report_path = tmp_path / "quality-gate.json"
    results = [
        gate.GateResult(
            name="pytest",
            category="tests",
            required=True,
            command=["python", "-m", "pytest", "-q"],
            returncode=0,
            duration_seconds=0.9,
            status="passed",
            stdout="ok",
            stderr="",
        ),
    ]

    gate._write_report(results, report_path)

    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert '"overall_status": "passed"' in content
    assert '"name": "pytest"' in content
    assert '"command_display": "python -m pytest -q"' in content


def test_build_checks_includes_pytest_checks() -> None:
    checks = gate._build_checks()
    check_names = {check.name for check in checks}

    assert "pytest" in check_names
    assert "pytest-warnings-as-errors" in check_names


def test_build_checks_marks_missing_optional_tools_as_skipped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_command_exists(command_name: str) -> bool:
        return command_name == "ruff"

    monkeypatch.setattr(gate, "_command_exists", fake_command_exists)

    checks = gate._build_checks()
    checks_by_name = {check.name: check for check in checks}

    assert checks_by_name["ruff"].category == "lint"
    assert checks_by_name["mypy"].category == "types-missing-tool"
    assert checks_by_name["bandit"].category == "security-missing-tool"
    assert checks_by_name["semgrep"].category == "security-missing-tool"
    assert checks_by_name["mypy"].required is False
    assert "missing dependency" in checks_by_name["mypy"].env["IRONCLAW_SKIP_REASON"]


def test_summarize_results_handles_empty_input_as_pass() -> None:
    summary = gate._summarize_results([])

    assert summary["overall_status"] == "passed"
    assert summary["passed"] == 0
    assert summary["failed_required"] == 0
    assert summary["failed_optional"] == 0
    assert summary["skipped"] == 0
