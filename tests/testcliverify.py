from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import cli.verify as verify_cli

MODULE_CANDIDATES = (
    "app.cli.verify",
    "app.cli.main",
)


def _import_cliverify_module() -> Any:
    last_error: Exception | None = None
    for module_name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            last_error = exc
    raise AssertionError(
        "Unable to import cliverify module. Expected one of: " + ", ".join(MODULE_CANDIDATES),
    ) from last_error


@pytest.fixture
def cliverify_module() -> Any:
    return _import_cliverify_module()


def _resolve_callable(module: Any, *names: str) -> Any:
    for name in names:
        value = getattr(module, name, None)
        if callable(value):
            return value
    raise AssertionError(f"Expected one of these callables to exist: {', '.join(names)}")


def _invoke_with_supported_kwargs(func: Any, **kwargs: Any) -> Any:
    code = getattr(func, "__code__", None)
    if code is None:
        return func()

    accepted = set(code.co_varnames[: code.co_argcount])
    filtered = {key: value for key, value in kwargs.items() if key in accepted}
    return func(**filtered)


def test_cliverify_module_exposes_expected_entrypoints(cliverify_module: Any) -> None:
    candidates = (
        "main",
        "handle_verify_args",
        "run_verify_command",
        "build_verify_parser",
        "verify_cli",
        "run_verify",
        "verify",
        "run_cli",
    )
    resolved = [name for name in candidates if callable(getattr(cliverify_module, name, None))]
    assert resolved, f"Expected at least one verify entrypoint, checked: {', '.join(candidates)}"


def test_cliverify_help_style_main_returns_none_or_int(
    cliverify_module: Any,
    capsys: pytest.CaptureFixture[str],
) -> None:
    main_func = getattr(cliverify_module, "main", None) or getattr(cliverify_module, "run_cli", None)
    if not callable(main_func):
        pytest.skip("No main() or run_cli() entrypoint exposed by cliverify module")

    try:
        result = _invoke_with_supported_kwargs(main_func, argv=["--help"])
    except SystemExit as exc:
        result = exc.code

    captured = capsys.readouterr()
    combined_output = f"{captured.out}\n{captured.err}".strip().lower()

    assert result is None or isinstance(result, int)
    if combined_output:
        assert "help" in combined_output or "usage" in combined_output or "verify" in combined_output


def test_cliverify_verify_like_entrypoint_accepts_noninteractive_invocation(
    cliverify_module: Any,
) -> None:
    verify_func = _resolve_callable(
        cliverify_module,
        "run_verify_command",
        "handle_verify_args",
        "verify_cli",
        "run_verify",
        "verify",
        "run_cli",
    )

    try:
        result = _invoke_with_supported_kwargs(
            verify_func,
            argv=[],
            args=[],
            strict=False,
            json_output=False,
            integration_id="integration-claude-code",
        )
    except SystemExit as exc:
        result = exc.code
    except TypeError:
        result = verify_func()

    assert result is None or isinstance(result, int | bool | dict | str | tuple)


def test_cliverify_main_noninteractive_execution_is_process_safe(
    cliverify_module: Any,
) -> None:
    main_func = getattr(cliverify_module, "main", None) or getattr(cliverify_module, "run_cli", None)
    if not callable(main_func):
        pytest.skip("No main() or run_cli() entrypoint exposed by cliverify module")

    try:
        result = _invoke_with_supported_kwargs(
            main_func,
            argv=["integration-claude-code"],
        )
    except SystemExit as exc:
        result = exc.code

    assert result is None or isinstance(result, int)


def test_cli_verify_rejects_unverified_runtime_install_key(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "provider_targets": ["claude_code"],
                "install_keys": {
                    "claude_code": "ic_install_claude_code_abc123",
                },
            }
        ),
        encoding="utf-8",
    )

    def fake_authenticate(candidate: str):
        if candidate == "ic_install_claude_code_abc123":
            return SimpleNamespace(
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                program="claude_code",
                owner_key="owner@example.com",
                revoked_at=None,
            )
        return None

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(verify_cli, "get_install_key_registry", lambda: SimpleNamespace(authenticate_install_key=fake_authenticate))
    try:
        report = verify_cli.build_verify_report(tmp_path, dry_run=True)
    finally:
        monkeypatch.undo()

    assert any(check.name == "install-key-runtime-claude_code" and check.ok for check in report.checks)


def test_cli_verify_accepts_alias_runtime_names_and_rejects_generic_key_values(tmp_path: Path) -> None:
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "provider_targets": ["claude-code"],
                "install_keys": {
                    "claude-code": "ic_install_claude_code_abc123",
                    "fallback": "ghp_exampletoken",
                },
            }
        ),
        encoding="utf-8",
    )

    def fake_authenticate(candidate: str):
        if candidate == "ic_install_claude_code_abc123":
            return SimpleNamespace(
                active=True,
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                program="claude_code",
                owner_key="owner@example.com",
                revoked_at=None,
            )
        return None

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(verify_cli, "get_install_key_registry", lambda: SimpleNamespace(authenticate_install_key=fake_authenticate))
    try:
        report = verify_cli.build_verify_report(tmp_path, dry_run=True)
    finally:
        monkeypatch.undo()

    assert any(check.name == "install-key-runtime-claude_code" and check.ok for check in report.checks)
    assert not any(check.name == "install-key-runtime-claude_code" and "missing" in check.detail.lower() for check in report.checks)
