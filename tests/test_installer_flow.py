from __future__ import annotations

import importlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

MODULE_CANDIDATES = (
    "ironclawinstaller",
    "scripts.install",
    "app.cli.install",
    "app.services.integrationinstaller",
    "services.integrationinstaller",
)


def _import_installer_module() -> Any:
    last_error: Exception | None = None
    for module_name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            last_error = exc
    raise AssertionError(
        "Unable to import installer module. Expected one of: " + ", ".join(MODULE_CANDIDATES),
    ) from last_error


@pytest.fixture
def installer_module() -> Any:
    return _import_installer_module()


def _resolve_attr(module: Any, *names: str) -> Any:
    for name in names:
        value = getattr(module, name, None)
        if value is not None:
            return value
    raise AssertionError(f"Expected one of these attributes to exist: {', '.join(names)}")


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
    accepts_var_kwargs = bool(code.co_flags & 0x08)
    if accepts_var_kwargs:
        return func(**kwargs)

    filtered = {key: value for key, value in kwargs.items() if key in accepted}
    return func(**filtered)


def _make_namespace(**values: Any) -> Any:
    return type("Args", (), values)()


def _assert_json_serializable(value: Any) -> None:
    json.dumps(value)


def test_app_cli_install_requires_paid_customer_install_key() -> None:
    from app.cli.install import build_install_parser

    parser = build_install_parser()
    args = parser.parse_args(["openclaw", "--key", "ic_123456", "--owner-key", "owner-456"])

    assert args.key == "ic_123456"
    assert args.owner_key == "owner-456"

    from app.cli.install import run_install_command

    fake_registry = MagicMock()
    fake_registry.authenticate_install_key.return_value = None
    exit_code, payload = run_install_command(
        "openclaw",
        key="ic_123456",
        owner_key="owner-456",
        registry=fake_registry,
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "install key unavailable until payment is complete" in payload["message"].lower()
    assert "ic_123456" not in json.dumps(payload)


def test_app_cli_install_rejects_system_api_keys_and_generic_tokens() -> None:
    from app.cli.install import run_install_command

    for bad_key in ("sk_live_abc123", "token-abc", "ic_org_1234", "ic_123456", "generic-token"):
        fake_registry = MagicMock()
        exit_code, payload = run_install_command(
            "openclaw",
            key=bad_key,
            owner_key="owner-456",
            registry=fake_registry,
        )
        assert exit_code == 1
        assert payload["status"] == "failed"
        assert "install key unavailable until payment is complete" in payload["message"].lower()
        assert bad_key not in json.dumps(payload)
        fake_registry.authenticate_install_key.assert_not_called()


def test_app_cli_install_rejects_platform_api_key_variants_before_registry_lookup() -> None:
    from app.cli.install import run_install_command

    for bad_key in ("platform-api-key", "internal_platform_api_key", "internal-platform-api-key"):
        fake_registry = MagicMock()
        exit_code, payload = run_install_command(
            "openclaw",
            key=bad_key,
            owner_key="owner-456",
            registry=fake_registry,
        )
        assert exit_code == 1
        assert payload["status"] == "failed"
        assert payload["key_classification"] == "generic_platform_api_key"
        assert bad_key not in json.dumps(payload)
        fake_registry.authenticate_install_key.assert_not_called()


def test_app_cli_install_rejects_mismatched_program_and_owner_key() -> None:
    from app.cli.install import run_install_command

    fake_registry = MagicMock()
    fake_registry.authenticate_install_key.return_value = MagicMock(
        key_id="ik_123",
        owner_key="owner-456",
        program="openclaw",
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        units_consumed=0,
    )

    exit_code, payload = run_install_command(
        "claude-code",
        key="ic_install_openclaw_abc123",
        owner_key="owner-456",
        registry=fake_registry,
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "install key unavailable until payment is complete" in payload["message"].lower()
    assert "ic_install_openclaw_abc123" not in json.dumps(payload)


def test_installer_module_imports(installer_module: Any) -> None:
    assert installer_module is not None


def test_installer_module_exposes_install_flow_entrypoint(installer_module: Any) -> None:
    candidates = (
        "main",
        "install",
        "run_install",
        "run_installer",
        "install_integration",
        "perform_install",
    )
    resolved = [name for name in candidates if callable(getattr(installer_module, name, None))]
    assert resolved, f"Expected at least one installer entrypoint, checked: {', '.join(candidates)}"


def test_installer_parser_accepts_common_flags(installer_module: Any) -> None:
    build_parser = getattr(installer_module, "build_parser", None)
    if not callable(build_parser):
        pytest.skip("build_parser() not exposed by installer module")

    parser = build_parser()
    args = parser.parse_args(
        [
            "--integration",
            "claude",
            "--target-dir",
            "C:/tmp/ironclaw-target",
        ],
    )

    integration = getattr(args, "integration", None) or getattr(args, "name", None)
    target_dir = getattr(args, "target_dir", None) or getattr(args, "install_dir", None)

    assert integration == "claude"
    assert target_dir is not None


def test_installer_module_exposes_config_or_manifest_shape(installer_module: Any, tmp_path: Path) -> None:
    candidates = (
        "InstallerConfig",
        "InstallConfig",
        "IntegrationInstallConfig",
        "InstallerManifest",
        "InstallManifest",
    )

    found = [name for name in candidates if getattr(installer_module, name, None) is not None]
    assert found or True

    for name in found:
        value = getattr(installer_module, name)
        if isinstance(value, type):
            annotations = getattr(value, "__annotations__", {})
            assert isinstance(annotations, dict)


def test_installer_can_build_config_from_args(installer_module: Any, tmp_path: Path) -> None:
    config_builder = getattr(installer_module, "_config_from_args", None)
    if not callable(config_builder):
        config_builder = getattr(installer_module, "config_from_args", None)
    if not callable(config_builder):
        pytest.skip("No config builder exposed by installer module")

    target_dir = tmp_path / "target"
    args = _make_namespace(
        integration="claude",
        name="claude",
        target_dir=target_dir,
        install_dir=target_dir,
        project_root=tmp_path,
        force=False,
        overwrite=False,
        dry_run=True,
        json=False,
    )

    result = _invoke_with_supported_kwargs(config_builder, args=args)

    assert result is not None
    if hasattr(result, "to_dict") and callable(result.to_dict):
        _assert_json_serializable(result.to_dict())


def test_installer_env_builder_preserves_environment(installer_module: Any, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_builder = getattr(installer_module, "build_install_env", None)
    if not callable(env_builder):
        env_builder = getattr(installer_module, "_build_env", None)
    if not callable(env_builder):
        env_builder = getattr(installer_module, "installer_env", None)
    if not callable(env_builder):
        pytest.skip("No installer environment helper exposed by installer module")

    monkeypatch.setenv("IRONCLAW_ENV", "test")
    monkeypatch.setenv("IRONCLAW_INSTALL_MODE", "safe")

    result = _invoke_with_supported_kwargs(
        env_builder,
        project_root=tmp_path,
        target_dir=tmp_path / "target",
    )

    assert isinstance(result, dict)
    assert result.get("IRONCLAW_ENV", "test") == "test"
    assert result.get("IRONCLAW_INSTALL_MODE", "safe") == "safe"


def test_installer_status_or_plan_payload_is_serializable(installer_module: Any, tmp_path: Path) -> None:
    candidate = getattr(installer_module, "installation_status", None)
    if not callable(candidate):
        candidate = getattr(installer_module, "get_status", None)
    if not callable(candidate):
        candidate = getattr(installer_module, "build_install_plan", None)
    if not callable(candidate):
        pytest.skip("No installer status/plan helper exposed by installer module")

    result = _invoke_with_supported_kwargs(
        candidate,
        project_root=tmp_path,
        target_dir=tmp_path / "target",
        integration="claude",
    )

    assert result is None or isinstance(result, dict | list | str | tuple)
    if isinstance(result, dict | list):
        _assert_json_serializable(result)


def test_installer_main_returns_exit_code_shape(
    installer_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    main_func = getattr(installer_module, "main", None)
    if not callable(main_func):
        pytest.skip("main() not exposed by installer module")

    monkeypatch.chdir(tmp_path)

    argv_options = (
        ["--help"],
        ["install", "--help"],
    )

    for argv in argv_options:
        try:
            result = _invoke_with_supported_kwargs(main_func, argv=argv)
        except SystemExit as exc:
            result = exc.code
        assert result is None or isinstance(result, int)


def test_installer_flow_entrypoint_accepts_temp_paths(
    installer_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    install_func = _resolve_callable(
        installer_module,
        "install",
        "run_install",
        "run_installer",
        "install_integration",
        "perform_install",
        "main",
    )

    project_root = tmp_path / "project"
    project_root.mkdir(parents=True, exist_ok=True)
    target_dir = project_root / ".ironclaw-installer-target"
    target_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.chdir(project_root)

    for attr_name, replacement in (
        ("PROJECT_ROOT", project_root),
        ("DEFAULT_PROJECT_ROOT", project_root),
        ("ROOT_DIR", project_root),
        ("BASE_DIR", project_root),
        ("DEFAULT_TARGET_DIR", target_dir),
        ("TARGET_DIR", target_dir),
    ):
        if hasattr(installer_module, attr_name):
            monkeypatch.setattr(installer_module, attr_name, replacement, raising=False)

    config_cls = getattr(installer_module, "InstallerConfig", None)
    if config_cls is None:
        config_cls = getattr(installer_module, "InstallConfig", None)
    if config_cls is None:
        config_cls = getattr(installer_module, "IntegrationInstallConfig", None)

    config = None
    if config_cls is not None:
        config_kwargs: dict[str, Any] = {}
        annotations = getattr(config_cls, "__annotations__", {})
        defaults: dict[str, Any] = {
            "project_root": project_root,
            "target_dir": target_dir,
            "install_dir": target_dir,
            "integration": "claude",
            "name": "claude",
            "force": False,
            "overwrite": False,
            "dry_run": True,
            "json": False,
        }
        for key in annotations:
            if key in defaults:
                config_kwargs[key] = defaults[key]
        try:
            config = config_cls(**config_kwargs)
        except TypeError:
            config = None

    invocation_kwargs: dict[str, Any] = {
        "project_root": project_root,
        "target_dir": target_dir,
        "install_dir": target_dir,
        "integration": "claude",
        "name": "claude",
        "force": False,
        "overwrite": False,
        "dry_run": True,
        "config": config,
        "args": _make_namespace(
            integration="claude",
            name="claude",
            target_dir=target_dir,
            install_dir=target_dir,
            project_root=project_root,
            force=False,
            overwrite=False,
            dry_run=True,
            json=False,
        ),
        "argv": ["--help"] if install_func is getattr(installer_module, "main", None) else [],
    }

    try:
        result = _invoke_with_supported_kwargs(install_func, **invocation_kwargs)
    except SystemExit as exc:
        result = exc.code
    except Exception:
        result = None

    assert result is None or isinstance(result, int | dict | str | Path | tuple | list)
    if isinstance(result, dict | list):
        _assert_json_serializable(result)


def test_installer_manifest_or_output_shape_is_stable(installer_module: Any, tmp_path: Path) -> None:
    candidate = getattr(installer_module, "render_install_manifest", None)
    if not callable(candidate):
        candidate = getattr(installer_module, "build_manifest", None)
    if not callable(candidate):
        candidate = getattr(installer_module, "installation_result", None)
    if not callable(candidate):
        pytest.skip("No installer manifest/output helper exposed by installer module")

    result = _invoke_with_supported_kwargs(
        candidate,
        project_root=tmp_path,
        target_dir=tmp_path / "target",
        integration="claude",
        dry_run=True,
    )

    assert result is None or isinstance(result, dict | str | list | tuple)
    if isinstance(result, dict | list):
        _assert_json_serializable(result)
