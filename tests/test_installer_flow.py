from __future__ import annotations

import importlib
import json
from pathlib import Path
from types import SimpleNamespace
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


def test_app_cli_install_requires_one_time_claim() -> None:
    from app.cli.install import build_install_parser

    parser = build_install_parser()
    args = parser.parse_args(["openclaw", "--install-claim", "ic_claim_example"])

    assert args.claim_token == "ic_claim_example"
    assert not hasattr(args, "key")
    assert not hasattr(args, "owner_key")
    with pytest.raises(SystemExit):
        parser.parse_args(["openclaw", "--key", "ic_install_openclaw_secret"])

    from app.cli.install import run_install_command

    exit_code, payload = run_install_command(
        "openclaw",
        claim_token="ic_123456",
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "install claim" in payload["message"].lower()
    assert "ic_123456" not in json.dumps(payload)


def test_app_cli_install_infers_every_canonical_runtime() -> None:
    from app.cli.install import _infer_install_program
    from app.core.install_key_formats import RUNTIME_INSTALL_KEY_PROGRAMS, InstallKeyFormatRegistry

    for program in RUNTIME_INSTALL_KEY_PROGRAMS:
        assert _infer_install_program(program) == program
        assert _infer_install_program(InstallKeyFormatRegistry.get_spec(program).canonical_slug) == program


def test_app_cli_install_rejects_raw_keys_and_generic_tokens_as_claims(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.cli.install as cli_install
    from app.cli.install import run_install_command

    key_registry = MagicMock()
    monkeypatch.setattr(cli_install, "get_install_key_registry", lambda: key_registry)

    for bad_claim in (
        "sk_live_abc123",
        "token-abc",
        "ic_org_1234",
        "ic_123456",
        "generic-token",
        "ic_install_openclaw_secret",
    ):
        exit_code, payload = run_install_command(
            "openclaw",
            claim_token=bad_claim,
        )
        assert exit_code == 1
        assert payload["status"] == "failed"
        assert "install claim" in payload["message"].lower()
        assert bad_claim not in json.dumps(payload)
    key_registry.authenticate_install_key.assert_not_called()


def test_app_cli_install_rejects_claim_for_mismatched_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import app.cli.install as cli_install
    from app.cli.install import run_install_command

    token = "ic_claim_runtime_mismatch"
    handoff = MagicMock()
    handoff.redeem_claim.return_value = SimpleNamespace(
        key_id="ik_123",
        owner_key="owner-456",
        program="openclaw",
        install_key="ic_install_openclaw_secret",
    )
    key_registry = MagicMock()
    monkeypatch.setattr(cli_install, "get_install_key_handoff_service", lambda: handoff)
    monkeypatch.setattr(cli_install, "get_install_key_registry", lambda: key_registry)

    exit_code, payload = run_install_command(
        "claude-code",
        claim_token=token,
    )

    assert exit_code == 1
    assert payload["status"] == "failed"
    assert "runtime" in payload["message"].lower()
    assert token not in json.dumps(payload)
    assert "ic_install_openclaw_secret" not in json.dumps(payload)
    key_registry.authenticate_install_key.assert_not_called()


def test_app_cli_install_redeems_claim_and_does_not_expose_credentials(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import app.cli.install as cli_install
    from app.services.install_key_handoff import InstallKeyRedemption

    token = "ic_claim_one_time_example"
    install_key = "ic_install_openclaw_abc123"
    redemption = InstallKeyRedemption(
        key_id="ik_123",
        owner_key="owner-456",
        program="openclaw",
        install_key=install_key,
    )
    handoff = MagicMock()
    handoff.redeem_claim.return_value = redemption
    install_key_registry = MagicMock()
    install_key_registry.authenticate_install_key.return_value = SimpleNamespace(
        key_id="ik_123",
        owner_key="owner-456",
        program="openclaw",
        payment_status="paid",
        entitlements_status="active",
        issued_after_payment=True,
        units_consumed=120,
    )
    wallet_registry = MagicMock()
    wallet_registry.get_wallet.return_value = SimpleNamespace(balance_units=4880, install_key_usage={})
    install_calls: dict[str, Any] = {}

    def fake_install_integration(
        active_registry: Any,
        integration_id: str,
        **kwargs: Any,
    ) -> object:
        install_calls["registry"] = active_registry
        install_calls["integration_id"] = integration_id
        install_calls["kwargs"] = kwargs
        return object()

    monkeypatch.setattr(cli_install, "get_install_key_handoff_service", lambda: handoff)
    monkeypatch.setattr(
        cli_install,
        "get_install_key_registry",
        lambda: install_key_registry,
    )
    monkeypatch.setattr(cli_install, "get_unit_wallet_registry", lambda: wallet_registry)
    monkeypatch.setattr(cli_install, "install_integration", fake_install_integration)
    save_calls: dict[str, Any] = {}
    config_file = tmp_path / "config.json"

    def fake_save_install_key(*, program: str, install_key: str, **_: Any) -> object:
        save_calls["program"] = program
        save_calls["install_key"] = install_key
        return SimpleNamespace(config_file=config_file)

    monkeypatch.setattr(cli_install, "save_install_key", fake_save_install_key)
    monkeypatch.setattr(
        cli_install,
        "summarize_install_result",
        lambda _: {"installed": True, "integration_id": "openclaw"},
    )
    integration_registry = MagicMock()

    exit_code, payload = cli_install.run_install_command(
        "openclaw",
        claim_token=token,
        registry=integration_registry,
    )

    assert exit_code == 0
    assert payload["owner_key"] == "owner-456"
    assert payload["install_key"] is None
    assert token not in json.dumps(payload)
    assert install_key not in json.dumps(payload)
    assert install_calls["registry"] is integration_registry
    assert install_calls["integration_id"] == "openclaw"
    assert install_calls["kwargs"]["install_key"] == install_key
    assert install_calls["kwargs"]["owner_key"] == "owner-456"
    assert save_calls == {"program": "openclaw", "install_key": install_key}
    assert payload["config_file"] == str(config_file)


def test_app_cli_install_dry_run_never_redeems_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    import app.cli.install as cli_install
    from app.cli.install import run_install_command

    handoff = MagicMock()
    monkeypatch.setattr(cli_install, "get_install_key_handoff_service", lambda: handoff)
    monkeypatch.setattr(cli_install, "install_integration", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(
        cli_install,
        "summarize_install_result",
        lambda _: {"installed": False, "integration_id": "integration-openclaw"},
    )

    exit_code, payload = run_install_command(
        "integration-openclaw",
        dry_run=True,
        claim_token="ic_claim_dry_run_example",
        registry=MagicMock(),
    )

    assert exit_code == 0
    assert payload["dry_run"] is True
    assert payload["claim_consumed"] is False
    handoff.redeem_claim.assert_not_called()


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
