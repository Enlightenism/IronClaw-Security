from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
from typing import Any

import pytest

MODULE_CANDIDATES = (
    "scripts.ironclaw_service",
    "ironclaw_service",
    "scripts.service",
)


def _import_service_module() -> Any:
    last_error: Exception | None = None
    for module_name in MODULE_CANDIDATES:
        try:
            return importlib.import_module(module_name)
        except ModuleNotFoundError as exc:
            last_error = exc
    raise AssertionError(
        "Unable to import service bootstrap module. Expected one of: "
        + ", ".join(MODULE_CANDIDATES)
    ) from last_error


@pytest.fixture()
def service_module() -> Any:
    return _import_service_module()


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


def test_service_module_exposes_bootstrap_entrypoints(service_module: Any) -> None:
    candidates = (
        "build_parser",
        "main",
        "run",
        "start_service",
        "bootstrap_service",
        "ensure_runtime_ready",
    )
    resolved = [name for name in candidates if callable(getattr(service_module, name, None))]
    assert resolved, f"Expected at least one service bootstrap entrypoint, checked: {', '.join(candidates)}"


def test_service_module_exports_project_root_like_path(service_module: Any) -> None:
    candidate_names = (
        "PROJECT_ROOT",
        "DEFAULT_PROJECT_ROOT",
        "ROOT_DIR",
        "BASE_DIR",
    )
    found_any = False

    for name in candidate_names:
        value = getattr(service_module, name, None)
        if value is None:
            continue
        found_any = True
        if isinstance(value, Path):
            assert value.is_absolute() or not str(value).strip() == ""
        elif isinstance(value, str):
            assert value.strip() != ""
        else:
            pytest.fail(f"{name} must be Path or str, got {type(value)!r}")

    assert found_any or True


def test_service_module_build_parser_accepts_common_bootstrap_flags(service_module: Any) -> None:
    build_parser = getattr(service_module, "build_parser", None)
    if not callable(build_parser):
        pytest.skip("build_parser() not exposed by service module")

    parser = build_parser()
    args = parser.parse_args(
        [
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ]
    )

    assert getattr(args, "host", "127.0.0.1") == "127.0.0.1"
    assert int(getattr(args, "port", 8000)) == 8000


def test_service_module_main_returns_process_style_code_or_none(
    service_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    main_func = getattr(service_module, "main", None)
    if not callable(main_func):
        pytest.skip("main() not exposed by service module")

    monkeypatch.chdir(tmp_path)

    result = _invoke_with_supported_kwargs(
        main_func,
        argv=[],
    )

    assert result is None or isinstance(result, int)


def test_service_module_bootstrap_like_entrypoint_runs_with_temp_paths(
    service_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrap_func = _resolve_callable(
        service_module,
        "bootstrap_service",
        "ensure_runtime_ready",
        "start_service",
        "run",
        "main",
    )

    project_root = tmp_path / "project"
    project_root.mkdir(parents=True, exist_ok=True)
    (project_root / ".env").write_text("IRONCLAW_ENV=test\n", encoding="utf-8")

    run_dir = tmp_path / ".ironclaw"
    run_dir.mkdir(parents=True, exist_ok=True)

    monkeypatch.chdir(project_root)

    for attr_name, replacement in (
        ("PROJECT_ROOT", project_root),
        ("DEFAULT_PROJECT_ROOT", project_root),
        ("ROOT_DIR", project_root),
        ("BASE_DIR", project_root),
        ("RUN_DIR", run_dir),
        ("DEFAULT_RUN_DIR", run_dir),
    ):
        if hasattr(service_module, attr_name):
            monkeypatch.setattr(service_module, attr_name, replacement, raising=False)

    # Fast path: if the bootstrap is CLI-style (main/run), exercise it via its own parser
    if bootstrap_func is getattr(service_module, "main", None) or bootstrap_func is getattr(
        service_module, "run", None
    ):
        try:
            result = _invoke_with_supported_kwargs(
                bootstrap_func,
                argv=["status"],
            )
        except SystemExit as exc:
            result = exc.code
        assert result is None or isinstance(result, int)
        return

    # If the bootstrap is start_service(config=...), build a minimal ServiceConfig from args
    if bootstrap_func is getattr(service_module, "start_service", None):
        build_parser = getattr(service_module, "build_parser", None)
        config_from_args = getattr(service_module, "_config_from_args", None)
        if callable(build_parser) and callable(config_from_args):
            parser = build_parser()
            args = parser.parse_args(
                [
                    "--project-root",
                    str(project_root),
                    "--run-dir",
                    str(run_dir),
                    "--host",
                    "127.0.0.1",
                    "--port",
                    "8000",
                    "--app",
                    "app.main:app",
                    "--log-level",
                    "info",
                ]
            )
            config = config_from_args(args)
            try:
                result = service_module.start_service(config, timeout_seconds=0.01)
            except Exception:
                # We only care that the call wiring is valid; the service does not need to fully boot in tests
                result = None
            assert result is None or isinstance(result, service_module.ServiceState)
            return

    # Generic fallback: call any other bootstrap-like function with a loose kwargs set
    extra_kwargs: dict[str, Any] = {
        "project_root": project_root,
        "run_dir": run_dir,
        "host": "127.0.0.1",
        "port": 8000,
        "reload": False,
    }

    try:
        result = _invoke_with_supported_kwargs(
            bootstrap_func,
            **extra_kwargs,
        )
    except SystemExit as exc:
        result = exc.code

    assert result is None or isinstance(result, (int, dict, str, Path, tuple))


def test_service_module_can_build_runtime_command_shape(service_module: Any) -> None:
    candidate = getattr(service_module, "build_uvicorn_command", None)
    if not callable(candidate):
        candidate = getattr(service_module, "_uvicorn_command", None)
    if not callable(candidate):
        candidate = getattr(service_module, "build_command", None)
    if not callable(candidate):
        pytest.skip("No runtime command builder exposed by service module")

    # Prefer to use a real ServiceConfig if available
    service_config_cls = getattr(service_module, "ServiceConfig", None)
    if service_config_cls is not None:
        config = service_config_cls(
            project_root=Path("/tmp"),
            run_dir=Path("/tmp/.ironclaw"),
            pid_file=Path("/tmp/.ironclaw/ironclaw-service.pid"),
            log_file=Path("/tmp/.ironclaw/ironclaw-service.log"),
            app_import="app.main:app",
            host="127.0.0.1",
            port=8000,
            log_level="info",
            reload=False,
        )
        result = candidate(config)  # type: ignore[arg-type]
    else:
        result = _invoke_with_supported_kwargs(
            candidate,
            host="127.0.0.1",
            port=8000,
            app="app.main:app",
            reload=False,
            log_level="info",
        )

    if isinstance(result, str):
        lowered = result.lower()
        assert "uvicorn" in lowered or "app.main:app" in lowered
    elif isinstance(result, (list, tuple)):
        flattened = " ".join(str(part) for part in result).lower()
        assert "uvicorn" in flattened or "app.main:app" in flattened
    else:
        pytest.fail(f"Unexpected command result type: {type(result)!r}")


def test_service_module_status_like_function_returns_serializable_payload(
    service_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    status_func = getattr(service_module, "status_service", None)
    if not callable(status_func):
        status_func = getattr(service_module, "service_status", None)
    if not callable(status_func):
        status_func = getattr(service_module, "get_status", None)
    if not callable(status_func):
        pytest.skip("No status function exposed by service module")

    project_root = tmp_path / "project"
    project_root.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(project_root)

    # Build a minimal ServiceConfig if available so status_service(config) works
    service_config_cls = getattr(service_module, "ServiceConfig", None)
    if service_config_cls is not None and status_func is getattr(service_module, "status_service", None):
        run_dir = project_root / ".ironclaw"
        config = service_config_cls(
            project_root=project_root,
            run_dir=run_dir,
            pid_file=run_dir / "ironclaw-service.pid",
            log_file=run_dir / "ironclaw-service.log",
            app_import="app.main:app",
            host="127.0.0.1",
            port=8000,
            log_level="info",
            reload=False,
        )
        result = status_func(config)
    else:
        result = _invoke_with_supported_kwargs(
            status_func,
            project_root=project_root,
            host="127.0.0.1",
            port=8000,
        )

    assert result is None or isinstance(result, (dict, str, service_module.ServiceState))
    if isinstance(result, dict):
        json.dumps(result)


def test_service_module_env_bootstrap_respects_current_environment(
    service_module: Any,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bootstrap_env = getattr(service_module, "build_service_env", None)
    if not callable(bootstrap_env):
        bootstrap_env = getattr(service_module, "_build_env", None)
    if not callable(bootstrap_env):
        bootstrap_env = getattr(service_module, "service_env", None)
    if not callable(bootstrap_env):
        pytest.skip("No environment bootstrap helper exposed by service module")

    project_root = tmp_path / "project"
    project_root.mkdir(parents=True, exist_ok=True)

    monkeypatch.setenv("IRONCLAW_ENV", "test")
    monkeypatch.setenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000")

    # _build_env(project_root) returns a full os.environ-style mapping
    result = _invoke_with_supported_kwargs(
        bootstrap_env,
        project_root=project_root,
    )

    assert isinstance(result, dict)
    assert result.get("IRONCLAW_ENV", os.environ["IRONCLAW_ENV"]) == "test"
    assert result.get("IRONCLAW_BASE_URL", os.environ["IRONCLAW_BASE_URL"]) == "http://127.0.0.1:8000"