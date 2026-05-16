from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Final

DEFAULT_HOST: Final[str] = os.getenv("IRONCLAW_SERVICE_HOST", "127.0.0.1")
DEFAULT_PORT: Final[int] = int(os.getenv("IRONCLAW_SERVICE_PORT", "8000"))
DEFAULT_APP: Final[str] = os.getenv("IRONCLAW_APP_IMPORT", "app.main:app")
DEFAULT_LOG_LEVEL: Final[str] = os.getenv("IRONCLAW_LOG_LEVEL", "info")
DEFAULT_PID_FILENAME: Final[str] = "ironclaw-service.pid"
DEFAULT_LOG_FILENAME: Final[str] = "ironclaw-service.log"
DEFAULT_START_TIMEOUT_SECONDS: Final[float] = 20.0
DEFAULT_STOP_TIMEOUT_SECONDS: Final[float] = 10.0
DEFAULT_STATUS_TIMEOUT_SECONDS: Final[float] = 0.5


class IronClawServiceError(RuntimeError):
    """Raised for service lifecycle failures."""


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    project_root: Path
    run_dir: Path
    pid_file: Path
    log_file: Path
    app_import: str
    host: str
    port: int
    log_level: str
    reload: bool

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["project_root"] = str(self.project_root)
        payload["run_dir"] = str(self.run_dir)
        payload["pid_file"] = str(self.pid_file)
        payload["log_file"] = str(self.log_file)
        return payload


@dataclass(frozen=True, slots=True)
class ServiceState:
    running: bool
    pid: int | None
    host: str
    port: int
    pid_file: Path
    log_file: Path

    def to_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "pid": self.pid,
            "host": self.host,
            "port": self.port,
            "pid_file": str(self.pid_file),
            "log_file": str(self.log_file),
        }


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _default_run_dir(project_root: Path) -> Path:
    return project_root / ".ironclaw"


def _ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _pid_exists(pid: int) -> bool:
    if pid <= 0:
        return False

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    else:
        return True


def _read_pid(pid_file: Path) -> int | None:
    if not pid_file.exists():
        return None

    raw = pid_file.read_text(encoding="utf-8").strip()
    if not raw:
        return None

    try:
        return int(raw)
    except ValueError:
        return None


def _write_pid(pid_file: Path, pid: int) -> None:
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(f"{pid}\n", encoding="utf-8")


def _remove_pid(pid_file: Path) -> None:
    if pid_file.exists():
        pid_file.unlink(missing_ok=True)


def _port_is_open(host: str, port: int, timeout: float = DEFAULT_STATUS_TIMEOUT_SECONDS) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _service_state(config: ServiceConfig) -> ServiceState:
    pid = _read_pid(config.pid_file)
    running = bool(pid and _pid_exists(pid))
    return ServiceState(
        running=running,
        pid=pid if running else None,
        host=config.host,
        port=config.port,
        pid_file=config.pid_file,
        log_file=config.log_file,
    )


def _uvicorn_command(config: ServiceConfig) -> list[str]:
    command = [
        sys.executable,
        "-m",
        "uvicorn",
        config.app_import,
        "--host",
        config.host,
        "--port",
        str(config.port),
        "--log-level",
        config.log_level,
    ]
    if config.reload:
        command.append("--reload")
    return command


def _build_env(project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    project_root_str = str(project_root)
    existing_pythonpath = env.get("PYTHONPATH", "").strip()
    env["PYTHONPATH"] = project_root_str if not existing_pythonpath else f"{project_root_str}{os.pathsep}{existing_pythonpath}"
    return env


def start_service(
    config: ServiceConfig,
    *,
    timeout_seconds: float = DEFAULT_START_TIMEOUT_SECONDS,
) -> ServiceState:
    state = _service_state(config)
    if state.running:
        return state

    _ensure_directory(config.run_dir)
    command = _uvicorn_command(config)

    with config.log_file.open("a", encoding="utf-8") as log_handle:
        if os.name == "nt":
            # CREATE_NEW_PROCESS_GROUP is only defined on Windows.
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
            process = subprocess.Popen(
                command,
                cwd=str(config.project_root),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                env=_build_env(config.project_root),
                creationflags=creationflags,
            )
        else:
            process = subprocess.Popen(
                command,
                cwd=str(config.project_root),
                stdout=log_handle,
                stderr=subprocess.STDOUT,
                env=_build_env(config.project_root),
                start_new_session=True,
            )

    _write_pid(config.pid_file, process.pid)

    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if _port_is_open(config.host, config.port):
            return _service_state(config)

        if process.poll() is not None:
            _remove_pid(config.pid_file)
            raise IronClawServiceError(
                f"IronClaw service exited early with code {process.returncode}. Check log: {config.log_file}",
            )

        time.sleep(0.25)

    try:
        if os.name == "nt":
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except Exception:
        pass

    _remove_pid(config.pid_file)
    raise IronClawServiceError(
        f"IronClaw service did not become ready within {timeout_seconds} seconds.",
    )


def stop_service(
    config: ServiceConfig,
    *,
    timeout_seconds: float = DEFAULT_STOP_TIMEOUT_SECONDS,
) -> ServiceState:
    state = _service_state(config)
    if not state.running or state.pid is None:
        _remove_pid(config.pid_file)
        return _service_state(config)

    pid = state.pid

    if os.name == "nt":
        try:
            subprocess.run(
                ["taskkill", "/PID", str(pid), "/T", "/F"],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            if _pid_exists(pid):
                raise IronClawServiceError(f"Failed to stop IronClaw service PID {pid}: {exc.stderr}") from exc
    else:
        try:
            os.killpg(pid, signal.SIGTERM)
        except ProcessLookupError:
            _remove_pid(config.pid_file)
            return _service_state(config)

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            if not _pid_exists(pid):
                break
            time.sleep(0.25)

        if _pid_exists(pid):
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

    _remove_pid(config.pid_file)
    return _service_state(config)


def status_service(config: ServiceConfig) -> ServiceState:
    state = _service_state(config)
    if state.running and not _port_is_open(config.host, config.port):
        _remove_pid(config.pid_file)
        return _service_state(config)
    return state


def restart_service(
    config: ServiceConfig,
    *,
    start_timeout_seconds: float = DEFAULT_START_TIMEOUT_SECONDS,
    stop_timeout_seconds: float = DEFAULT_STOP_TIMEOUT_SECONDS,
) -> ServiceState:
    stop_service(config, timeout_seconds=stop_timeout_seconds)
    return start_service(config, timeout_seconds=start_timeout_seconds)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Manage the local IronClaw sidecar service for skill-style integrations.",
    )
    parser.add_argument("--json", action="store_true", help="Print structured JSON output.")
    parser.add_argument(
        "--project-root",
        type=Path,
        default=_project_root(),
        help="Project root containing the IronClaw application.",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help="Directory for PID and log files. Default: <project-root>/.ironclaw",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_HOST,
        help=f"Host interface for uvicorn. Default: {DEFAULT_HOST}",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"Port for uvicorn. Default: {DEFAULT_PORT}",
    )
    parser.add_argument(
        "--app",
        default=DEFAULT_APP,
        help=f"ASGI app import path. Default: {DEFAULT_APP}",
    )
    parser.add_argument(
        "--log-level",
        default=DEFAULT_LOG_LEVEL,
        help=f"Uvicorn log level. Default: {DEFAULT_LOG_LEVEL}",
    )
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Enable uvicorn autoreload for development use.",
    )

    subparsers = parser.add_subparsers(dest="command")

    start_parser = subparsers.add_parser("start", help="Start the IronClaw service.")
    start_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_START_TIMEOUT_SECONDS,
        help=f"Startup readiness timeout in seconds. Default: {DEFAULT_START_TIMEOUT_SECONDS}",
    )

    stop_parser = subparsers.add_parser("stop", help="Stop the IronClaw service.")
    stop_parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_STOP_TIMEOUT_SECONDS,
        help=f"Stop timeout in seconds. Default: {DEFAULT_STOP_TIMEOUT_SECONDS}",
    )

    subparsers.add_parser("status", help="Show current IronClaw service status.")

    restart_parser = subparsers.add_parser("restart", help="Restart the IronClaw service.")
    restart_parser.add_argument(
        "--start-timeout",
        type=float,
        default=DEFAULT_START_TIMEOUT_SECONDS,
        help=f"Restart startup timeout in seconds. Default: {DEFAULT_START_TIMEOUT_SECONDS}",
    )
    restart_parser.add_argument(
        "--stop-timeout",
        type=float,
        default=DEFAULT_STOP_TIMEOUT_SECONDS,
        help=f"Restart stop timeout in seconds. Default: {DEFAULT_STOP_TIMEOUT_SECONDS}",
    )

    return parser


def _config_from_args(args: argparse.Namespace) -> ServiceConfig:
    project_root = args.project_root.expanduser().resolve()
    run_dir = args.run_dir.expanduser().resolve() if args.run_dir else _default_run_dir(project_root)

    if args.port <= 0 or args.port > 65535:
        raise IronClawServiceError("--port must be between 1 and 65535")

    return ServiceConfig(
        project_root=project_root,
        run_dir=run_dir,
        pid_file=run_dir / DEFAULT_PID_FILENAME,
        log_file=run_dir / DEFAULT_LOG_FILENAME,
        app_import=str(args.app).strip(),
        host=str(args.host).strip(),
        port=int(args.port),
        log_level=str(args.log_level).strip(),
        reload=bool(args.reload),
    )


def _print_result(payload: dict[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))
        return

    action = payload.get("action", "unknown")
    state = payload.get("state", {})
    print(f"[ironclaw-service] action: {action}")
    print(f"[ironclaw-service] running: {state.get('running')}")
    print(f"[ironclaw-service] pid: {state.get('pid')}")
    print(f"[ironclaw-service] host: {state.get('host')}")
    print(f"[ironclaw-service] port: {state.get('port')}")
    print(f"[ironclaw-service] pid_file: {state.get('pid_file')}")
    print(f"[ironclaw-service] log_file: {state.get('log_file')}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    try:
        config = _config_from_args(args)

        if args.command == "start":
            state = start_service(config, timeout_seconds=float(args.timeout))
        elif args.command == "stop":
            state = stop_service(config, timeout_seconds=float(args.timeout))
        elif args.command == "status":
            state = status_service(config)
        elif args.command == "restart":
            state = restart_service(
                config,
                start_timeout_seconds=float(args.start_timeout),
                stop_timeout_seconds=float(args.stop_timeout),
            )
        else:
            raise IronClawServiceError(f"Unsupported command: {args.command}")

        _print_result(
            {
                "action": args.command,
                "state": state.to_dict(),
            },
            as_json=bool(args.json),
        )
        return 0
    except IronClawServiceError as exc:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2))
        else:
            print(f"[ironclaw-service] failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
