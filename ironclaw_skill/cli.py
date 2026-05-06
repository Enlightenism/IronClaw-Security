from __future__ import annotations


import argparse
import json
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final


from ironclaw_installer import InstallConfig, build_install_config, run_install


try:
    from ironclaw_skill import __version__
except ImportError:
    __version__ = "0.1.0"


DEFAULT_CONFIG_DIR: Final[Path] = Path.home() / ".ironclaw"
DEFAULT_CONFIG_FILE: Final[str] = "config.json"
DEFAULT_SKILL_FILE: Final[str] = "skill.json"
DEFAULT_BASE_URL: Final[str] = os.getenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
DEFAULT_TIMEOUT_SECONDS: Final[float] = 10.0


class IronClawSkillCliError(RuntimeError):
    """Base skill CLI error."""


@dataclass(frozen=True, slots=True)
class SkillStatus:
    installed: bool
    config_dir: Path
    config_file: Path
    skill_file: Path
    env_file: Path
    base_url: str | None
    version: str

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["config_dir"] = str(self.config_dir)
        payload["config_file"] = str(self.config_file)
        payload["skill_file"] = str(self.skill_file)
        payload["env_file"] = str(self.env_file)
        return payload


@dataclass(frozen=True, slots=True)
class SkillDoctorResult:
    ok: bool
    checks: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        return {"ok": self.ok, "checks": list(self.checks)}


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _config_dir() -> Path:
    return Path(os.getenv("IRONCLAW_CONFIG_DIR", DEFAULT_CONFIG_DIR)).expanduser().resolve()


def _config_file() -> Path:
    return _config_dir() / DEFAULT_CONFIG_FILE


def _skill_file() -> Path:
    return _config_dir() / DEFAULT_SKILL_FILE


def _env_file() -> Path:
    return _project_root() / ".env"


def _load_json_file(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise IronClawSkillCliError(f"Expected JSON object in {path}")
    return payload


def _derive_status() -> SkillStatus:
    # ENV VAR always takes priority over config file value.
    env_base_url = os.getenv("IRONCLAW_BASE_URL", "").strip()

    if env_base_url:
        base_url: str | None = env_base_url.rstrip("/")
    else:
        config_payload = _load_json_file(_config_file()) if _config_file().exists() else {}
        raw = config_payload.get("base_url")
        base_url = raw.strip().rstrip("/") if isinstance(raw, str) and raw.strip() else None

    return SkillStatus(
        installed=_config_file().exists() and _skill_file().exists(),
        config_dir=_config_dir(),
        config_file=_config_file(),
        skill_file=_skill_file(),
        env_file=_env_file(),
        base_url=base_url,
        version=__version__,
    )


def _doctor() -> SkillDoctorResult:
    status = _derive_status()
    checks: list[dict[str, Any]] = []

    checks.append(
        {
            "name": "project-root",
            "ok": _project_root().exists(),
            "detail": str(_project_root()),
        }
    )
    checks.append(
        {
            "name": "config-file",
            "ok": status.config_file.exists(),
            "detail": str(status.config_file),
        }
    )
    checks.append(
        {
            "name": "skill-file",
            "ok": status.skill_file.exists(),
            "detail": str(status.skill_file),
        }
    )
    checks.append(
        {
            "name": "env-file",
            "ok": status.env_file.exists(),
            "detail": str(status.env_file),
        }
    )
    checks.append(
        {
            "name": "base-url",
            "ok": bool(status.base_url),
            "detail": status.base_url or "missing",
        }
    )

    ok = all(bool(item["ok"]) for item in checks)
    return SkillDoctorResult(ok=ok, checks=tuple(checks))


def _print_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))


def _cmd_install(args: argparse.Namespace) -> int:
    install_args = argparse.Namespace(
        project_root=args.project_root,
        config_dir=args.config_dir,
        base_url=args.base_url,
        backup_target=args.backup_target,
        restore_target=args.restore_target,
        retention_days=args.retention_days,
        no_vscode=args.no_vscode,
        no_skill_config=args.no_skill_config,
        no_env=args.no_env,
        overwrite=args.overwrite,
    )

    config: InstallConfig = build_install_config(install_args)
    result = run_install(config)

    if args.json:
        _print_json(result.to_dict())
    else:
        print("[ironclaw-skill] install completed")
        print(f"[ironclaw-skill] config file: {result.config_file}")
        if result.env_file is not None:
            print(f"[ironclaw-skill] env file: {result.env_file}")
        if result.vscode_settings_file is not None:
            print(f"[ironclaw-skill] vscode settings: {result.vscode_settings_file}")

    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    status = _derive_status()
    if args.json:
        _print_json(status.to_dict())
    else:
        print(f"installed: {'yes' if status.installed else 'no'}")
        print(f"version: {status.version}")
        print(f"config_dir: {status.config_dir}")
        print(f"config_file: {status.config_file}")
        print(f"skill_file: {status.skill_file}")
        print(f"env_file: {status.env_file}")
        print(f"base_url: {status.base_url or 'unset'}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    result = _doctor()
    if args.json:
        _print_json(result.to_dict())
    else:
        for check in result.checks:
            label = "OK" if check["ok"] else "FAIL"
            print(f"[{label}] {check['name']}: {check['detail']}")
    return 0 if result.ok else 1


def _cmd_version(_: argparse.Namespace) -> int:
    print(__version__)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw-skill",
        description="IronClaw skill-style installer and local integration CLI.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print command output as JSON when supported.",
    )

    subparsers = parser.add_subparsers(dest="command")

    install_parser = subparsers.add_parser(
        "install",
        help="Bootstrap IronClaw skill-style local installation.",
    )
    install_parser.add_argument(
        "--project-root",
        type=Path,
        default=_project_root(),
        help="Project root directory containing pyproject.toml.",
    )
    install_parser.add_argument(
        "--config-dir",
        type=Path,
        default=_config_dir(),
        help="Persistent IronClaw config directory.",
    )
    install_parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for IronClaw runtime, default: {DEFAULT_BASE_URL}",
    )
    install_parser.add_argument(
        "--backup-target",
        default=os.getenv("IRONCLAW_BACKUP_TARGET_NAME", "primary"),
        help="Default backup target name.",
    )
    install_parser.add_argument(
        "--restore-target",
        default=os.getenv("IRONCLAW_RESTORE_TARGET_NAME", "primary"),
        help="Default restore target name.",
    )
    install_parser.add_argument(
        "--retention-days",
        type=int,
        default=30,
        help="Backup retention days.",
    )
    install_parser.add_argument(
        "--no-vscode",
        action="store_true",
        help="Do not write .vscode/settings.json.",
    )
    install_parser.add_argument(
        "--no-skill-config",
        action="store_true",
        help="Do not write skill.json config.",
    )
    install_parser.add_argument(
        "--no-env",
        action="store_true",
        help="Do not write .env.",
    )
    install_parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite generated files.",
    )
    install_parser.set_defaults(func=_cmd_install)

    status_parser = subparsers.add_parser(
        "status",
        help="Show current IronClaw skill installation status.",
    )
    status_parser.set_defaults(func=_cmd_status)

    doctor_parser = subparsers.add_parser(
        "doctor",
        help="Run local IronClaw skill diagnostics.",
    )
    doctor_parser.set_defaults(func=_cmd_doctor)

    version_parser = subparsers.add_parser(
        "version",
        help="Print CLI version.",
    )
    version_parser.set_defaults(func=_cmd_version)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    try:
        func = getattr(args, "func")
        return int(func(args))
    except IronClawSkillCliError as exc:
        print(f"[ironclaw-skill] failed: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ironclaw-skill] unexpected failure: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))