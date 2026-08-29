from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
from typing import Any, Final

from app.core.install_key_formats import InstallKeyFormatRegistry, normalize_install_key_program

DEFAULT_BASE_URL: Final[str] = "http://127.0.0.1:8000"
DEFAULT_CONFIG_DIRNAME: Final[str] = ".ironclaw"
DEFAULT_CONFIG_FILENAME: Final[str] = "config.json"
DEFAULT_SKILL_CONFIG_FILENAME: Final[str] = "skill.json"
DEFAULT_ENV_FILENAME: Final[str] = ".env"
DEFAULT_TIMEOUT_SECONDS: Final[float] = 20.0
DEFAULT_BACKUP_TARGET: Final[str] = "primary"
DEFAULT_RESTORE_TARGET: Final[str] = "primary"
DEFAULT_RETENTION_DAYS: Final[int] = 30
DEFAULT_PROVIDER_TARGETS: Final[tuple[str, ...]] = tuple(InstallKeyFormatRegistry.list_programs())
_SUBPROCESS_TIMEOUT: Final[int] = 300


class IronClawInstallerError(RuntimeError):
    """Base installer error."""


@dataclass(frozen=True, slots=True)
class InstallConfig:
    project_root: Path
    config_dir: Path
    config_file: Path
    env_file: Path
    base_url: str
    backup_target: str
    restore_target: str
    retention_days: int
    install_vscode_settings: bool
    install_skill_config: bool
    write_env_file: bool
    overwrite: bool
    provider_targets: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["project_root"] = str(self.project_root)
        payload["config_dir"] = str(self.config_dir)
        payload["config_file"] = str(self.config_file)
        payload["env_file"] = str(self.env_file)
        payload["provider_targets"] = list(self.provider_targets)
        return payload


@dataclass(frozen=True, slots=True)
class InstallResult:
    ok: bool
    config_file: Path
    env_file: Path | None
    vscode_settings_file: Path | None
    skill_config_file: Path | None
    created_paths: tuple[str, ...]
    updated_paths: tuple[str, ...]
    skipped_paths: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "config_file": str(self.config_file),
            "env_file": str(self.env_file) if self.env_file else None,
            "vscode_settings_file": str(self.vscode_settings_file) if self.vscode_settings_file else None,
            "skill_config_file": str(self.skill_config_file) if self.skill_config_file else None,
            "created_paths": list(self.created_paths),
            "updated_paths": list(self.updated_paths),
            "skipped_paths": list(self.skipped_paths),
        }


def _project_root() -> Path:
    return Path(__file__).resolve().parent


def _default_config_dir() -> Path:
    return Path.home() / DEFAULT_CONFIG_DIRNAME


def _strong_secret(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def _ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _normalize_base_url(value: str) -> str:
    normalized = str(value).strip().rstrip("/")
    if not normalized:
        raise IronClawInstallerError("--base-url must not be empty")
    if not (normalized.startswith("http://") or normalized.startswith("https://")):
        raise IronClawInstallerError("--base-url must start with http:// or https://")
    return normalized


def _normalize_target(value: str, *, flag_name: str, default: str) -> str:
    normalized = str(value).strip()
    if normalized:
        return normalized
    if default:
        return default
    raise IronClawInstallerError(f"{flag_name} must not be empty")


def _normalize_provider_targets(values: tuple[str, ...] | list[str] | None) -> tuple[str, ...]:
    if not values:
        return DEFAULT_PROVIDER_TARGETS

    normalized: list[str] = []
    seen: set[str] = set()

    for value in values:
        item = str(value).strip()
        if not item:
            continue
        canonical = InstallKeyFormatRegistry.normalize_program(item) or normalize_install_key_program(item)
        if canonical is None:
            raise IronClawInstallerError(f"Unsupported provider target: {value!r}")
        if canonical not in seen:
            normalized.append(canonical)
            seen.add(canonical)

    if not normalized:
        raise IronClawInstallerError("--provider-target must include at least one non-empty value")

    return tuple(normalized)


def _classify_write(
    path: Path,
    wrote: bool,
    existed_before: bool,
    created: list[str],
    updated: list[str],
    skipped: list[str],
) -> None:
    path_text = str(path)
    if not wrote:
        skipped.append(path_text)
        return
    if existed_before:
        updated.append(path_text)
    else:
        created.append(path_text)


def _write_json_file(path: Path, payload: dict[str, Any], *, overwrite: bool) -> tuple[bool, bool]:
    existed_before = path.exists()
    if existed_before and not overwrite:
        return False, True

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return True, existed_before


def _write_text_file(path: Path, content: str, *, overwrite: bool) -> tuple[bool, bool]:
    existed_before = path.exists()
    if existed_before and not overwrite:
        return False, True

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return True, existed_before


def _build_runtime_config(config: InstallConfig) -> dict[str, Any]:
    provider_set = set(config.provider_targets)
    features = {
        "health": True,
        "ui": True,
        "backup": True,
        "restore": True,
        "guarded_execution": True,
        "skill_integration": True,
        "shared_skill_package": "security_guardian" in provider_set,
        "claude_integration": "claude_code" in provider_set,
        "openclaw_integration": "openclaw" in provider_set,
        "cursor_integration": "cursor" in provider_set,
        "goose_integration": "goose" in provider_set,
        "gemini_cli_integration": "gemini_cli" in provider_set,
        "copilot_integration": "copilot" in provider_set,
        "security_guardian_integration": "security_guardian" in provider_set,
    }
    return {
        "schema_version": 1,
        "product": "IronClaw-Security",
        "install_mode": "local-bootstrap",
        "skill_mode": True,
        "base_url": config.base_url,
        "backup_target": config.backup_target,
        "restore_target": config.restore_target,
        "retention_days": config.retention_days,
        "provider_targets": list(config.provider_targets),
        "paths": {
            "project_root": str(config.project_root),
            "env_file": str(config.env_file),
        },
        "features": features,
    }


def _build_env_contents(config: InstallConfig) -> str:
    shared_skill_package = "security_guardian" in set(config.provider_targets)
    values = {
        "ENVIRONMENT": "production",
        "IRONCLAW_BASE_URL": config.base_url,
        "IRONCLAW_PERSISTENCE_MODE": "supabase",
        "IRONCLAW_API_KEY": _strong_secret(24),
        "AUTH_REQUIRED": "true",
        "IRONCLAW_BACKUP_TARGET_NAME": config.backup_target,
        "IRONCLAW_RESTORE_TARGET_NAME": config.restore_target,
        "IRONCLAW_BACKUP_RETENTION_DAYS": str(config.retention_days),
        "IRONCLAW_BACKUP_ENCRYPTION": "true",
        "IRONCLAW_BACKUP_CHECKSUM": "true",
        "IRONCLAW_PROVIDER_TARGETS": ",".join(config.provider_targets),
        "IRONCLAW_SHARED_SKILL_PACKAGE": "true" if shared_skill_package else "false",
        "IRONCLAW_SECURITY_GUARDIAN_INTEGRATION": "true" if shared_skill_package else "false",
        "SECRET_KEY": _strong_secret(),
        "JWT_SECRET": _strong_secret(),
        "API_SECRET": _strong_secret(),
        "SUPABASE_URL": "",
        "SUPABASE_SERVICE_ROLE_KEY": "",
        "SUPABASE_KEY": "",
        "SUPABASE_ANON_KEY": "",
    }

    lines = [
        "# IronClaw-Security local installer environment",
        "# Review and replace placeholder values before production use.",
        "# IRONCLAW_API_KEY is auto-generated — save it before sharing with clients.",
        "",
    ]
    lines.extend(f"{key}={value}" for key, value in values.items())
    lines.append("")
    return "\n".join(lines)


def _build_vscode_settings() -> dict[str, Any]:
    return {
        "python.defaultInterpreterPath": "${workspaceFolder}\\.venv\\Scripts\\python.exe",
        "python.analysis.extraPaths": ["${workspaceFolder}"],
        "python.analysis.autoSearchPaths": True,
        "python.analysis.diagnosticMode": "workspace",
        "python.analysis.typeCheckingMode": "basic",
        "python.testing.pytestEnabled": True,
        "python.testing.unittestEnabled": False,
        "python.testing.pytestArgs": ["tests"],
        "python.envFile": "${workspaceFolder}\\.env",
        "python.terminal.activateEnvironment": True,
        "[python]": {
            "editor.defaultFormatter": "ms-python.black-formatter",
            "editor.formatOnSave": True,
            "editor.codeActionsOnSave": {
                "source.organizeImports": "explicit",
                "source.fixAll": "explicit",
            },
        },
        "editor.formatOnSave": True,
        "files.trimTrailingWhitespace": True,
        "files.insertFinalNewline": True,
        "files.trimFinalNewlines": True,
        "files.eol": "\n",
        "ruff.nativeServer": "on",
        "ruff.organizeImports": True,
        "ruff.lint.run": "onType",
    }


def _build_skill_config(config: InstallConfig) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "enabled": True,
        "product": "IronClaw-Security",
        "provider_targets": list(config.provider_targets),
        "base_url": config.base_url,
        "default_policy_mode": "review",
        "default_timeout_seconds": DEFAULT_TIMEOUT_SECONDS,
    }


def _venv_python(project_root: Path) -> Path:
    if os.name == "nt":
        return project_root / ".venv" / "Scripts" / "python.exe"
    return project_root / ".venv" / "bin" / "python"


def _validate_project_root(project_root: Path) -> None:
    if not project_root.exists():
        raise IronClawInstallerError(f"Project root does not exist: {project_root}")
    if not project_root.is_dir():
        raise IronClawInstallerError(f"Project root is not a directory: {project_root}")
    if not (project_root / "pyproject.toml").exists():
        raise IronClawInstallerError(f"pyproject.toml was not found under project root: {project_root}")


def _create_virtualenv(project_root: Path) -> None:
    venv_python = _venv_python(project_root)
    if venv_python.exists():
        return

    subprocess.run(
        [sys.executable, "-m", "venv", str(project_root / ".venv")],
        cwd=str(project_root),
        check=True,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )


def _install_project_editable(project_root: Path) -> None:
    venv_python = _venv_python(project_root)
    if not venv_python.exists():
        raise IronClawInstallerError("Virtual environment python executable was not created.")

    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "--upgrade", "pip"],
        cwd=str(project_root),
        check=True,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )
    subprocess.run(
        [str(venv_python), "-m", "pip", "install", "-e", ".[dev]"],
        cwd=str(project_root),
        check=True,
        capture_output=True,
        text=True,
        timeout=_SUBPROCESS_TIMEOUT,
    )


def run_install(config: InstallConfig) -> InstallResult:
    created_paths: list[str] = []
    updated_paths: list[str] = []
    skipped_paths: list[str] = []

    _validate_project_root(config.project_root)
    _ensure_directory(config.config_dir)

    config_payload = _build_runtime_config(config)
    wrote_config, config_existed_before = _write_json_file(
        config.config_file,
        config_payload,
        overwrite=config.overwrite,
    )
    _classify_write(
        config.config_file,
        wrote_config,
        config_existed_before,
        created_paths,
        updated_paths,
        skipped_paths,
    )

    env_path: Path | None = None
    if config.write_env_file:
        env_contents = _build_env_contents(config)
        wrote_env, env_existed_before = _write_text_file(
            config.env_file,
            env_contents,
            overwrite=config.overwrite,
        )
        env_path = config.env_file
        _classify_write(
            config.env_file,
            wrote_env,
            env_existed_before,
            created_paths,
            updated_paths,
            skipped_paths,
        )

    vscode_settings_path: Path | None = None
    if config.install_vscode_settings:
        vscode_dir = config.project_root / ".vscode"
        vscode_settings_path = vscode_dir / "settings.json"
        wrote_vscode, vscode_existed_before = _write_json_file(
            vscode_settings_path,
            _build_vscode_settings(),
            overwrite=config.overwrite,
        )
        _classify_write(
            vscode_settings_path,
            wrote_vscode,
            vscode_existed_before,
            created_paths,
            updated_paths,
            skipped_paths,
        )

    skill_config_path: Path | None = None
    if config.install_skill_config:
        skill_config_path = config.config_dir / DEFAULT_SKILL_CONFIG_FILENAME
        wrote_skill, skill_existed_before = _write_json_file(
            skill_config_path,
            _build_skill_config(config),
            overwrite=config.overwrite,
        )
        _classify_write(
            skill_config_path,
            wrote_skill,
            skill_existed_before,
            created_paths,
            updated_paths,
            skipped_paths,
        )

    _create_virtualenv(config.project_root)
    _install_project_editable(config.project_root)

    return InstallResult(
        ok=True,
        config_file=config.config_file,
        env_file=env_path,
        vscode_settings_file=vscode_settings_path,
        skill_config_file=skill_config_path,
        created_paths=tuple(created_paths),
        updated_paths=tuple(updated_paths),
        skipped_paths=tuple(skipped_paths),
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Install and bootstrap IronClaw-Security for local skill-style use.",
    )
    parser.add_argument(
        "--project-root",
        type=Path,
        default=_project_root(),
        help="Project root directory containing pyproject.toml.",
    )
    parser.add_argument(
        "--config-dir",
        type=Path,
        default=_default_config_dir(),
        help="Directory for persistent IronClaw user configuration.",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("IRONCLAW_BASE_URL", DEFAULT_BASE_URL),
        help=f"Base URL for IronClaw runtime, default: {DEFAULT_BASE_URL}",
    )
    parser.add_argument(
        "--backup-target",
        default=os.getenv("IRONCLAW_BACKUP_TARGET_NAME", DEFAULT_BACKUP_TARGET),
        help=f"Default backup target, default: {DEFAULT_BACKUP_TARGET}",
    )
    parser.add_argument(
        "--restore-target",
        default=os.getenv("IRONCLAW_RESTORE_TARGET_NAME", DEFAULT_RESTORE_TARGET),
        help=f"Default restore target, default: {DEFAULT_RESTORE_TARGET}",
    )
    parser.add_argument(
        "--retention-days",
        type=int,
        default=DEFAULT_RETENTION_DAYS,
        help=f"Backup retention days, default: {DEFAULT_RETENTION_DAYS}",
    )
    parser.add_argument(
        "--provider-target",
        action="append",
        default=[],
        help="Provider target to enable, repeatable, e.g. --provider-target claude_code --provider-target openclaw --provider-target security_guardian",
    )
    parser.add_argument(
        "--no-vscode",
        action="store_true",
        help="Do not write .vscode/settings.json.",
    )
    parser.add_argument(
        "--no-skill-config",
        action="store_true",
        help="Do not write skill.json into the user IronClaw config directory.",
    )
    parser.add_argument(
        "--no-env",
        action="store_true",
        help="Do not write the project .env file.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite existing generated files.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the install result as JSON.",
    )
    return parser


def build_install_config(args: argparse.Namespace) -> InstallConfig:
    project_root = args.project_root.expanduser().resolve()
    config_dir = args.config_dir.expanduser().resolve()

    if args.retention_days <= 0:
        raise IronClawInstallerError("--retention-days must be greater than 0")

    return InstallConfig(
        project_root=project_root,
        config_dir=config_dir,
        config_file=config_dir / DEFAULT_CONFIG_FILENAME,
        env_file=project_root / DEFAULT_ENV_FILENAME,
        base_url=_normalize_base_url(args.base_url),
        backup_target=_normalize_target(
            args.backup_target,
            flag_name="--backup-target",
            default=DEFAULT_BACKUP_TARGET,
        ),
        restore_target=_normalize_target(
            args.restore_target,
            flag_name="--restore-target",
            default=DEFAULT_RESTORE_TARGET,
        ),
        retention_days=args.retention_days,
        install_vscode_settings=not args.no_vscode,
        install_skill_config=not args.no_skill_config,
        write_env_file=not args.no_env,
        overwrite=bool(args.overwrite),
        provider_targets=_normalize_provider_targets(args.provider_target),
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = build_install_config(args)
        result = run_install(config)
    except (IronClawInstallerError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        print(f"[ironclaw-installer] failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print("[ironclaw-installer] install completed")
        print(f"[ironclaw-installer] config: {result.config_file}")
        if result.skill_config_file is not None:
            print(f"[ironclaw-installer] skill-config: {result.skill_config_file}")
        if result.env_file is not None:
            print(f"[ironclaw-installer] env: {result.env_file}")
        if result.vscode_settings_file is not None:
            print(f"[ironclaw-installer] vscode: {result.vscode_settings_file}")
        if result.created_paths:
            print(f"[ironclaw-installer] created: {len(result.created_paths)}")
        if result.updated_paths:
            print(f"[ironclaw-installer] updated: {len(result.updated_paths)}")
        if result.skipped_paths:
            print(f"[ironclaw-installer] skipped: {len(result.skipped_paths)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
