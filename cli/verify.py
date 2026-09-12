from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import sys
from typing import Any

from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import get_install_key_registry

_GENERIC_INSTALL_KEY_PREFIXES = (
    "sk_",
    "ghp_",
    "gho_",
    "github_pat_",
    "token_",
    "secret_",
    "api_",
    "api-key",
    "api_key",
    "platform-api-key",
    "platform_api_key",
    "internal-platform-api-key",
    "internal_platform_api_key",
    "system-api-key",
    "system_api_key",
    "bearer ",
    "x-api-key",
)


@dataclass(slots=True)
class VerifyCheck:
    name: str
    ok: bool
    detail: str
    recommendation: str | None = None


@dataclass(slots=True)
class VerifyReport:
    product: str
    version: str
    environment: str
    platform: str
    python_executable: str
    install_root: str
    config_path: str
    dry_run: bool
    checks: list[VerifyCheck]
    next_steps: list[str]


def _default_install_root() -> Path:
    home = Path.home()
    system = platform.system().lower()
    if system == "windows":
        return home / "IronClaw-Security"
    return home / ".ironclaw-security"


def _default_config_path(root: Path) -> Path:
    return root / "config.json"


def _env_name() -> str:
    return os.getenv("IRONCLAW_ENV", "local")


def _normalize_runtime_program(value: str | None) -> str | None:
    if value is None:
        return None
    program = InstallKeyFormatRegistry.normalize_program(str(value).strip())
    if program is not None:
        return program
    normalized = str(value).strip().lower().replace("-", "_")
    return InstallKeyFormatRegistry.normalize_program(normalized)


def _looks_like_generic_install_key(candidate: str | None) -> bool:
    if candidate is None:
        return False
    normalized = str(candidate).strip().lower()
    if not normalized:
        return False
    if any(normalized.startswith(prefix) for prefix in _GENERIC_INSTALL_KEY_PREFIXES):
        return True
    if "platform" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized):
        return True
    if "system" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized):
        return True
    if "api" in normalized and "key" in normalized:
        return True
    return False


def _read_config_install_keys(config_path: Path) -> dict[str, str]:
    if not config_path.exists():
        return {}
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    if not isinstance(payload, dict):
        return {}

    keys: dict[str, str] = {}
    nested = payload.get("install_keys")
    if isinstance(nested, dict):
        for program_name, candidate in nested.items():
            if isinstance(candidate, str) and candidate.strip():
                normalized_program = _normalize_runtime_program(program_name)
                if normalized_program is None:
                    normalized_program = InstallKeyFormatRegistry.parse_program_from_key(candidate)
                if normalized_program is not None:
                    keys[normalized_program] = candidate.strip()

    for key_name in (
        "install_key",
        "installKey",
        "install_key_value",
        "installKeyValue",
        "raw_install_key",
        "rawInstallKey",
        "paid_install_key",
        "paidInstallKey",
    ):
        candidate = payload.get(key_name)
        if isinstance(candidate, str) and candidate.strip():
            program = InstallKeyFormatRegistry.parse_program_from_key(candidate)
            if program is not None:
                keys[program] = candidate.strip()

    return dict(sorted(keys.items(), key=lambda item: InstallKeyFormatRegistry.list_programs().index(item[0]) if item[0] in InstallKeyFormatRegistry.list_programs() else len(InstallKeyFormatRegistry.list_programs())))


def _is_verified_install_key(candidate: str | None, *, program: str | None = None, owner_key: str | None = None) -> bool:
    if not isinstance(candidate, str):
        return False
    value = candidate.strip()
    if not value:
        return False
    if value.startswith("ic_org_") or _looks_like_generic_install_key(value):
        return False

    runtime_program = _normalize_runtime_program(program) or InstallKeyFormatRegistry.parse_program_from_key(value)
    if runtime_program is None:
        return False

    spec = InstallKeyFormatRegistry.get_spec(runtime_program)
    if value.startswith("ic_") and not value.startswith(spec.prefix):
        return False
    if not value.startswith(spec.prefix):
        return False

    registry = get_install_key_registry()
    record = registry.authenticate_install_key(value)
    if record is None:
        return False
    if not getattr(record, "active", False):
        return False
    if str(getattr(record, "payment_status", "")).strip().lower() != "paid":
        return False
    if str(getattr(record, "entitlements_status", "")).strip().lower() != "active":
        return False
    if not getattr(record, "issued_after_payment", False):
        return False
    if runtime_program != _normalize_runtime_program(getattr(record, "program", None)):
        return False
    normalized_owner = (owner_key or "").strip().lower()
    if normalized_owner and (getattr(record, "owner_key", "") or "").strip().lower() != normalized_owner:
        return False
    return True


def _install_key_verification_checks(config_path: Path) -> list[VerifyCheck]:
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8")) if config_path.exists() else {}
    except Exception:
        payload = {}

    installed_keys = _read_config_install_keys(config_path)
    provider_targets = payload.get("provider_targets", []) if isinstance(payload, dict) else []
    expected_programs: list[str] = []
    if isinstance(provider_targets, list):
        for target in provider_targets:
            program = _normalize_runtime_program(target)
            if program is not None:
                expected_programs.append(program)
    if not expected_programs:
        expected_programs = list(installed_keys)

    if not installed_keys and not expected_programs:
        return [
            VerifyCheck(
                name="install-key-runtime",
                ok=False,
                detail="No live install key was embedded in the local configuration.",
                recommendation="Install or repurchase a valid paid runtime install key before running verification.",
            )
        ]

    checks: list[VerifyCheck] = []
    seen: set[str] = set()
    for program in expected_programs:
        seen.add(program)
        candidate = installed_keys.get(program)
        ok = _is_verified_install_key(candidate, program=program)
        detail = f"Runtime {program} key is present and verified as active and paid." if ok else f"Runtime {program} key is missing, stale, mismatched, revoked, or not backed by a paid entitlement."
        recommendation = None if ok else f"Reinstall or repurchase a valid paid install key for {program} and rerun verification."
        checks.append(
            VerifyCheck(
                name=f"install-key-runtime-{program}",
                ok=ok,
                detail=detail,
                recommendation=recommendation,
            )
        )

    for program, candidate in installed_keys.items():
        if program not in seen:
            ok = _is_verified_install_key(candidate, program=program)
            checks.append(
                VerifyCheck(
                    name=f"install-key-runtime-{program}",
                    ok=ok,
                    detail=(f"Runtime {program} key is present and verified as active and paid." if ok else f"Runtime {program} key is stale, mismatched, revoked, or not backed by a paid entitlement."),
                    recommendation=None if ok else f"Replace the invalid key for {program} with a valid paid install key.",
                )
            )

    return checks


def _venv_python(root: Path) -> Path:
    if platform.system().lower() == "windows":
        return root / ".venv" / "Scripts" / "python.exe"
    return root / ".venv" / "bin" / "python"


def _venv_pip(root: Path) -> Path:
    if platform.system().lower() == "windows":
        return root / ".venv" / "Scripts" / "pip.exe"
    return root / ".venv" / "bin" / "pip"


def _requirements_path(root: Path) -> Path:
    return root / "requirements.txt"


def _python_version_check() -> VerifyCheck:
    version = sys.version_info
    ok = (version.major, version.minor) >= (3, 11)
    detail = f"Detected Python {version.major}.{version.minor}.{version.micro}"
    recommendation = None if ok else "Use Python 3.11 or newer."
    return VerifyCheck(
        name="python-version",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _install_root_check(root: Path) -> VerifyCheck:
    ok = root.exists() and root.is_dir()
    detail = f"Install root: {root}"
    recommendation = None if ok else "Run install first to create the installation root."
    return VerifyCheck(
        name="install-root",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _config_exists_check(config_path: Path) -> VerifyCheck:
    ok = config_path.exists() and config_path.is_file()
    detail = f"Config path: {config_path}"
    recommendation = None if ok else "Create the configuration file before running verify again."
    return VerifyCheck(
        name="config-file",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _config_readable_check(config_path: Path) -> VerifyCheck:
    if not config_path.exists():
        return VerifyCheck(
            name="config-readable",
            ok=False,
            detail=f"Config path missing: {config_path}",
            recommendation="Create a readable configuration file.",
        )

    try:
        json.loads(config_path.read_text(encoding="utf-8"))
        return VerifyCheck(
            name="config-readable",
            ok=True,
            detail=f"Readable JSON configuration: {config_path}",
        )
    except Exception as exc:
        return VerifyCheck(
            name="config-readable",
            ok=False,
            detail=f"Unreadable configuration: {config_path} ({exc})",
            recommendation="Fix the configuration file JSON before verifying again.",
        )


def _config_channel_check(config_path: Path) -> VerifyCheck:
    if not config_path.exists():
        return VerifyCheck(
            name="config-channel",
            ok=False,
            detail=f"Config path missing: {config_path}",
            recommendation="Create config.json with a valid update channel.",
        )

    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return VerifyCheck(
            name="config-channel",
            ok=False,
            detail=f"Unable to parse config for channel check: {exc}",
            recommendation="Fix config.json JSON before verifying channel configuration.",
        )

    channel = str(payload.get("channel", "stable")).strip().lower()
    ok = channel in {"stable", "preview", "dev"}
    return VerifyCheck(
        name="config-channel",
        ok=ok,
        detail=f"Configured channel: {channel}",
        recommendation=None if ok else "Use stable, preview, or dev in config.json.",
    )


def _data_directory_check(root: Path) -> VerifyCheck:
    data_dir = root / "data"
    ok = data_dir.exists() and data_dir.is_dir()
    detail = f"Data directory: {data_dir}"
    recommendation = None if ok else "Create the data directory used by IronClaw-Security."
    return VerifyCheck(
        name="data-directory",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _logs_directory_check(root: Path) -> VerifyCheck:
    logs_dir = root / "logs"
    ok = logs_dir.exists() and logs_dir.is_dir()
    detail = f"Log directory: {logs_dir}"
    recommendation = None if ok else "Create the log directory used by IronClaw-Security."
    return VerifyCheck(
        name="log-directory",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _venv_python_check(root: Path) -> VerifyCheck:
    path = _venv_python(root)
    ok = path.exists() and path.is_file()
    detail = f"Virtual environment Python: {path}"
    recommendation = None if ok else "Create the managed virtual environment before verifying runtime readiness."
    return VerifyCheck(
        name="virtualenv-python",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _venv_pip_check(root: Path) -> VerifyCheck:
    path = _venv_pip(root)
    ok = path.exists() and path.is_file()
    detail = f"Virtual environment pip: {path}"
    recommendation = None if ok else "Ensure pip is installed inside the managed virtual environment."
    return VerifyCheck(
        name="virtualenv-pip",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _requirements_file_check(root: Path) -> VerifyCheck:
    path = _requirements_path(root)
    ok = path.exists() and path.is_file()
    detail = f"Requirements file: {path}"
    recommendation = None if ok else "Restore requirements.txt so dependency verification can succeed."
    return VerifyCheck(
        name="requirements-file",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _git_available_check() -> VerifyCheck:
    git_path = shutil.which("git")
    ok = git_path is not None
    detail = f"Git executable: {git_path or 'not found'}"
    recommendation = None if ok else "Install Git so update and recovery flows work correctly."
    return VerifyCheck(
        name="git-available",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _api_key_env_check() -> VerifyCheck:
    candidates = [
        "IRONCLAW_API_KEY",
        "IRONCLAW_INTERNAL_API_KEY",
        "IRONCLAW_PLATFORM_API_KEY",
    ]
    found = [name for name in candidates if os.getenv(name)]
    ok = bool(found)
    detail = "Detected environment keys: " + (", ".join(found) if found else "none")
    recommendation = None if ok else "Set at least one platform API key environment variable."
    return VerifyCheck(
        name="api-key-env",
        ok=ok,
        detail=detail,
        recommendation=recommendation,
    )


def _hostname_check() -> VerifyCheck:
    try:
        hostname = socket.gethostname()
        return VerifyCheck(
            name="hostname",
            ok=bool(hostname),
            detail=f"Hostname: {hostname}",
            recommendation=None if hostname else "Ensure the local hostname is available.",
        )
    except Exception as exc:
        return VerifyCheck(
            name="hostname",
            ok=False,
            detail=f"Unable to resolve hostname ({exc})",
            recommendation="Check basic system networking and hostname configuration.",
        )


def build_verify_report(
    install_root: Path | None = None,
    dry_run: bool = True,
) -> VerifyReport:
    root = (install_root or _default_install_root()).resolve()
    config_path = _default_config_path(root)

    checks = [
        _python_version_check(),
        _install_root_check(root),
        _config_exists_check(config_path),
        _config_readable_check(config_path),
        _config_channel_check(config_path),
        _data_directory_check(root),
        _logs_directory_check(root),
        _venv_python_check(root),
        _venv_pip_check(root),
        _requirements_file_check(root),
        _git_available_check(),
        _api_key_env_check(),
        _hostname_check(),
    ]

    if config_path.exists():
        checks.extend(_install_key_verification_checks(config_path))

    next_steps = [
        "Run the install command if configuration, dependencies, or directories are missing.",
        "Set required environment variables for platform and customer key flows.",
        "Run the update command if the install is present but incomplete.",
        "Start the application and run a protected request after verify succeeds.",
    ]

    return VerifyReport(
        product="IronClaw-Security",
        version="gen1",
        environment=_env_name(),
        platform=platform.platform(),
        python_executable=sys.executable,
        install_root=str(root),
        config_path=str(config_path),
        dry_run=dry_run,
        checks=checks,
        next_steps=next_steps,
    )


def run_verify_command(
    install_root: Path | None = None,
    dry_run: bool = True,
) -> VerifyReport:
    return build_verify_report(
        install_root=install_root,
        dry_run=dry_run,
    )


def _render_text(report: VerifyReport) -> str:
    lines = [
        f"{report.product} verification report",
        f"version: {report.version}",
        f"environment: {report.environment}",
        f"platform: {report.platform}",
        f"python: {report.python_executable}",
        f"install_root: {report.install_root}",
        f"config_path: {report.config_path}",
        f"dry_run: {str(report.dry_run).lower()}",
        "",
        "checks:",
    ]

    for check in report.checks:
        status = "OK" if check.ok else "FAIL"
        lines.append(f"- [{status}] {check.name}: {check.detail}")
        if check.recommendation:
            lines.append(f"  recommendation: {check.recommendation}")

    lines.append("")
    lines.append("next_steps:")
    for step in report.next_steps:
        lines.append(f"- {step}")

    return "\n".join(lines)


def _render_json(report: VerifyReport) -> str:
    payload: dict[str, Any] = asdict(report)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_verify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw-verify",
        description="Verify a local IronClaw-Security installation.",
    )
    parser.add_argument(
        "--install-root",
        type=Path,
        default=None,
        help="Optional override for the installation root directory.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Render the verification report without performing any mutating action.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render the verification report as JSON.",
    )
    return parser


def handle_verify_args(args: argparse.Namespace) -> int:
    report = run_verify_command(
        install_root=args.install_root,
        dry_run=bool(args.dry_run),
    )

    if args.json:
        print(_render_json(report))
    else:
        print(_render_text(report))

    return 0 if all(check.ok for check in report.checks) else 1


def main() -> int:
    parser = build_verify_parser()
    args = parser.parse_args()
    return handle_verify_args(args)


if __name__ == "__main__":
    raise SystemExit(main())
