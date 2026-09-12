from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import platform
import sys
from typing import Any

from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import get_install_key_registry
from ironclaw_installer import build_install_key_commands

_GENERIC_INSTALL_KEY_PREFIXES: tuple[str, ...] = (
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
class InstallCheck:
    name: str
    ok: bool
    detail: str
    recommendation: str | None = None


@dataclass(slots=True)
class InstallPlan:
    product: str
    version: str
    install_root: str
    platform: str
    python_executable: str
    virtualenv_path: str
    config_path: str
    data_path: str
    log_path: str
    checks: list[InstallCheck]
    next_steps: list[str]


@dataclass(slots=True)
class OperatorInstallResult:
    status: str
    platform: str | None
    program: str | None
    install_key: str | None
    install_command: str | None
    owner_key: str | None
    retry_after_purchase: bool
    message: str


def _default_install_root() -> Path:
    home = Path.home()
    system = platform.system().lower()
    if system == "windows":
        return home / "IronClaw-Security"
    return home / ".ironclaw-security"


def _default_config_path(root: Path) -> Path:
    return root / "config.json"


def _default_data_path(root: Path) -> Path:
    return root / "data"


def _default_log_path(root: Path) -> Path:
    return root / "logs"


def _default_virtualenv_path(root: Path) -> Path:
    return root / ".venv"


def _python_version_ok() -> tuple[bool, str]:
    version = sys.version_info
    ok = (version.major, version.minor) >= (3, 11)
    detail = f"Detected Python {version.major}.{version.minor}.{version.micro}"
    return ok, detail


def _path_writable(path: Path) -> tuple[bool, str]:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".write_test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True, f"Writable: {path}"
    except Exception as exc:
        return False, f"Not writable: {path} ({exc})"


def _build_checks(root: Path) -> list[InstallCheck]:
    python_ok, python_detail = _python_version_ok()
    root_ok, root_detail = _path_writable(root)
    data_ok, data_detail = _path_writable(_default_data_path(root))
    log_ok, log_detail = _path_writable(_default_log_path(root))

    checks = [
        InstallCheck(
            name="python-version",
            ok=python_ok,
            detail=python_detail,
            recommendation=None if python_ok else "Use Python 3.11 or newer.",
        ),
        InstallCheck(
            name="install-root",
            ok=root_ok,
            detail=root_detail,
            recommendation=None if root_ok else "Choose a writable installation directory.",
        ),
        InstallCheck(
            name="data-directory",
            ok=data_ok,
            detail=data_detail,
            recommendation=None if data_ok else "Verify the data directory permissions.",
        ),
        InstallCheck(
            name="log-directory",
            ok=log_ok,
            detail=log_detail,
            recommendation=None if log_ok else "Verify the log directory permissions.",
        ),
    ]
    return checks


def build_install_plan(install_root: Path | None = None) -> InstallPlan:
    root = install_root or _default_install_root()
    checks = _build_checks(root)

    next_steps = [
        f"Create virtual environment at {_default_virtualenv_path(root)}",
        "Install project dependencies",
        "Set required environment variables and API keys",
        "Run CLI verify command after installation completes",
    ]

    return InstallPlan(
        product="IronClaw-Security",
        version="gen1",
        install_root=str(root),
        platform=platform.platform(),
        python_executable=sys.executable,
        virtualenv_path=str(_default_virtualenv_path(root)),
        config_path=str(_default_config_path(root)),
        data_path=str(_default_data_path(root)),
        log_path=str(_default_log_path(root)),
        checks=checks,
        next_steps=next_steps,
    )


def _render_text(plan: InstallPlan) -> str:
    lines = [
        f"{plan.product} installer plan",
        f"version: {plan.version}",
        f"platform: {plan.platform}",
        f"python: {plan.python_executable}",
        f"install_root: {plan.install_root}",
        f"virtualenv_path: {plan.virtualenv_path}",
        f"config_path: {plan.config_path}",
        f"data_path: {plan.data_path}",
        f"log_path: {plan.log_path}",
        "",
        "checks:",
    ]

    for check in plan.checks:
        status = "OK" if check.ok else "FAIL"
        lines.append(f"- [{status}] {check.name}: {check.detail}")
        if check.recommendation:
            lines.append(f"  recommendation: {check.recommendation}")

    lines.append("")
    lines.append("next_steps:")
    for step in plan.next_steps:
        lines.append(f"- {step}")

    return "\n".join(lines)


def _render_json(plan: InstallPlan) -> str:
    payload: dict[str, Any] = asdict(plan)
    return json.dumps(payload, indent=2, ensure_ascii=False)


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


def _validate_paid_install_key_for_runtime(
    program: str | None,
    install_key: str | None,
    *,
    owner_key: str | None = None,
) -> tuple[bool, str | None]:
    runtime_program = _normalize_runtime_program(program)
    if runtime_program is None:
        return False, "Unsupported runtime target for this install flow."

    candidate = str(install_key).strip() if install_key is not None else ""
    if not candidate:
        return False, "A valid paid install key is required; retry after purchase or wait for the backend to return an active key."
    if candidate.startswith("ic_org_") or _looks_like_generic_install_key(candidate):
        return False, "A valid paid install key is required; generic or non-install keys are rejected."

    spec = InstallKeyFormatRegistry.get_spec(runtime_program)
    valid_prefixes = (spec.prefix,)
    if candidate.startswith("ic_") and not candidate.startswith(valid_prefixes):
        return False, "A valid paid install key is required; the key does not match the canonical runtime family."
    if not candidate.startswith(valid_prefixes):
        return False, "A valid paid install key is required; expected prefix does not match the canonical runtime family."

    registry = get_install_key_registry()
    record = registry.authenticate_install_key(candidate)
    if record is None:
        return False, "A valid paid install key is required; the backend has not returned an active paid key yet."
    if not bool(getattr(record, "active", False)):
        return False, "The backend returned an inactive install key; retry after purchase or after key activation."
    if getattr(record, "payment_status", "") != "paid":
        return False, "A valid paid install key is required; the key is not marked as paid."
    if getattr(record, "entitlements_status", "") != "active":
        return False, "A valid paid install key is required; the key entitlements are not active."
    if not getattr(record, "issued_after_payment", False):
        return False, "A valid paid install key is required; the key was not issued after successful payment."
    if runtime_program != _normalize_runtime_program(getattr(record, "program", None)):
        return False, "A valid paid install key is required; the key belongs to a different runtime family."
    normalized_owner = (owner_key or "").strip().lower()
    if normalized_owner and (getattr(record, "owner_key", "") or "").strip().lower() != normalized_owner:
        return False, "A valid paid install key is required; the key does not belong to the supplied owner."
    return True, None


def build_install_command(program: str | None, install_key: str | None, *, owner_key: str | None = None) -> str | None:
    runtime_program = _normalize_runtime_program(program)
    if runtime_program is None:
        return None

    valid, _ = _validate_paid_install_key_for_runtime(runtime_program, install_key, owner_key=owner_key)
    if not valid:
        return None

    commands = build_install_key_commands({runtime_program: str(install_key).strip()})
    return commands.get(runtime_program)


def build_operator_install_result(
    *,
    platform: str | None,
    install_key: str | None,
    owner_key: str | None = None,
    dry_run: bool = False,
) -> OperatorInstallResult:
    runtime_program = _normalize_runtime_program(platform)
    if runtime_program is None:
        return OperatorInstallResult(
            status="blocked",
            platform=platform,
            program=None,
            install_key=install_key,
            install_command=None,
            owner_key=owner_key,
            retry_after_purchase=True,
            message="Unsupported runtime target for this install flow.",
        )

    if not install_key or not str(install_key).strip():
        return OperatorInstallResult(
            status="blocked",
            platform=platform,
            program=runtime_program,
            install_key=None,
            install_command=None,
            owner_key=owner_key,
            retry_after_purchase=True,
            message="A valid paid install key is required; retry after purchase or wait for the backend to return an active key.",
        )

    valid, reason = _validate_paid_install_key_for_runtime(runtime_program, install_key, owner_key=owner_key)
    if not valid:
        return OperatorInstallResult(
            status="blocked",
            platform=platform,
            program=runtime_program,
            install_key=str(install_key).strip(),
            install_command=None,
            owner_key=owner_key,
            retry_after_purchase=True,
            message=reason or "A valid paid install key is required; retry after purchase or wait for the backend to return an active key.",
        )

    command = build_install_command(runtime_program, install_key, owner_key=owner_key)
    if command is None:
        return OperatorInstallResult(
            status="blocked",
            platform=platform,
            program=runtime_program,
            install_key=str(install_key).strip(),
            install_command=None,
            owner_key=owner_key,
            retry_after_purchase=True,
            message="A valid paid install key is required; the backend has not returned a usable active key.",
        )

    return OperatorInstallResult(
        status="ready" if dry_run else "ready",
        platform=platform,
        program=runtime_program,
        install_key=str(install_key).strip(),
        install_command=command,
        owner_key=owner_key,
        retry_after_purchase=False,
        message="Ready to install with the canonical active paid key returned by the backend.",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ironclaw-install",
        description="Prepare a local installation plan for IronClaw-Security or execute a backend-safe operator install flow.",
    )
    parser.add_argument(
        "--install-root",
        type=Path,
        default=None,
        help="Optional override for the installation root directory.",
    )
    parser.add_argument(
        "--platform",
        default=None,
        help="Canonical runtime platform to install, e.g. openclaw, claude_code, cursor, goose, gemini_cli, copilot, hermes.",
    )
    parser.add_argument(
        "--install-key",
        dest="install_key",
        default=None,
        help="A paid install key returned by the backend for the selected runtime.",
    )
    parser.add_argument(
        "--owner-key",
        default=None,
        help="Owner identifier that must match the install key record.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the key and print the canonical installation command without executing it.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render the install plan or install result as JSON.",
    )
    args = parser.parse_args(argv)

    if args.platform or args.install_key or args.owner_key:
        result = build_operator_install_result(
            platform=args.platform,
            install_key=args.install_key,
            owner_key=args.owner_key,
            dry_run=args.dry_run,
        )
        payload = asdict(result)
        if args.json:
            print(json.dumps(payload, indent=2, ensure_ascii=False))
        else:
            print(f"install status: {result.status}")
            print(f"message: {result.message}")
            if result.install_command:
                print(f"command: {result.install_command}")
        return 0 if result.status == "ready" else 1

    plan = build_install_plan(args.install_root)

    if args.json:
        print(_render_json(plan))
    else:
        print(_render_text(plan))

    return 0 if all(check.ok for check in plan.checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
