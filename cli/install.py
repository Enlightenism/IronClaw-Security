from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import platform
import sys
from typing import Any

from app.core.install_key_formats import RUNTIME_INSTALL_KEY_PROGRAMS, InstallKeyFormatRegistry
from ironclaw_installer import IronClawInstallerError, build_install_claim_commands


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
    install_command: str | None
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
        return program if program in RUNTIME_INSTALL_KEY_PROGRAMS else None
    normalized = str(value).strip().lower().replace("-", "_")
    program = InstallKeyFormatRegistry.normalize_program(normalized)
    return program if program in RUNTIME_INSTALL_KEY_PROGRAMS else None


def build_operator_install_result(
    *,
    platform: str | None,
    claim_token: str | None,
    dry_run: bool = False,
) -> OperatorInstallResult:
    runtime_program = _normalize_runtime_program(platform)
    if runtime_program is None:
        return OperatorInstallResult(
            status="blocked",
            platform=platform,
            program=None,
            install_command=None,
            retry_after_purchase=True,
            message="Unsupported runtime target for this install flow.",
        )

    if not claim_token or not str(claim_token).strip():
        return OperatorInstallResult(
            status="blocked",
            platform=platform,
            program=runtime_program,
            install_command=None,
            retry_after_purchase=True,
            message="A valid one-time install claim is required; request a fresh claim from the authenticated dashboard.",
        )

    try:
        command = build_install_claim_commands({runtime_program: str(claim_token).strip()}).get(runtime_program)
    except IronClawInstallerError:
        command = None
    if command is None:
        return OperatorInstallResult(
            status="blocked",
            platform=platform,
            program=runtime_program,
            install_command=None,
            retry_after_purchase=True,
            message="A valid one-time install claim is required; request a fresh claim from the authenticated dashboard.",
        )

    return OperatorInstallResult(
        status="ready" if dry_run else "ready",
        platform=platform,
        program=runtime_program,
        install_command=command,
        retry_after_purchase=False,
        message="Ready to install with the canonical short-lived, single-use claim.",
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
        "--install-claim",
        dest="claim_token",
        default=None,
        help="A short-lived, single-use install claim returned by the authenticated dashboard.",
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

    if args.platform or args.claim_token:
        result = build_operator_install_result(
            platform=args.platform,
            claim_token=args.claim_token,
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
