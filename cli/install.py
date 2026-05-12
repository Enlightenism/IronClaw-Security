from __future__ import annotations

import argparse
import json
import platform
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


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
        f"Create virtual environment at { _default_virtualenv_path(root) }",
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


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="ironclaw-install",
        description="Prepare a local installation plan for IronClaw-Security.",
    )
    parser.add_argument(
        "--install-root",
        type=Path,
        default=None,
        help="Optional override for the installation root directory.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render the install plan as JSON.",
    )
    args = parser.parse_args()

    plan = build_install_plan(args.install_root)

    if args.json:
        print(_render_json(plan))
    else:
        print(_render_text(plan))

    return 0 if all(check.ok for check in plan.checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())