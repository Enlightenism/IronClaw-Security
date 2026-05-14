from __future__ import annotations

import argparse
import json
import platform
import shutil
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

_ALLOWED_CHANNELS = {"stable", "preview", "dev"}


@dataclass(slots=True)
class UpdateStep:
    name: str
    ok: bool
    detail: str
    recommendation: str | None = None


@dataclass(slots=True)
class UpdatePlan:
    product: str
    version: str
    install_root: str
    platform: str
    python_executable: str
    target_channel: str
    config_path: str
    dry_run: bool
    steps: list[UpdateStep]
    next_steps: list[str]


def _default_install_root() -> Path:
    home = Path.home()
    system = platform.system().lower()
    if system == "windows":
        return home / "IronClaw-Security"
    return home / ".ironclaw-security"


def _default_config_path(root: Path) -> Path:
    return root / "config.json"


def _python_ok() -> tuple[bool, str]:
    version = sys.version_info
    ok = (version.major, version.minor) >= (3, 11)
    return ok, f"Detected Python {version.major}.{version.minor}.{version.micro}"


def _path_exists(path: Path) -> tuple[bool, str]:
    ok = path.exists()
    return ok, f"Path: {path}"


def _git_ok() -> tuple[bool, str]:
    git_path = shutil.which("git")
    ok = git_path is not None
    return ok, f"Git executable: {git_path or 'not found'}"


def _pip_ok() -> tuple[bool, str]:
    pip_path = shutil.which("pip")
    ok = pip_path is not None
    return ok, f"Pip executable: {pip_path or 'not found'}"


def _read_config_channel(config_path: Path) -> tuple[bool, str]:
    if not config_path.exists():
        return False, "Config file not found."
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Config is not valid JSON: {exc}"
    configured_channel = str(data.get("channel", "stable")).strip().lower()
    if configured_channel not in _ALLOWED_CHANNELS:
        return False, f"Config channel is invalid: {configured_channel}"
    return True, f"Config channel: {configured_channel}"


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


def _build_steps(root: Path, channel: str) -> list[UpdateStep]:
    python_ok, python_detail = _python_ok()
    root_ok, root_detail = _path_exists(root)
    config_path = _default_config_path(root)
    config_ok, config_detail = _path_exists(config_path)
    venv_python = _venv_python(root)
    venv_pip = _venv_pip(root)
    venv_ok, venv_detail = _path_exists(venv_python)
    requirements_ok, requirements_detail = _path_exists(_requirements_path(root))
    git_ok, git_detail = _git_ok()
    pip_ok, pip_detail = _pip_ok()
    config_channel_ok, config_channel_detail = _read_config_channel(config_path)

    return [
        UpdateStep(
            name="python-version",
            ok=python_ok,
            detail=python_detail,
            recommendation=None if python_ok else "Use Python 3.11 or newer before updating.",
        ),
        UpdateStep(
            name="install-root",
            ok=root_ok,
            detail=root_detail,
            recommendation=None if root_ok else "Run install first to create the installation root.",
        ),
        UpdateStep(
            name="config-file",
            ok=config_ok,
            detail=config_detail,
            recommendation=None if config_ok else "Create or restore config.json before updating.",
        ),
        UpdateStep(
            name="config-channel",
            ok=config_channel_ok,
            detail=config_channel_detail,
            recommendation=None if config_channel_ok else "Ensure config.json contains a valid channel: stable, preview, or dev.",
        ),
        UpdateStep(
            name="virtualenv-python",
            ok=venv_ok,
            detail=f"Virtual environment Python: {venv_python}" if venv_ok else f"Missing virtual environment Python: {venv_python}",
            recommendation=None if venv_ok else "Create the virtual environment before applying updates.",
        ),
        UpdateStep(
            name="virtualenv-pip",
            ok=venv_pip.exists(),
            detail=f"Virtual environment pip: {venv_pip}" if venv_pip.exists() else f"Missing virtual environment pip: {venv_pip}",
            recommendation=None if venv_pip.exists() else "Install pip inside the managed virtual environment before updating.",
        ),
        UpdateStep(
            name="requirements-file",
            ok=requirements_ok,
            detail=requirements_detail,
            recommendation=None if requirements_ok else "Restore requirements.txt so dependencies can be refreshed.",
        ),
        UpdateStep(
            name="git-available",
            ok=git_ok,
            detail=git_detail,
            recommendation=None if git_ok else "Install Git so the update command can refresh tracked source files.",
        ),
        UpdateStep(
            name="pip-available",
            ok=pip_ok,
            detail=pip_detail,
            recommendation=None if pip_ok else "Install pip so dependency upgrades can run.",
        ),
        UpdateStep(
            name="update-channel",
            ok=channel in _ALLOWED_CHANNELS,
            detail=f"Requested update channel: {channel}",
            recommendation=None if channel in _ALLOWED_CHANNELS else "Use stable, preview, or dev.",
        ),
    ]


def build_update_plan(
    install_root: Path | None = None,
    channel: str = "stable",
    dry_run: bool = True,
) -> UpdatePlan:
    root = (install_root or _default_install_root()).resolve()
    normalized_channel = channel.strip().lower()
    steps = _build_steps(root, normalized_channel)

    next_steps = [
        "Back up the current configuration before applying changes.",
        "Fetch the latest tracked source for the selected channel.",
        "Refresh dependencies inside the managed virtual environment.",
        "Re-run the verify command after the update completes.",
    ]

    return UpdatePlan(
        product="IronClaw-Security",
        version="gen1",
        install_root=str(root),
        platform=platform.platform(),
        python_executable=sys.executable,
        target_channel=normalized_channel,
        config_path=str(_default_config_path(root)),
        dry_run=dry_run,
        steps=steps,
        next_steps=next_steps,
    )


def _run_command(command: list[str], cwd: Path) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            command,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            check=False,
        )
    except Exception as exc:
        return False, str(exc)

    output = (completed.stdout or completed.stderr or "").strip()
    if completed.returncode != 0:
        return False, output or f"Command failed with exit code {completed.returncode}"
    return True, output or "ok"


def run_update_command(
    install_root: Path | None = None,
    channel: str = "stable",
    dry_run: bool = True,
) -> UpdatePlan:
    plan = build_update_plan(
        install_root=install_root,
        channel=channel,
        dry_run=dry_run,
    )

    if not all(step.ok for step in plan.steps):
        return plan

    if dry_run:
        return plan

    root = Path(plan.install_root)
    venv_python = _venv_python(root)

    git_fetch_ok, git_fetch_detail = _run_command(["git", "fetch", "--all", "--tags"], cwd=root)
    git_status_ok, git_status_detail = _run_command(["git", "status", "--short"], cwd=root)
    pip_upgrade_ok, pip_upgrade_detail = _run_command(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--upgrade",
            "-r",
            str(_requirements_path(root)),
        ],
        cwd=root,
    )

    runtime_steps = [
        UpdateStep(
            name="git-fetch",
            ok=git_fetch_ok,
            detail=git_fetch_detail or "Fetched remote updates.",
            recommendation=None if git_fetch_ok else "Check Git remote access and repository state.",
        ),
        UpdateStep(
            name="git-status-cleanliness",
            ok=git_status_ok,
            detail=git_status_detail or "Working tree is clean.",
            recommendation=None if git_status_ok else "Resolve repository state before continuing.",
        ),
        UpdateStep(
            name="dependency-refresh",
            ok=pip_upgrade_ok,
            detail=pip_upgrade_detail or "Dependencies refreshed.",
            recommendation=None if pip_upgrade_ok else "Inspect pip output and fix dependency issues.",
        ),
    ]

    refreshed = build_update_plan(
        install_root=root,
        channel=plan.target_channel,
        dry_run=dry_run,
    )
    refreshed.steps.extend(runtime_steps)
    return refreshed


def _render_text(plan: UpdatePlan) -> str:
    lines = [
        f"{plan.product} update plan",
        f"version: {plan.version}",
        f"platform: {plan.platform}",
        f"python: {plan.python_executable}",
        f"install_root: {plan.install_root}",
        f"config_path: {plan.config_path}",
        f"target_channel: {plan.target_channel}",
        f"dry_run: {str(plan.dry_run).lower()}",
        "",
        "steps:",
    ]

    for step in plan.steps:
        status = "OK" if step.ok else "FAIL"
        lines.append(f"- [{status}] {step.name}: {step.detail}")
        if step.recommendation:
            lines.append(f"  recommendation: {step.recommendation}")

    lines.append("")
    lines.append("next_steps:")
    for item in plan.next_steps:
        lines.append(f"- {item}")

    return "\n".join(lines)


def _render_json(plan: UpdatePlan) -> str:
    payload: dict[str, Any] = asdict(plan)
    return json.dumps(payload, indent=2, ensure_ascii=False)


def build_update_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw-update",
        description="Prepare or execute an update for an IronClaw-Security installation.",
    )
    parser.add_argument(
        "--install-root",
        type=Path,
        default=None,
        help="Optional override for the installation root directory.",
    )
    parser.add_argument(
        "--channel",
        default="stable",
        help="Update channel to target: stable, preview, or dev.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview the update plan without applying changes.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Render the update plan as JSON.",
    )
    return parser


def handle_update_args(args: argparse.Namespace) -> int:
    plan = run_update_command(
        install_root=args.install_root,
        channel=str(args.channel).strip().lower(),
        dry_run=bool(args.dry_run),
    )

    if args.json:
        print(_render_json(plan))
    else:
        print(_render_text(plan))

    return 0 if all(step.ok for step in plan.steps) else 1


def main() -> int:
    parser = build_update_parser()
    args = parser.parse_args()
    return handle_update_args(args)


if __name__ == "__main__":
    raise SystemExit(main())
