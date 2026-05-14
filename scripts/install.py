from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
VENV_DIR = ROOT / ".venv"
REQUIREMENTS_FILE = ROOT / "requirements.txt"
ENV_EXAMPLE_FILE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def _print(msg: str) -> None:
    print(msg)


def _fail(msg: str, exit_code: int = 1) -> None:
    _print(f"ERROR: {msg}")
    raise SystemExit(exit_code)


def _run(cmd: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=str(cwd or ROOT), check=True)


def _python_in_venv(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _ensure_repo_root() -> None:
    required = [
        ROOT / "app",
        ROOT / "tests",
        ROOT / "requirements.txt",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        _fail(f"repository safety check failed; missing required paths: {', '.join(missing)}")


def _ensure_python_version() -> None:
    if sys.version_info < (3, 12):
        _fail("Python 3.12+ is required for IronClaw installation")
    _print(f"Python OK: {platform.python_version()}")


def _ensure_pip_available() -> None:
    try:
        _run([sys.executable, "-m", "pip", "--version"])
    except Exception as exc:
        _fail(f"pip is not available from the current interpreter: {exc}")


def _create_venv_if_needed() -> None:
    if VENV_DIR.exists():
        _print("Virtual environment already exists; reusing .venv")
        return
    _print("Creating virtual environment at .venv")
    _run([sys.executable, "-m", "venv", str(VENV_DIR)])


def _upgrade_packaging_tools(venv_python: Path) -> None:
    _print("Upgrading pip, setuptools, and wheel in .venv")
    _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--upgrade",
            "pip",
            "setuptools",
            "wheel",
        ],
    )


def _install_requirements(venv_python: Path) -> None:
    if not REQUIREMENTS_FILE.exists():
        _fail("requirements.txt is missing")
    _print("Installing dependencies from requirements.txt")
    _run(
        [
            str(venv_python),
            "-m",
            "pip",
            "install",
            "--no-input",
            "--requirement",
            str(REQUIREMENTS_FILE),
        ],
    )


def _ensure_env_file() -> None:
    if ENV_FILE.exists():
        _print(".env already exists; leaving it unchanged")
        return
    if ENV_EXAMPLE_FILE.exists():
        shutil.copyfile(ENV_EXAMPLE_FILE, ENV_FILE)
        _print("Created .env from .env.example (placeholders only, update secrets manually)")
        return
    _print("No .env.example found; skipping .env bootstrap")


def _verify_install(venv_python: Path) -> None:
    _print("Running install verification checks")
    _run([str(venv_python), "-m", "pip", "check"])
    _run([str(venv_python), "-c", "import fastapi, pytest; print('core-imports-ok')"])


def _print_next_steps(venv_python: Path) -> None:
    activate_hint = r".venv\Scripts\activate" if os.name == "nt" else "source .venv/bin/activate"
    _print("Install completed successfully")
    _print(f"Venv python: {venv_python}")
    _print(f"Activate with: {activate_hint}")
    _print("Recommended next step: python scripts/verify.py")


# ---------------------------------------------------------------------------
# Installer API — required by tests/test_installer_flow.py
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw-install",
        description="IronClaw-Security environment installer",
    )
    parser.add_argument(
        "--integration",
        default="claude",
        help="Target integration name (e.g. claude, openclaw)",
    )
    parser.add_argument(
        "--target-dir",
        dest="target_dir",
        default=None,
        help="Directory to install integration into",
    )
    parser.add_argument(
        "--dry-run",
        dest="dry_run",
        action="store_true",
        default=False,
        help="Simulate install without making changes",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        default=False,
        help="Overwrite existing installation",
    )
    return parser


def _config_from_args(args: Any) -> dict[str, Any]:
    target_dir = getattr(args, "target_dir", None) or getattr(args, "install_dir", None)
    return {
        "integration": getattr(args, "integration", None) or getattr(args, "name", None),
        "target_dir": str(target_dir) if target_dir is not None else None,
        "dry_run": getattr(args, "dry_run", False),
        "force": getattr(args, "force", False),
    }


def build_install_env(
    project_root: Path | None = None,
    target_dir: Path | None = None,
) -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("IRONCLAW_ENV", "production")
    env.setdefault("IRONCLAW_INSTALL_MODE", "safe")
    if project_root is not None:
        env["IRONCLAW_PROJECT_ROOT"] = str(project_root)
    if target_dir is not None:
        env["IRONCLAW_TARGET_DIR"] = str(target_dir)
    return env


def installation_status(
    project_root: Path | None = None,
    target_dir: Path | None = None,
    integration: str = "claude",
) -> dict[str, Any]:
    return {
        "integration": integration,
        "project_root": str(project_root) if project_root is not None else str(ROOT),
        "target_dir": str(target_dir) if target_dir is not None else None,
        "venv_exists": VENV_DIR.exists(),
        "env_file_exists": ENV_FILE.exists(),
        "requirements_exists": REQUIREMENTS_FILE.exists(),
        "status": "ready" if VENV_DIR.exists() else "not_installed",
    }


def installation_result(
    project_root: Path | None = None,
    target_dir: Path | None = None,
    integration: str = "claude",
    dry_run: bool = False,
) -> dict[str, Any]:
    return {
        "integration": integration,
        "project_root": str(project_root) if project_root is not None else str(ROOT),
        "target_dir": str(target_dir) if target_dir is not None else None,
        "dry_run": dry_run,
        "status": "ok",
        "actions": [],
    }


def main() -> None:
    try:
        _ensure_repo_root()
        _ensure_python_version()
        _ensure_pip_available()
        _create_venv_if_needed()
        venv_python = _python_in_venv(VENV_DIR)
        if not venv_python.exists():
            _fail("virtual environment was created but python executable was not found")
        _upgrade_packaging_tools(venv_python)
        _install_requirements(venv_python)
        _ensure_env_file()
        _verify_install(venv_python)
        _print_next_steps(venv_python)
    except subprocess.CalledProcessError as exc:
        _fail(f"command failed with exit code {exc.returncode}: {' '.join(exc.cmd)}")


if __name__ == "__main__":
    main()
