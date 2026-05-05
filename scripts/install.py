from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


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
        ]
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
        ]
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
    activate_hint = (
        r".venv\Scripts\activate"
        if os.name == "nt"
        else "source .venv/bin/activate"
    )
    _print("Install completed successfully")
    _print(f"Venv python: {venv_python}")
    _print(f"Activate with: {activate_hint}")
    _print("Recommended next step: python scripts/verify.py")


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