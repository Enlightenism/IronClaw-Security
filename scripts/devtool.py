from __future__ import annotations

import argparse
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = ROOT / "scripts"


COMMAND_MAP = {
    "install": SCRIPTS_DIR / "install.py",
    "update": SCRIPTS_DIR / "update.py",
    "verify": SCRIPTS_DIR / "verify.py",
    "smoke": SCRIPTS_DIR / "smoke_test.py",
    "deploy-check": SCRIPTS_DIR / "deployment_readiness.py",
    "quality-gate": SCRIPTS_DIR / "securityqualitygate.py",
    "route-inventory": SCRIPTS_DIR / "route_inventory.py",
}


def _run_script(script_path: Path) -> int:
    if not script_path.exists():
        print(f"ERROR: missing script: {script_path.relative_to(ROOT)}")
        return 1

    completed = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(ROOT),
        check=False,
    )
    return int(completed.returncode)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="devtool",
        description="IronClaw developer convenience wrapper",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    for name in COMMAND_MAP:
        subparsers.add_parser(name, help=f"Run {name}")

    subparsers.add_parser(
        "all",
        help="Run install, verify, smoke, deployment readiness, and quality gate in sequence",
    )
    return parser


def _run_all() -> int:
    ordered_commands = [
        "install",
        "verify",
        "smoke",
        "deploy-check",
        "quality-gate",
    ]

    for name in ordered_commands:
        print(f"==> Running {name}")
        returncode = _run_script(COMMAND_MAP[name])
        if returncode != 0:
            print(f"ERROR: {name} failed with exit code {returncode}")
            return returncode

    print("All devtool commands completed successfully")
    return 0


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "all":
        raise SystemExit(_run_all())

    script_path = COMMAND_MAP[args.command]
    raise SystemExit(_run_script(script_path))


if __name__ == "__main__":
    main()
