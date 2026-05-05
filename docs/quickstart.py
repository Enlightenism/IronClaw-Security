from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Final

PROJECT_ROOT: Final[Path] = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ironclawclient import IronClawClient, IronClawClientError


DEFAULT_BASE_URL: Final[str] = os.getenv("IRONCLAW_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
DEFAULT_BACKUP_TARGET: Final[str] = os.getenv("IRONCLAW_BACKUP_TARGET_NAME", "primary")
DEFAULT_RESTORE_TARGET: Final[str] = os.getenv("IRONCLAW_RESTORE_TARGET_NAME", DEFAULT_BACKUP_TARGET)


def _pretty_print(title: str, payload: Any) -> None:
    print(f"\n=== {title} ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True))


def _print_step(message: str) -> None:
    print(f"[quickstart] {message}")


def _run_health_demo(client: IronClawClient) -> None:
    _print_step("Checking health surfaces")
    _pretty_print("health", client.health())
    _pretty_print("health_liveness", client.health_liveness())
    _pretty_print("health_readiness", client.health_readiness())
    _pretty_print("system_status", client.system_status())


def _run_ui_demo(client: IronClawClient) -> None:
    _print_step("Checking UI/runtime surfaces")
    _pretty_print("ui_manifest", client.ui_manifest())
    _pretty_print("ui_status", client.ui_status())
    _pretty_print("ui_runtime_status", client.ui_runtime_status())


def _run_backup_demo(client: IronClawClient, target_name: str) -> None:
    _print_step(f"Checking backup surfaces for target={target_name!r}")
    _pretty_print("backup_status", client.backup_status())
    _pretty_print("backup_targets", client.backup_targets())

    try:
        _pretty_print("backup_snapshot", client.backup_snapshot(target_name))
    except IronClawClientError as exc:
        _print_step(f"backup_snapshot unavailable: {exc}")

    try:
        _pretty_print("backup_export", client.backup_export(target_name))
    except IronClawClientError as exc:
        _print_step(f"backup_export unavailable: {exc}")

    try:
        _pretty_print("backup_rotate", client.backup_rotate(target_name))
    except IronClawClientError as exc:
        _print_step(f"backup_rotate unavailable: {exc}")


def _run_restore_demo(client: IronClawClient, target_name: str, *, dry_run: bool) -> None:
    _print_step(f"Checking restore surfaces for target={target_name!r}, dry_run={dry_run}")
    _pretty_print("restore_status", client.restore_status())
    _pretty_print("restore_targets", client.restore_targets())

    try:
        _pretty_print("restore_validate", client.restore_validate(target_name))
    except IronClawClientError as exc:
        _print_step(f"restore_validate unavailable: {exc}")

    try:
        _pretty_print("restore_run", client.restore_run(target_name, dry_run=dry_run))
    except IronClawClientError as exc:
        _print_step(f"restore_run unavailable: {exc}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="IronClaw quickstart runner for health, UI, backup, and restore examples."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"Base URL for the IronClaw API, default: {DEFAULT_BASE_URL}",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Client timeout in seconds.",
    )
    parser.add_argument(
        "--backup-target",
        default=DEFAULT_BACKUP_TARGET,
        help=f"Backup target name, default: {DEFAULT_BACKUP_TARGET}",
    )
    parser.add_argument(
        "--restore-target",
        default=DEFAULT_RESTORE_TARGET,
        help=f"Restore target name, default: {DEFAULT_RESTORE_TARGET}",
    )
    parser.add_argument(
        "--skip-ui",
        action="store_true",
        help="Skip UI/runtime endpoint examples.",
    )
    parser.add_argument(
        "--skip-backup",
        action="store_true",
        help="Skip backup endpoint examples.",
    )
    parser.add_argument(
        "--skip-restore",
        action="store_true",
        help="Skip restore endpoint examples.",
    )
    parser.add_argument(
        "--execute-restore",
        action="store_true",
        help="Allow restore execution example with dry_run=False.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.timeout <= 0:
        parser.error("--timeout must be greater than 0")

    _print_step(f"Connecting to IronClaw at {args.base_url}")

    try:
        with IronClawClient(base_url=args.base_url, timeout=args.timeout) as client:
            _run_health_demo(client)

            if not args.skip_ui:
                _run_ui_demo(client)

            if not args.skip_backup:
                _run_backup_demo(client, args.backup_target)

            if not args.skip_restore:
                _run_restore_demo(
                    client,
                    args.restore_target,
                    dry_run=not args.execute_restore,
                )

    except IronClawClientError as exc:
        print(f"[quickstart] failed: {exc}", file=sys.stderr)
        return 1

    _print_step("Quickstart completed successfully")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))