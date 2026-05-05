from __future__ import annotations

import argparse
import json
from typing import Any

from app.services.integration_installer import (
    IntegrationInstallResult,
    install_integration,
    summarize_install_result,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    initialize_integration_registry,
)


def _emit(payload: dict[str, Any], *, pretty: bool = True) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def build_install_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw install",
        description="Install an IronClaw integration.",
    )
    parser.add_argument("integration_id")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--requested-by", default="cli")
    parser.add_argument("--install-target", default=None)
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON output.",
    )
    return parser


def run_install_command(
    integration_id: str,
    *,
    dry_run: bool = False,
    requested_by: str | None = "cli",
    install_target: str | None = None,
    registry: IntegrationRegistry | None = None,
    compact: bool = False,
) -> tuple[int, dict[str, Any]]:
    active_registry = registry or initialize_integration_registry()

    result: IntegrationInstallResult = install_integration(
        active_registry,
        integration_id,
        dry_run=dry_run,
        requested_by=requested_by,
        install_target=install_target,
    )
    summary = summarize_install_result(result)
    payload = {
        "command": "install",
        **summary,
    }
    _emit(payload, pretty=not compact)
    exit_code = 0 if summary.get("installed", False) or dry_run else 1
    return exit_code, payload


def handle_install_args(
    args: argparse.Namespace,
    *,
    registry: IntegrationRegistry | None = None,
) -> int:
    exit_code, _ = run_install_command(
        args.integration_id,
        dry_run=args.dry_run,
        requested_by=args.requested_by,
        install_target=args.install_target,
        registry=registry,
        compact=args.compact,
    )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_install_parser()
    args = parser.parse_args(argv)
    return handle_install_args(args)


if __name__ == "__main__":
    raise SystemExit(main())