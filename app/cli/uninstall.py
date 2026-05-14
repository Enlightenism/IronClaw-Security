from __future__ import annotations

import argparse
import json
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    get_integration,
    initialize_integration_registry,
    update_integration_status,
)


def _emit(payload: dict[str, Any], *, pretty: bool = True) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def build_uninstall_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw uninstall",
        description="Uninstall or disable an IronClaw integration.",
    )
    parser.add_argument("integration_id")
    parser.add_argument("--requested-by", default="cli")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON output.",
    )
    return parser


def run_uninstall_command(
    integration_id: str,
    *,
    requested_by: str | None = "cli",
    registry: IntegrationRegistry | None = None,
    compact: bool = False,
) -> tuple[int, dict[str, Any]]:
    active_registry = registry or initialize_integration_registry()

    record = get_integration(active_registry, integration_id)
    if record is None:
        raise KeyError(f"unknown integration_id: {integration_id}")

    status_before = record.status
    updated = update_integration_status(active_registry, integration_id, "disabled")

    payload = {
        "command": "uninstall",
        "integration_id": updated.integration_id,
        "slug": updated.slug,
        "uninstalled": status_before != "disabled",
        "status_before": status_before,
        "status_after": updated.status,
        "requested_by": requested_by,
        "completed_at": updated.updated_at,
    }
    _emit(payload, pretty=not compact)
    return 0, payload


def handle_uninstall_args(
    args: argparse.Namespace,
    *,
    registry: IntegrationRegistry | None = None,
) -> int:
    exit_code, _ = run_uninstall_command(
        args.integration_id,
        requested_by=args.requested_by,
        registry=registry,
        compact=args.compact,
    )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_uninstall_parser()
    args = parser.parse_args(argv)
    return handle_uninstall_args(args)


if __name__ == "__main__":
    raise SystemExit(main())
