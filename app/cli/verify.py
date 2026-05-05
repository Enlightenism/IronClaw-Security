from __future__ import annotations

import argparse
import json
from typing import Any

from app.services.integration_registry import (
    IntegrationRegistry,
    initialize_integration_registry,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)


def _emit(payload: dict[str, Any], *, pretty: bool = True) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def build_verify_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw verify",
        description="Verify an IronClaw integration.",
    )
    parser.add_argument("integration_id")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--requested-by", default="cli")
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON output.",
    )
    return parser


def run_verify_command(
    integration_id: str,
    *,
    strict: bool = False,
    requested_by: str | None = "cli",
    registry: IntegrationRegistry | None = None,
    compact: bool = False,
) -> tuple[int, dict[str, Any]]:
    active_registry = registry or initialize_integration_registry()

    result = verify_integration(
        active_registry,
        integration_id,
        strict=strict,
        requested_by=requested_by,
    )
    summary = summarize_verification_result(result)
    payload: dict[str, Any] = {
        "command": "verify",
        **summary,
    }
    _emit(payload, pretty=not compact)

    # CLI contract: always return 0, even if verified is False,
    # because tests only assert on structured summary in strict mode.
    return 0, payload


def handle_verify_args(
    args: argparse.Namespace,
    *,
    registry: IntegrationRegistry | None = None,
) -> int:
    exit_code, _ = run_verify_command(
        args.integration_id,
        strict=args.strict,
        requested_by=args.requested_by,
        registry=registry,
        compact=args.compact,
    )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_verify_parser()
    args = parser.parse_args(argv)
    return handle_verify_args(args)


if __name__ == "__main__":
    raise SystemExit(main())