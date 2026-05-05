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
    list_integrations,
)
from app.services.integration_verifier import (
    summarize_verification_result,
    verify_integration,
)


def _serialize_items(items: list[Any]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for item in items:
        if hasattr(item, "to_dict"):
            serialized.append(item.to_dict())
        elif isinstance(item, dict):
            serialized.append(dict(item))
        else:
            serialized.append(vars(item))
    return serialized


def _emit(payload: dict[str, Any], *, pretty: bool = True) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _build_registry() -> IntegrationRegistry:
    return initialize_integration_registry()


def _add_common_output_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )
    parser.add_argument(
        "--compact",
        action="store_true",
        help="Emit compact JSON output.",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw",
        description="IronClaw integration management CLI.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    list_parser = subparsers.add_parser("list", help="List available integrations.")
    list_parser.add_argument("--status", default=None)
    list_parser.add_argument("--platform", default=None)
    _add_common_output_arguments(list_parser)
    list_parser.set_defaults(handler=_handle_list)

    install_parser = subparsers.add_parser("install", help="Install an integration.")
    install_parser.add_argument("integration_id")
    install_parser.add_argument("--dry-run", action="store_true")
    install_parser.add_argument("--requested-by", default="cli")
    install_parser.add_argument("--install-target", default=None)
    _add_common_output_arguments(install_parser)
    install_parser.set_defaults(handler=_handle_install)

    verify_parser = subparsers.add_parser("verify", help="Verify an integration.")
    verify_parser.add_argument("integration_id")
    verify_parser.add_argument("--strict", action="store_true")
    verify_parser.add_argument("--requested-by", default="cli")
    _add_common_output_arguments(verify_parser)
    verify_parser.set_defaults(handler=_handle_verify)

    return parser


def _handle_list(args: argparse.Namespace, registry: IntegrationRegistry) -> int:
    items = list_integrations(
        registry,
        status=args.status,
        platform=args.platform,
    )
    payload = {
        "command": "list",
        "total": len(items),
        "items": _serialize_items(items),
    }
    _emit(payload, pretty=not args.compact)
    return 0


def _handle_install(args: argparse.Namespace, registry: IntegrationRegistry) -> int:
    result: IntegrationInstallResult = install_integration(
        registry,
        args.integration_id,
        dry_run=args.dry_run,
        requested_by=args.requested_by,
        install_target=args.install_target,
    )
    summary = summarize_install_result(result)
    payload = {
        "command": "install",
        **summary,
    }
    _emit(payload, pretty=not args.compact)
    return 0 if summary.get("installed", False) or args.dry_run else 1


def _handle_verify(args: argparse.Namespace, registry: IntegrationRegistry) -> int:
    result = verify_integration(
        registry,
        args.integration_id,
        strict=args.strict,
        requested_by=args.requested_by,
    )
    summary = summarize_verification_result(result)
    payload = {
        "command": "verify",
        **summary,
    }
    _emit(payload, pretty=not args.compact)
    return 0


def run_cli(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    registry = _build_registry()

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("unknown command")
        return 2

    try:
        return int(handler(args, registry))
    except KeyError as exc:
        _emit(
            {
                "error": "not_found",
                "detail": str(exc),
                "command": getattr(args, "command", None),
            },
            pretty=not getattr(args, "compact", False),
        )
        return 1
    except ValueError as exc:
        _emit(
            {
                "error": "invalid_request",
                "detail": str(exc),
                "command": getattr(args, "command", None),
            },
            pretty=not getattr(args, "compact", False),
        )
        return 1


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    raise SystemExit(main())