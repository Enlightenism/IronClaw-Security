from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from app.cli.config import CLIConfig, load_cli_config
from app.cli.install import handle_install_args
from app.cli.output import (
    format_error,
    format_json_payload,
    format_scan_result,
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
from ironclaw_sdk.client import IronclawClient
from ironclaw_sdk.exceptions import (
    IronclawAPIError,
    IronclawAuthError,
    IronclawRetryExhausted,
    IronclawTimeoutError,
)
from ironclaw_sdk.models import ScanRequest


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
        help="Emit compact JSON output (implies --json).",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw",
        description="IronClaw Security CLI — integration management and scan operations.",
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
    install_parser.add_argument(
        "--install-claim",
        dest="claim_token",
        default=None,
        help="One-time install claim to redeem and save for a paid install (required unless --dry-run).",
    )
    _add_common_output_arguments(install_parser)
    install_parser.set_defaults(handler=_handle_install)

    verify_parser = subparsers.add_parser("verify", help="Verify an integration.")
    verify_parser.add_argument("integration_id")
    verify_parser.add_argument("--strict", action="store_true")
    verify_parser.add_argument("--requested-by", default="cli")
    _add_common_output_arguments(verify_parser)
    verify_parser.set_defaults(handler=_handle_verify)

    scan_parser = subparsers.add_parser("scan", help="Scan a target via the IronClaw API.")
    scan_parser.add_argument("target_value", help="Value to scan.")
    scan_parser.add_argument(
        "--type",
        dest="target_type",
        default="text",
        choices=["prompt", "github_repo", "skill", "archive", "url", "text", "local_path"],
        help="Target type (default: text).",
    )
    scan_parser.add_argument("--client-id", default=None, help="Optional client identifier.")
    _add_common_output_arguments(scan_parser)
    scan_parser.set_defaults(handler=_handle_scan)

    auth_check_parser = subparsers.add_parser("auth-check", help="Verify API key is accepted by the server.")
    _add_common_output_arguments(auth_check_parser)
    auth_check_parser.set_defaults(handler=_handle_auth_check)

    version_parser = subparsers.add_parser("version", help="Print IronClaw SDK version.")
    _add_common_output_arguments(version_parser)
    version_parser.set_defaults(handler=_handle_version)

    return parser


def _use_json(args: argparse.Namespace) -> bool:
    return getattr(args, "json", False) or getattr(args, "compact", False)


def _handle_list(args: argparse.Namespace, registry: IntegrationRegistry, _config: CLIConfig) -> int:
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
    format_json_payload(payload, compact=args.compact)
    return 0


def _handle_install(args: argparse.Namespace, registry: IntegrationRegistry, _config: CLIConfig) -> int:
    return handle_install_args(args, registry=registry)


def _handle_verify(args: argparse.Namespace, registry: IntegrationRegistry, _config: CLIConfig) -> int:
    result = verify_integration(
        registry,
        args.integration_id,
        strict=args.strict,
        requested_by=args.requested_by,
    )
    summary = summarize_verification_result(result)
    payload = {"command": "verify", **summary}
    format_json_payload(payload, compact=args.compact)
    return 0


def _handle_scan(args: argparse.Namespace, _registry: IntegrationRegistry, config: CLIConfig) -> int:
    client = IronclawClient(
        api_key=config.api_key,
        base_url=config.base_url,
        connect_timeout=config.timeout_seconds,
        read_timeout=config.timeout_seconds,
    )
    request = ScanRequest(
        target_type=args.target_type,
        target_value=args.target_value,
        client_id=args.client_id,
    )
    try:
        response = client.scan(request)
    except IronclawAuthError as exc:
        if _use_json(args):
            _emit({"error": "auth_error", "detail": str(exc), "command": "scan"}, pretty=not args.compact)
        else:
            format_error("auth_error", str(exc), command="scan")
        return 2
    except IronclawTimeoutError as exc:
        if _use_json(args):
            _emit({"error": "timeout", "detail": str(exc), "command": "scan"}, pretty=not args.compact)
        else:
            format_error("timeout", str(exc), command="scan")
        return 3
    except IronclawRetryExhausted as exc:
        if _use_json(args):
            _emit({"error": "retry_exhausted", "detail": str(exc), "command": "scan"}, pretty=not args.compact)
        else:
            format_error("retry_exhausted", str(exc), command="scan")
        return 3
    except IronclawAPIError as exc:
        if _use_json(args):
            _emit({"error": "api_error", "detail": str(exc), "command": "scan"}, pretty=not args.compact)
        else:
            format_error("api_error", str(exc), command="scan")
        return 1

    if _use_json(args):
        payload = response.model_dump()
        payload["command"] = "scan"
        format_json_payload(payload, compact=args.compact)
    else:
        format_scan_result(response, compact=args.compact)

    return 0 if response.verdict == "allow" else 1


def _handle_auth_check(args: argparse.Namespace, _registry: IntegrationRegistry, config: CLIConfig) -> int:
    client = IronclawClient(
        api_key=config.api_key,
        base_url=config.base_url,
        connect_timeout=config.timeout_seconds,
        read_timeout=config.timeout_seconds,
    )
    try:
        result = client.health()
        payload = {"command": "auth-check", "status": "ok", "detail": result}
        format_json_payload(payload, compact=args.compact)
        return 0
    except IronclawAuthError as exc:
        if _use_json(args):
            _emit({"command": "auth-check", "status": "rejected", "detail": str(exc)}, pretty=not args.compact)
        else:
            format_error("auth_rejected", str(exc), command="auth-check")
        return 2
    except (IronclawTimeoutError, IronclawRetryExhausted, IronclawAPIError) as exc:
        if _use_json(args):
            _emit({"command": "auth-check", "status": "unreachable", "detail": str(exc)}, pretty=not args.compact)
        else:
            format_error("unreachable", str(exc), command="auth-check")
        return 3


def _handle_version(args: argparse.Namespace, _registry: IntegrationRegistry, _config: CLIConfig) -> int:
    from ironclaw_sdk import __version__

    payload = {"command": "version", "version": __version__}
    format_json_payload(payload, compact=args.compact)
    return 0


def run_cli(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    registry = _build_registry()

    try:
        config = load_cli_config()
    except OSError as exc:
        if _use_json(args):
            _emit(
                {
                    "error": "configuration_error",
                    "detail": str(exc),
                    "command": getattr(args, "command", None),
                },
                pretty=not getattr(args, "compact", False),
            )
        else:
            format_error("configuration_error", str(exc), command=getattr(args, "command", None))
        return 2

    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("unknown command")
        return 2

    try:
        return int(handler(args, registry, config))
    except KeyError as exc:
        if _use_json(args):
            _emit({"error": "not_found", "detail": str(exc), "command": getattr(args, "command", None)}, pretty=not getattr(args, "compact", False))
        else:
            format_error("not_found", str(exc), command=getattr(args, "command", None))
        return 1
    except ValueError as exc:
        if _use_json(args):
            _emit({"error": "invalid_request", "detail": str(exc), "command": getattr(args, "command", None)}, pretty=not getattr(args, "compact", False))
        else:
            format_error("invalid_request", str(exc), command=getattr(args, "command", None))
        return 1


def main() -> int:
    return run_cli()


if __name__ == "__main__":
    sys.exit(main())
