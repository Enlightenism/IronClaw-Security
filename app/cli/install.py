from __future__ import annotations

import argparse
import json
from typing import Any

from app.core.install_keys import get_install_key_registry
from app.core.unit_wallet import get_unit_wallet_registry
from app.services.integration_installer import (
    IntegrationInstallResult,
    install_integration,
    summarize_install_result,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    initialize_integration_registry,
)

_VALID_INSTALL_KEY_PREFIXES = ("ic_install_openclaw_", "ic_install_claude_code_")


def _infer_install_program(integration_id: str | None) -> str | None:
    normalized = (integration_id or "").strip().lower()
    if not normalized:
        return None
    if normalized in {"openclaw", "openclaw-agent", "openclaw-cli"}:
        return "openclaw"
    if normalized in {"claude-code", "claude_code", "claude", "claude-code-cli"}:
        return "claude_code"
    return None


def _emit(payload: dict[str, Any], *, pretty: bool = True) -> None:
    if pretty:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return
    print(json.dumps(payload, separators=(",", ":"), sort_keys=True))


def _normalize_owner_key(owner_key: str | None) -> str | None:
    if owner_key is None:
        return None
    candidate = str(owner_key).strip().lower()
    return candidate or None


def _normalize_install_key(raw_key: str | None, *, expected_program: str | None = None) -> str | None:
    if raw_key is None:
        return None
    candidate = str(raw_key).strip()
    if not candidate:
        return None

    expected_prefixes: tuple[str, ...]
    if expected_program is None:
        expected_prefixes = _VALID_INSTALL_KEY_PREFIXES
    else:
        normalized_program = str(expected_program).strip().lower()
        if normalized_program == "openclaw":
            expected_prefixes = ("ic_install_openclaw_",)
        elif normalized_program == "claude_code":
            expected_prefixes = ("ic_install_claude_code_",)
        else:
            expected_prefixes = _VALID_INSTALL_KEY_PREFIXES

    if not candidate.startswith(expected_prefixes):
        return None
    return candidate


def _validate_paid_cli_install_key(
    install_key: str | None,
    *,
    owner_key: str | None,
    integration_id: str | None = None,
) -> tuple[bool, dict[str, Any], str | None]:
    expected_program = _infer_install_program(integration_id)
    normalized_install_key = _normalize_install_key(install_key, expected_program=expected_program)
    normalized_owner_key = _normalize_owner_key(owner_key)

    if not normalized_install_key:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "owner_key": normalized_owner_key,
                "key_classification": "system_api_key_or_generic_token",
            },
            "install key unavailable until payment is complete",
        )

    registry = get_install_key_registry()
    record = registry.authenticate_install_key(normalized_install_key)
    if record is None:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "owner_key": normalized_owner_key,
                "key_classification": "unrecognized_or_inactive",
            },
            "install key unavailable until payment is complete",
        )

    if record.payment_status != "paid" or record.entitlements_status != "active" or not record.issued_after_payment:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "owner_key": normalized_owner_key,
                "payment_status": record.payment_status,
                "entitlements_status": record.entitlements_status,
                "issued_after_payment": record.issued_after_payment,
            },
            "install key unavailable until payment is complete",
        )

    if expected_program and record.program != expected_program:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "owner_key": normalized_owner_key,
                "program": record.program,
                "expected_program": expected_program,
            },
            "install key unavailable until payment is complete",
        )

    if normalized_owner_key and record.owner_key != normalized_owner_key:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install key unavailable until payment is complete",
                "owner_key": normalized_owner_key,
                "record_owner_key": record.owner_key,
            },
            "install key unavailable until payment is complete",
        )

    wallet_registry = get_unit_wallet_registry()
    wallet = wallet_registry.get_wallet(record.owner_key)
    wallet_balance = wallet.balance_units if wallet is not None else 0
    usage_summary = (
        wallet_registry.get_key_usage_summary(record.owner_key, key_id=record.key_id)
        if wallet is not None
        else {
            "owner_key": record.owner_key,
            "wallet_balance_units": 0,
            "total_consumed_units": 0,
            "total_blocked_attacks": 0,
            "install_key_usage": {},
        }
    )

    return (
        True,
        {
            "install_key_required": True,
            "install_key_valid": True,
            "key_id": record.key_id,
            "program": record.program,
            "owner_key": record.owner_key,
            "payment_status": record.payment_status,
            "entitlements_status": record.entitlements_status,
            "units_remaining": wallet_balance,
            "usage": {
                "key_id": record.key_id,
                "program": record.program,
                "units_used": int(record.units_consumed),
                "units_remaining": wallet_balance,
                "blocked_attacks": int(usage_summary.get("total_blocked_attacks", 0)),
            },
        },
        None,
    )


def build_install_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw install",
        description="Install an IronClaw integration with a valid paid customer install key.",
    )
    parser.add_argument("integration_id")
    parser.add_argument("--key", dest="key", default=None, help="Paid customer install key required for installation.")
    parser.add_argument("--owner-key", dest="owner_key", default=None, help="Owner or customer identifier tied to the install key.")
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
    key: str | None = None,
    owner_key: str | None = None,
    registry: IntegrationRegistry | None = None,
    compact: bool = False,
) -> tuple[int, dict[str, Any]]:
    valid, validation_payload, validation_error = _validate_paid_cli_install_key(key, owner_key=owner_key, integration_id=integration_id)
    if not valid:
        payload = {
            "command": "install",
            "status": "failed",
            "message": validation_error or "install key unavailable until payment is complete",
            **validation_payload,
        }
        _emit(payload, pretty=not compact)
        return 1, payload

    active_registry = registry or initialize_integration_registry()
    result: IntegrationInstallResult = install_integration(
        active_registry,
        integration_id,
        dry_run=dry_run,
        requested_by=requested_by,
        install_target=install_target,
        install_key=key,
        owner_key=owner_key,
        extra_metadata={
            "install_key_validated": True,
            "owner_key": owner_key,
            "key_id": validation_payload.get("key_id"),
        },
    )
    summary = summarize_install_result(result)
    payload = {
        "command": "install",
        "status": "ok" if summary.get("installed", False) or dry_run else "failed",
        "message": ("install completed successfully" if summary.get("installed", False) or dry_run else "install key unavailable until payment is complete"),
        **summary,
        "usage": validation_payload.get("usage", {}),
        "install_key": None,
        "owner_key": validation_payload.get("owner_key"),
    }
    if not payload["usage"]:
        payload["usage"] = {
            "key_id": validation_payload.get("key_id"),
            "units_remaining": validation_payload.get("units_remaining", 0),
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
        key=getattr(args, "key", None),
        owner_key=getattr(args, "owner_key", None),
        registry=registry,
        compact=getattr(args, "compact", False),
    )
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = build_install_parser()
    args = parser.parse_args(argv)
    return handle_install_args(args)


if __name__ == "__main__":
    raise SystemExit(main())
