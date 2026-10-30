from __future__ import annotations

import argparse
import json
from typing import Any

from app.core.install_key_formats import RUNTIME_INSTALL_KEY_PROGRAMS, get_install_key_format_registry
from app.core.install_keys import get_install_key_registry
from app.core.unit_wallet import get_unit_wallet_registry
from app.services.install_key_handoff import (
    InstallKeyRedemption,
    InvalidInstallKeyClaimError,
    get_install_key_handoff_service,
)
from app.services.integration_installer import (
    IntegrationInstallResult,
    install_integration,
    summarize_install_result,
)
from app.services.integration_registry import (
    IntegrationRegistry,
    initialize_integration_registry,
)

_GENERIC_PLATFORM_KEY_PATTERNS = (
    "platform_api_key",
    "platform-api-key",
    "internal_platform_api_key",
    "internal-platform-api-key",
    "system_api_key",
    "system-api-key",
    "api_key",
    "api-key",
    "secret_key",
    "secret-key",
    "sk_live_",
    "sk_test_",
    "ghp_",
    "gho_",
    "github_pat_",
    "token_",
    "bearer ",
)


def _is_generic_platform_api_key(candidate: str | None) -> bool:
    if candidate is None:
        return False
    normalized = str(candidate).strip().lower()
    if not normalized:
        return False
    if any(normalized.startswith(pattern) for pattern in _GENERIC_PLATFORM_KEY_PATTERNS):
        return True
    if "platform" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized):
        return True
    if "system" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized):
        return True
    if "api" in normalized and "key" in normalized and normalized not in {"api_key"}:
        return True
    return False


def _infer_install_program(integration_id: str | None) -> str | None:
    if not integration_id or not integration_id.strip():
        return None
    format_registry = get_install_key_format_registry()
    program = format_registry.normalize_program(integration_id)
    return program if program in RUNTIME_INSTALL_KEY_PROGRAMS else None


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
    if _is_generic_platform_api_key(candidate):
        return None

    format_registry = get_install_key_format_registry()
    normalized_program = format_registry.normalize_program(expected_program) if expected_program else None
    if normalized_program is None:
        if candidate.startswith("ic_install_"):
            detected = format_registry.parse_program_from_key(candidate)
            if detected is not None:
                return candidate
        return None

    spec = format_registry.get_spec(normalized_program)
    if not spec.matches_key(candidate):
        return None
    return candidate


def _validate_paid_cli_install_claim(
    claim_token: str | None,
    *,
    integration_id: str | None = None,
) -> tuple[bool, dict[str, Any], str | None, InstallKeyRedemption | None]:
    expected_program = _infer_install_program(integration_id)

    if expected_program is None:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "unsupported runtime",
                "owner_key": None,
                "key_classification": "unsupported_runtime",
            },
            "unsupported install runtime",
            None,
        )

    try:
        redemption = get_install_key_handoff_service().redeem_claim(claim_token or "")
    except InvalidInstallKeyClaimError:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install claim is invalid, expired, or already redeemed",
                "owner_key": None,
                "key_classification": "invalid_install_claim",
            },
            "install claim is invalid, expired, or already redeemed",
            None,
        )

    format_registry = get_install_key_format_registry()
    normalized_owner_key = _normalize_owner_key(redemption.owner_key)
    normalized_program = format_registry.normalize_program(redemption.program)
    normalized_install_key = _normalize_install_key(
        redemption.install_key,
        expected_program=expected_program,
    )
    if normalized_owner_key is None or normalized_program != expected_program or not normalized_install_key:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install claim does not match the requested runtime",
                "owner_key": normalized_owner_key,
                "program": normalized_program,
                "expected_program": expected_program,
                "key_classification": "install_claim_mismatch",
            },
            "install claim does not match the requested runtime",
            None,
        )

    registry = get_install_key_registry()
    record = registry.authenticate_install_key(normalized_install_key)
    if record is None or record.key_id != redemption.key_id or _normalize_owner_key(record.owner_key) != normalized_owner_key or format_registry.normalize_program(record.program) != expected_program:
        return (
            False,
            {
                "install_key_required": True,
                "install_key_valid": False,
                "reason": "install claim does not match an active install key",
                "owner_key": normalized_owner_key,
                "key_classification": "install_claim_mismatch",
            },
            "install claim does not match an active install key",
            None,
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
            None,
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
        redemption,
    )


def build_install_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ironclaw install",
        description="Install an IronClaw integration with a one-time paid customer install claim.",
    )
    parser.add_argument("integration_id")
    parser.add_argument(
        "--install-claim",
        dest="claim_token",
        default=None,
        help="One-time install claim issued after payment.",
    )
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
    claim_token: str | None = None,
    registry: IntegrationRegistry | None = None,
    compact: bool = False,
) -> tuple[int, dict[str, Any]]:
    valid, validation_payload, validation_error, redemption = _validate_paid_cli_install_claim(
        claim_token,
        integration_id=integration_id,
    )
    if not valid or redemption is None:
        payload = {
            "command": "install",
            "status": "failed",
            "message": validation_error or "install claim is unavailable",
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
        install_key=redemption.install_key,
        owner_key=redemption.owner_key,
        extra_metadata={
            "install_key_validated": True,
            "owner_key": redemption.owner_key,
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
        claim_token=getattr(args, "claim_token", None),
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
