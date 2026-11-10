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
from ironclaw_installer import IronClawInstallerError, save_install_key

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
    candidate = integration_id.strip().lower()
    if candidate.startswith("integration-"):
        candidate = candidate[len("integration-") :]
    program = format_registry.normalize_program(candidate)
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
    key_usage = wallet.install_key_usage.get(record.key_id) if wallet is not None else None
    units_used = max(int(record.units_consumed), int(getattr(key_usage, "total_consumed_units", 0) or 0))

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
                "units_used": units_used,
                "units_remaining": wallet_balance,
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
    active_registry = registry or initialize_integration_registry()
    if dry_run:
        dry_result: IntegrationInstallResult = install_integration(
            active_registry,
            integration_id,
            dry_run=True,
            requested_by=requested_by,
            install_target=install_target,
        )
        dry_payload = {
            "command": "install",
            **summarize_install_result(dry_result),
            "dry_run": True,
            "claim_consumed": False,
        }
        _emit(dry_payload, pretty=not compact)
        return 0, dry_payload

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

    try:
        saved = save_install_key(
            program=str(validation_payload["program"]),
            install_key=redemption.install_key,
        )
    except IronClawInstallerError as exc:
        payload = {
            "command": "install",
            "status": "failed",
            "message": str(exc),
            "usage": validation_payload.get("usage", {}),
            "install_key": None,
            "owner_key": validation_payload.get("owner_key"),
        }
        _emit(payload, pretty=not compact)
        return 1, payload

    result: IntegrationInstallResult = install_integration(
        active_registry,
        integration_id,
        dry_run=False,
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
    installed = bool(summary.get("installed", False))
    payload = {
        "command": "install",
        "status": "ok" if installed else "failed",
        "message": ("install completed successfully" if installed else "integration registry install did not complete"),
        **summary,
        "config_file": str(saved.config_file),
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
    exit_code = 0 if installed else 1
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
