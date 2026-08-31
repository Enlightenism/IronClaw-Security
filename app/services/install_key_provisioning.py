from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
import logging
from typing import Any, Literal

from app.core.billing import get_billing_registry, resolve_billing_owner
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import InstallKeyRecord, get_install_key_registry
from app.core.logging import get_logger
from app.core.unit_wallet import get_unit_wallet_registry

_logger: logging.Logger = get_logger("ironclaw.install_key_provisioning")

ProgramCode = Literal[
    "openclaw",
    "claude_code",
    "cursor",
    "goose",
    "gemini_cli",
    "copilot",
    "hermes",
    "security_guardian",
]
_VALID_PROGRAMS: tuple[ProgramCode, ...] = tuple(InstallKeyFormatRegistry.list_programs())


@dataclass(frozen=True, slots=True)
class InstallKeyIssued:
    """Single-use issuance envelope for install key delivery.

    The raw secret is intentionally exposed only once here. After delivery, the
    authoritative record should be treated as masked-only.
    """

    record: InstallKeyRecord
    raw_key: str = ""
    issued_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str = "purchase"
    wallet_owner: str = ""
    telemetry: dict[str, Any] = field(default_factory=dict)

    def public_view(self) -> dict[str, Any]:
        return {
            "key_id": self.record.key_id,
            "owner_key": self.record.owner_key,
            "subscription_id": self.record.subscription_id,
            "program": self.record.program,
            "masked_key": self.record.masked_key,
            "label": self.record.label,
            "active": self.record.active,
            "units_consumed": self.record.units_consumed,
            "created_at": self.record.created_at.isoformat(),
            "last_used_at": self.record.last_used_at.isoformat() if self.record.last_used_at else None,
            "metadata": dict(self.record.metadata),
        }

    def delivery_payload(self) -> dict[str, Any]:
        payload = self.public_view()
        if self.raw_key:
            payload["raw_key"] = self.raw_key
        return payload


class InstallKeyProvisioningService:
    """Canonical lifecycle service for install-key creation and wallet binding.

    This is the single source of truth for:
    - payment/subscription entitlement checks
    - purchaser identity resolution
    - install key generation
    - wallet creation if missing
    - usage telemetry metadata
    - one-time raw-key handling
    """

    def __init__(
        self,
        *,
        install_key_registry: Any | None = None,
        wallet_registry: Any | None = None,
        billing_registry: Any | None = None,
    ) -> None:
        self._install_key_registry = install_key_registry or get_install_key_registry()
        self._wallet_registry = wallet_registry or get_unit_wallet_registry()
        self._billing_registry = billing_registry or get_billing_registry()

    @staticmethod
    def _normalize_owner_key(owner_key: str) -> str:
        if owner_key is None:
            raise ValueError("owner_key is required")
        normalized = str(owner_key).strip().lower()
        if not normalized:
            raise ValueError("owner_key cannot be blank")
        return normalized

    @staticmethod
    def _normalise_program(program: str) -> ProgramCode:
        canonical = InstallKeyFormatRegistry.normalize_program(program)
        if canonical is None:
            raise ValueError(f"Unsupported install key program: {program!r}. Allowed: {list(_VALID_PROGRAMS)}")
        return canonical

    @staticmethod
    def _is_successful_payment_status(value: str | None) -> bool:
        return str(value or "").strip().lower() == "paid"

    @staticmethod
    def _has_valid_paid_entitlement(record: InstallKeyRecord) -> bool:
        return bool(getattr(record, "active", False)) and str(getattr(record, "payment_status", "")).strip().lower() == "paid" and str(getattr(record, "entitlements_status", "")).strip().lower() == "active" and bool(getattr(record, "issued_after_payment", False))

    def resolve_owner_key(
        self,
        *,
        auth_ctx: Any | None = None,
        buyer_email: str | None = None,
        org_id: str | None = None,
    ) -> str:
        """Resolve the canonical wallet/owner identity for the purchaser.

        This mirrors the repo's single source of truth in app.core.billing.resolve_billing_owner
        and explicitly rejects generic API-key / auth-token ownership fallbacks.
        """
        if auth_ctx is not None:
            key_type = str(getattr(auth_ctx, "key_type", "") or "").strip().lower()
            if key_type in {"api_key", "system", "generic", "internal", "service", "auth_token"}:
                raise ValueError("System API keys and generic auth tokens are not valid install-key owners.")

        if auth_ctx is not None:
            resolved = resolve_billing_owner(auth_ctx, (buyer_email or "").strip())
            if resolved:
                return self._normalize_owner_key(resolved)

        if org_id:
            return self._normalize_owner_key(f"ic_org_{str(org_id).strip()}")

        if buyer_email:
            return self._normalize_owner_key(buyer_email)

        raise ValueError("Could not resolve purchaser identity: provide auth_ctx, buyer_email, or org_id")

    def ensure_entitled_owner(self, owner_key: str) -> str:
        normalized = self._normalize_owner_key(owner_key)
        if not self._billing_registry.has_active_subscription(normalized):
            raise ValueError(f"Cannot provision install key: no active subscription for owner {normalized!r}")
        return normalized

    def ensure_wallet(self, owner_key: str, *, metadata: dict[str, Any] | None = None) -> Any:
        normalized = self._normalize_owner_key(owner_key)
        return self._wallet_registry.get_or_create_wallet(normalized, metadata=metadata or {})

    def _find_reusable_key(self, owner_key: str, program: ProgramCode) -> InstallKeyRecord | None:
        for record in self._install_key_registry.get_keys_for_owner(owner_key):
            if str(getattr(record, "program", "")).strip().lower() != program:
                continue
            if not self._has_valid_paid_entitlement(record):
                continue
            if str(getattr(record, "owner_key", "")).strip().lower() != owner_key:
                continue
            return record
        return None

    def provision_for_program(
        self,
        *,
        owner_key: str,
        subscription_id: str,
        program: str,
        source: str = "purchase",
        label: str = "auto-provisioned",
        metadata: dict[str, Any] | None = None,
        payment_status: str | None = "paid",
        entitlements_status: str | None = "active",
        issued_after_payment: bool = True,
        checkout_session_id: str | None = None,
        purchase_reference: str | None = None,
        customer_id: str | None = None,
        org_id: str | None = None,
        payment_confirmed: bool | None = None,
    ) -> InstallKeyIssued:
        normalized_owner = self.ensure_entitled_owner(owner_key)
        canonical_program = self._normalise_program(program)

        normalized_payment_status = str(payment_status or "").strip().lower()
        normalized_entitlements_status = str(entitlements_status or "").strip().lower()
        if payment_confirmed is not None:
            confirmed = bool(payment_confirmed)
        else:
            confirmed = normalized_payment_status == "paid" and normalized_entitlements_status == "active" and bool(issued_after_payment)
        if not confirmed:
            raise ValueError("Install keys can only be provisioned after successful payment confirmation and an active paid entitlement.")
        if normalized_payment_status != "paid":
            raise ValueError("Install keys can only be provisioned after successful payment confirmation.")
        if normalized_entitlements_status != "active":
            raise ValueError("Install keys require an active paid entitlement before issuance.")
        if not bool(issued_after_payment):
            raise ValueError("Install keys must be issued only after successful payment confirmation.")

        existing = self._find_reusable_key(normalized_owner, canonical_program)
        if existing is not None:
            _logger.info(
                "install_key_reused",
                extra={
                    "owner_key": normalized_owner,
                    "program": canonical_program,
                    "subscription_id": subscription_id,
                    "key_id": existing.key_id,
                    "source": source,
                },
            )
            return InstallKeyIssued(
                record=existing,
                raw_key="",
                source=source,
                wallet_owner=normalized_owner,
                telemetry={
                    "event": "install_key.reused",
                    "owner_key": normalized_owner,
                    "program": canonical_program,
                    "subscription_id": subscription_id,
                    "key_id": existing.key_id,
                    "source": source,
                },
            )

        self.ensure_wallet(
            normalized_owner,
            metadata={
                "install_key_source": source,
                "program": canonical_program,
                "subscription_id": subscription_id,
                "last_operation": "ensure_wallet",
            },
        )

        effective_purchase_reference = purchase_reference or checkout_session_id or subscription_id
        effective_checkout_session_id = checkout_session_id or purchase_reference or subscription_id
        effective_metadata: dict[str, Any] = {
            "source": source,
            "subscription_id": subscription_id,
            "wallet_owner": normalized_owner,
            "customer_id": customer_id,
            "org_id": org_id,
            "program": canonical_program,
            "payment_status": "paid",
            "entitlements_status": "active",
            "issued_after_payment": True,
            "purchase_reference": effective_purchase_reference,
            "checkout_session_id": effective_checkout_session_id,
            "auto_provisioned": True,
            "telemetry": {
                "event": "install_key.issued",
                "program": canonical_program,
                "owner_key": normalized_owner,
                "subscription_id": subscription_id,
                "source": source,
            },
        }
        if metadata:
            effective_metadata.update(metadata)
        effective_metadata["payment_status"] = "paid"
        effective_metadata["entitlements_status"] = "active"
        effective_metadata["issued_after_payment"] = True

        record = self._install_key_registry.generate_for_paid_customer(
            owner_key=normalized_owner,
            subscription_id=subscription_id,
            program=canonical_program,
            org_id=org_id,
            customer_id=customer_id,
            payment_status=effective_metadata.get("payment_status", "paid"),
            entitlements_status=effective_metadata.get("entitlements_status", "active"),
            issued_after_payment=bool(effective_metadata.get("issued_after_payment", True)),
            purchase_reference=effective_metadata.get("purchase_reference"),
            checkout_session_id=effective_metadata.get("checkout_session_id"),
            label=label,
            metadata=effective_metadata,
        )

        issued = InstallKeyIssued(
            record=record,
            raw_key=record.raw_key,
            source=source,
            wallet_owner=normalized_owner,
            telemetry={
                "event": "install_key.issued",
                "owner_key": normalized_owner,
                "program": canonical_program,
                "subscription_id": subscription_id,
                "key_id": record.key_id,
                "source": source,
                "masked_key": record.masked_key,
            },
        )

        _logger.info(
            "install_key_provisioned",
            extra={
                "owner_key": normalized_owner,
                "program": canonical_program,
                "subscription_id": subscription_id,
                "key_id": record.key_id,
                "masked_key": record.masked_key,
                "source": source,
            },
        )
        return issued

    def provision_for_purchase(
        self,
        *,
        owner_key: str | None = None,
        subscription_id: str,
        customer_id: str | None = None,
        buyer_email: str | None = None,
        org_id: str | None = None,
        auth_ctx: Any | None = None,
        source: str = "purchase",
        metadata: dict[str, Any] | None = None,
        payment_status: str | None = "paid",
        entitlements_status: str | None = "active",
        issued_after_payment: bool = True,
        checkout_session_id: str | None = None,
        purchase_reference: str | None = None,
        payment_confirmed: bool | None = None,
    ) -> dict[str, InstallKeyIssued]:
        """Authoritative purchase-time install-key flow.

        Payment/subscription must already be confirmed before calling this.
        """
        if auth_ctx is not None or buyer_email is not None or org_id is not None:
            resolved_owner = self.resolve_owner_key(
                auth_ctx=auth_ctx,
                buyer_email=buyer_email,
                org_id=org_id,
            )
        elif owner_key is not None:
            resolved_owner = self._normalize_owner_key(owner_key)
        else:
            raise ValueError("Either owner_key or buyer_email/org_id/auth_ctx must be provided")

        if payment_confirmed is not None:
            confirmed = bool(payment_confirmed)
        else:
            confirmed = str(payment_status or "").strip().lower() in {"paid", "success", "succeeded", "complete", "completed", "active"}
        if not confirmed:
            raise ValueError("Install keys can only be provisioned after successful payment confirmation.")

        normalized_owner = self.ensure_entitled_owner(resolved_owner)
        base_metadata: dict[str, Any] = {
            "customer_id": customer_id,
            "subscription_id": subscription_id,
            "owner_key": normalized_owner,
            "source": source,
            "payment_status": payment_status or "paid",
            "entitlements_status": entitlements_status or "active",
            "issued_after_payment": bool(issued_after_payment),
            "checkout_session_id": checkout_session_id,
            "purchase_reference": purchase_reference or checkout_session_id or subscription_id,
            "auto_provisioned": True,
        }
        if metadata:
            base_metadata.update(metadata)

        results: dict[str, InstallKeyIssued] = {}
        for program in _VALID_PROGRAMS:
            program_metadata = dict(base_metadata)
            program_metadata["program"] = program
            results[program] = self.provision_for_program(
                owner_key=normalized_owner,
                subscription_id=subscription_id,
                program=program,
                source=source,
                label="auto-provisioned",
                metadata=program_metadata,
                payment_status=program_metadata.get("payment_status"),
                entitlements_status=program_metadata.get("entitlements_status"),
                issued_after_payment=bool(program_metadata.get("issued_after_payment", True)),
                checkout_session_id=program_metadata.get("checkout_session_id"),
                purchase_reference=program_metadata.get("purchase_reference"),
                customer_id=customer_id,
                org_id=org_id,
                payment_confirmed=True,
            )
        return results

    def issue_install_key(
        self,
        *,
        owner_key: str,
        subscription_id: str,
        program: str,
        source: str = "manual",
        label: str = "manual-issued",
        metadata: dict[str, Any] | None = None,
    ) -> InstallKeyIssued:
        return self.provision_for_program(
            owner_key=owner_key,
            subscription_id=subscription_id,
            program=program,
            source=source,
            label=label,
            metadata=metadata,
        )


__all__ = [
    "ProgramCode",
    "InstallKeyIssued",
    "InstallKeyProvisioningService",
    "provision_install_key_service",
]

_default_service = InstallKeyProvisioningService()


def provision_install_key_service() -> InstallKeyProvisioningService:
    return _default_service
