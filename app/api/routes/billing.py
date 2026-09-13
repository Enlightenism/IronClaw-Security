from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import logging
import os
import re
from threading import Lock
from typing import Any
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator

from app.core.auth import AuthContext, get_auth_context, require_auth_context
from app.core.billing import resolve_billing_owner
from app.core.install_key_formats import InstallKeyFormatRegistry
from app.core.install_keys import InstallKeyAlreadyExistsError, get_install_key_registry
from app.core.unit_wallet import (
    ORG_KEY_PREFIX,
    TOKEN_CHUNK_SIZE,
    get_unit_wallet_registry,
    units_required_for_tokens,
)
from app.persistencebootstrap import build_store

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/billing",
    tags=["billing"],
    dependencies=[Depends(require_auth_context)],
)

_PURCHASES_MAX_SIZE: int = 1_000
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_ORG_KEY_RE = re.compile(r"^ic_org_")

_BILLING_PACKAGE_FALLBACK: dict[str, dict[str, Any]] = {
    "pkg_5000": {
        "package_id": "pkg_5000",
        "name": "Starter",
        "price_usd": 20.00,
        "included_units": 5_000,
        "display_label": "5,000 units — $20.00",
        "description": ("Prepaid protection units for individual builders who want guarded prompt handling, tool-call review, source inspection, and safe response release."),
    },
    "pkg_25000": {
        "package_id": "pkg_25000",
        "name": "Team",
        "price_usd": 90.00,
        "included_units": 25_000,
        "display_label": "25,000 units — $90.00",
        "description": ("Prepaid protection units for teams running higher volumes of AI-assisted development, research, and guarded agent workflows."),
    },
    "pkg_60000": {
        "package_id": "pkg_60000",
        "name": "Enterprise",
        "price_usd": 180.00,
        "included_units": 60_000,
        "display_label": "60,000 units — $180.00",
        "description": ("Prepaid protection units for organizations protecting large-scale agent operations, sensitive workflows, and high-frequency prompt activity."),
    },
}


def _derive_package_catalog() -> dict[str, dict[str, Any]]:
    try:
        from app.core.unit_wallet import UNIT_PACKAGE_CATALOG  # noqa: PLC0415

        required_ids = set(_BILLING_PACKAGE_FALLBACK)
        catalog: dict[str, dict[str, Any]] = {}
        for pkg_id in required_ids:
            source = UNIT_PACKAGE_CATALOG.get(pkg_id)
            if source is not None:
                catalog[pkg_id] = {
                    "package_id": pkg_id,
                    "name": str(source["name"]),
                    "price_usd": float(source["price_usd"]),
                    "included_units": int(source["unit_amount"]),
                    "display_label": str(source.get("display_label", "")),
                    "description": str(source.get("description", "")),
                }
            else:
                catalog[pkg_id] = _BILLING_PACKAGE_FALLBACK[pkg_id]
        return catalog
    except Exception:
        logger.exception("billing: failed to derive PACKAGE_CATALOG from unit_wallet; using hardcoded fallback")
        return dict(_BILLING_PACKAGE_FALLBACK)


PACKAGE_CATALOG: dict[str, dict[str, Any]] = _derive_package_catalog()


class BillingPackageView(BaseModel):
    package_id: str
    name: str
    price_usd: float
    included_units: int
    display_label: str
    description: str
    token_coverage: int
    tokens_per_unit: int


class ProtectionValueView(BaseModel):
    title: str
    detail: str


class UnitPolicyView(BaseModel):
    unit_definition: str
    token_chunk_size: int
    delivery_model: str
    buyer_positioning: str
    protection_layers: list[ProtectionValueView] = Field(default_factory=list)
    market_context: list[str] = Field(default_factory=list)


class BillingPackagePurchaseRequest(BaseModel):
    package_id: str = Field(min_length=1, max_length=120)
    buyer_name: str = Field(min_length=1, max_length=120)
    buyer_email: str = Field(min_length=3, max_length=254)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("buyer_email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        value = v.strip()
        if _ORG_KEY_RE.match(value):
            return value
        normalized = value.lower()
        if not _EMAIL_RE.match(normalized):
            raise ValueError("Invalid email address")
        return normalized


class BillingPackagePurchaseView(BaseModel):
    purchase_id: str
    package_id: str
    package_name: str
    buyer_name: str
    buyer_email: str
    owner_key: str
    price_usd: float
    granted_units: int
    token_coverage: int
    tokens_per_unit: int
    created_at: str
    payment_id: str | None = None
    payment_status: str = "pending"
    entitlement_status: str = "not_active"
    install_key_id: str | None = None
    masked_key: str | None = None
    program: str | None = None
    usage_summary: dict[str, Any] = Field(default_factory=dict)
    openclaw_install_key: str | None = None
    claude_code_install_key: str | None = None
    hermes_install_key: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletBalanceView(BaseModel):
    wallet_id: str
    owner_key: str
    balance_units: int
    total_purchased_units: int
    total_consumed_units: int
    total_refunded_units: int
    updated_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletLedgerEntryView(BaseModel):
    entry_id: str
    wallet_id: str
    owner_key: str
    entry_type: str
    units: int
    balance_after: int
    created_at: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class BillingPackagesResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    packages: list[BillingPackageView] = Field(default_factory=list)
    unit_policy: UnitPolicyView


class BillingPackagePurchaseResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    purchase: BillingPackagePurchaseView
    wallet: WalletBalanceView


class BillingWalletBalanceResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    wallet: WalletBalanceView


class BillingLedgerResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str | None = None
    limit: int
    entries: list[WalletLedgerEntryView] = Field(default_factory=list)


class WalletDebitRequest(BaseModel):
    units: int | None = Field(default=None, ge=1)
    token_count: int | None = Field(default=None, ge=1)
    reason: str = Field(default="api_debit", min_length=1, max_length=120)
    reference_id: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletDebitResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str
    units_debited: int
    token_count: int | None
    wallet: WalletBalanceView


class WalletRefundRequest(BaseModel):
    units: int = Field(ge=1)
    reason: str = Field(default="api_refund", min_length=1, max_length=120)
    reference_id: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WalletRefundResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str
    units_refunded: int
    wallet: WalletBalanceView


class InsufficientUnitsErrorResponse(BaseModel):
    status: str
    error: str
    owner_key: str
    have: int
    need: int
    tokens_per_unit: int
    timestamp: str


_PURCHASES: list[BillingPackagePurchaseView] = []


def _compute_payload_hash(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _event_idempotency_store() -> Any:
    return build_store(mode=os.getenv("IRONCLAW_PERSISTENCE_MODE", "auto"), allow_fallback=True)


def _read_event_ledger_record(*, session_id: str | None = None, payload_hash: str | None = None, purchase_id: str | None = None) -> dict[str, Any] | None:
    store = _event_idempotency_store()
    for table in ("event_idempotency_ledger", "ironclaw_event_idempotency"):
        try:
            rows = store.select(table)
            for row in rows:
                if session_id and str(row.get("checkout_session_id") or "").strip() == session_id:
                    return row
                if payload_hash and str(row.get("payload_hash") or "").strip() == payload_hash:
                    return row
                if purchase_id and str(row.get("purchase_id") or "").strip() == purchase_id:
                    return row
        except Exception:
            logger.exception("billing: failed to read event ledger table=%s", table)
    return None


def _write_event_ledger_record(*, event_id: str, event_type: str, session_id: str | None, purchase_id: str | None, payload_hash: str) -> dict[str, Any]:
    store = _event_idempotency_store()
    record = {
        "event_id": event_id,
        "event_type": event_type,
        "source": "billing_checkout_session_completed",
        "checkout_session_id": session_id,
        "purchase_id": purchase_id,
        "payload_hash": payload_hash,
        "created_at": _utc_now_iso(),
        "processed_at": _utc_now_iso(),
        "status": "processed",
    }
    for table in ("event_idempotency_ledger", "ironclaw_event_idempotency"):
        try:
            rows = store.select(table)
            existing = None
            for row in rows:
                if session_id and str(row.get("checkout_session_id") or "").strip() == session_id:
                    existing = row
                    break
                if payload_hash and str(row.get("payload_hash") or "").strip() == payload_hash:
                    existing = row
                    break
            if existing is not None:
                store.update(table, record, filters={"event_id": str(existing.get("event_id") or event_id)})
            else:
                store.insert(table, record)
            return record
        except Exception:
            logger.exception("billing: failed to write event ledger table=%s", table)
    return record


def _verify_stripe_signature(payload: bytes, signature: str | None) -> dict[str, Any]:
    secret = (os.getenv("STRIPE_WEBHOOK_SECRET") or "").strip()
    if not secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "invalid_payload", "reason": "stripe_webhook_secret_missing"},
        )
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "invalid_payload", "reason": "missing_stripe_signature"},
        )
    try:
        import stripe  # type: ignore
    except Exception as exc:  # pragma: no cover - dependency guard
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"status": "server_error", "reason": "stripe_sdk_unavailable"},
        ) from exc
    try:
        event = stripe.Webhook.construct_event(payload=payload, sig_header=signature, secret=secret)
    except Exception as exc:  # stripe.error.SignatureVerificationError
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "invalid_payload", "reason": "stripe_signature_invalid"},
        ) from exc
    return dict(event)


class _DurablePurchaseRepository:
    def __init__(self, store: Any | None = None) -> None:
        self._lock = Lock()
        self._table = "billing_purchases"
        self._store = store or build_store(mode="memory", allow_fallback=True)

    def _normalize_purchase(self, purchase: BillingPackagePurchaseView | dict[str, Any]) -> dict[str, Any]:
        if isinstance(purchase, BillingPackagePurchaseView):
            payload = purchase.model_dump(mode="json")
        else:
            payload = dict(purchase)
        payload.setdefault("metadata", {})
        return payload

    def upsert(self, purchase: BillingPackagePurchaseView | dict[str, Any]) -> dict[str, Any]:
        payload = self._normalize_purchase(purchase)
        purchase_id = str(payload.get("purchase_id") or "").strip()
        if not purchase_id:
            raise ValueError("purchase_id is required for durable purchase write")
        with self._lock:
            try:
                rows = self._store.select(self._table, filters={"purchase_id": purchase_id})
                if rows:
                    self._store.update(self._table, payload, filters={"purchase_id": purchase_id})
                else:
                    self._store.insert(self._table, payload)
            except Exception:
                logger.exception("billing: failed to persist purchase %s to durable storage", purchase_id)
                raise RuntimeError(f"billing: durable purchase persistence failed for {purchase_id}") from None
        return payload

    def list_recent(self, limit: int = 50) -> list[BillingPackagePurchaseView]:
        safe_limit = max(1, min(int(limit), _PURCHASES_MAX_SIZE))
        records: list[BillingPackagePurchaseView] = []
        try:
            rows = self._store.select(self._table)
            for row in rows:
                try:
                    records.append(BillingPackagePurchaseView(**row))
                except Exception:
                    continue
        except Exception:
            logger.exception("billing: durable purchase list failed; falling back to in-memory state")
            records = []
        if records:
            return list(reversed(records))[:safe_limit]
        return list(reversed(_PURCHASES))[:safe_limit]

    def find_for_checkout(
        self,
        *,
        session_id: str | None = None,
        owner_key: str | None = None,
        buyer_email: str | None = None,
        customer_id: str | None = None,
        purchase_id: str | None = None,
    ) -> BillingPackagePurchaseView | None:
        session_value = str(session_id or "").strip()
        owner_value = str(owner_key or "").strip().lower()
        buyer_value = str(buyer_email or "").strip().lower()
        customer_value = str(customer_id or "").strip()
        purchase_value = str(purchase_id or "").strip()
        combined: list[BillingPackagePurchaseView] = []
        for purchase in reversed(_PURCHASES):
            combined.append(purchase)
        try:
            for row in self._store.select(self._table):
                try:
                    combined.append(BillingPackagePurchaseView(**row))
                except Exception:
                    continue
        except Exception:
            pass
        seen: set[str] = set()
        for purchase in combined:
            purchase_key = str(purchase.purchase_id).strip()
            if purchase_key and purchase_key in seen:
                continue
            seen.add(purchase_key)
            if purchase_value and purchase.purchase_id == purchase_value:
                return purchase
            metadata = purchase.metadata or {}
            if session_value and (metadata.get("checkout_session_id") == session_value or purchase.purchase_id == session_value):
                return purchase
            if owner_value and purchase.owner_key.lower() == owner_value:
                return purchase
            if buyer_value and purchase.buyer_email.lower() == buyer_value:
                return purchase
            if customer_value and str(metadata.get("customer_id") or "").strip() == customer_value:
                return purchase
        return None


_PURCHASE_REPOSITORY = _DurablePurchaseRepository()


def _append_purchase(purchase: BillingPackagePurchaseView) -> None:
    _PURCHASES.append(purchase)
    try:
        _PURCHASE_REPOSITORY.upsert(purchase)
    except Exception:
        if purchase in _PURCHASES:
            _PURCHASES.remove(purchase)
        raise
    if len(_PURCHASES) > _PURCHASES_MAX_SIZE:
        del _PURCHASES[: len(_PURCHASES) - _PURCHASES_MAX_SIZE]


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _new_purchase_id() -> str:
    return f"purch_{uuid.uuid4().hex[:16]}"


def _parse_checkout_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _install_key_records_for_owner(owner_key: str) -> list[Any]:
    try:
        return get_install_key_registry().get_keys_for_owner(owner_key)
    except Exception:
        logger.exception("billing: failed to load install keys for owner_key=%s", owner_key)
        return []


def _provision_paid_install_keys(
    *,
    owner_key: str,
    purchase_id: str,
    session_id: str | None,
    payment_id: str | None,
    buyer_email: str,
) -> dict[str, str]:
    issued: dict[str, str] = {}
    registry = get_install_key_registry()
    for program in InstallKeyFormatRegistry.list_programs():
        try:
            record = registry.generate_install_key(
                owner_key=owner_key,
                subscription_id=purchase_id,
                program=program,
                label=f"paid-provisioned on purchase {purchase_id}",
                metadata={
                    "purchase_id": purchase_id,
                    "checkout_session_id": session_id,
                    "payment_id": payment_id,
                    "payment_status": "paid",
                    "entitlements_status": "active",
                    "issued_after_payment": True,
                    "auto_provisioned": True,
                    "buyer_email": buyer_email,
                },
                payment_status="paid",
                entitlements_status="active",
                issued_after_payment=True,
                purchase_reference=purchase_id,
                checkout_session_id=session_id,
            )
        except InstallKeyAlreadyExistsError:
            existing = next((item for item in registry.get_keys_for_owner(owner_key) if item.program == program and (item.active or str(item.payment_status).lower() == "paid")), None)
            if existing is None:
                continue
            record = existing
        except Exception:
            logger.exception(
                "billing: install key issuance failed for owner=%s program=%s purchase_id=%s",
                owner_key,
                program,
                purchase_id,
            )
            continue

        if str(getattr(record, "payment_status", "")).strip().lower() != "paid":
            continue
        if not bool(getattr(record, "issued_after_payment", False)):
            continue
        masked_key = getattr(record, "masked_key", None)
        if not masked_key:
            continue
        issued[program] = str(masked_key)
    return issued


def _find_matching_purchase(
    *,
    session_id: str | None = None,
    owner_key: str | None = None,
    buyer_email: str | None = None,
    customer_id: str | None = None,
    purchase_id: str | None = None,
) -> BillingPackagePurchaseView | None:
    return _PURCHASE_REPOSITORY.find_for_checkout(
        session_id=session_id,
        owner_key=owner_key,
        buyer_email=buyer_email,
        customer_id=customer_id,
        purchase_id=purchase_id,
    )


def _package_to_view(pkg_id: str, pkg: dict[str, Any]) -> BillingPackageView:
    included_units = int(pkg["included_units"])
    token_coverage = included_units * TOKEN_CHUNK_SIZE
    return BillingPackageView(
        package_id=pkg_id,
        name=str(pkg["name"]),
        price_usd=float(pkg["price_usd"]),
        included_units=included_units,
        display_label=str(pkg.get("display_label", "")),
        description=str(pkg.get("description", "")),
        token_coverage=token_coverage,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
    )


def _wallet_to_view(wallet: Any) -> WalletBalanceView:
    updated_at = getattr(wallet, "updated_at", None)
    if hasattr(updated_at, "isoformat"):
        updated_at_value = updated_at.isoformat().replace("+00:00", "Z")
    else:
        updated_at_value = _utc_now_iso()

    metadata = getattr(wallet, "metadata", {}) or {}
    if not isinstance(metadata, dict):
        metadata = {}

    return WalletBalanceView(
        wallet_id=str(wallet.wallet_id),
        owner_key=str(wallet.owner_key),
        balance_units=int(wallet.balance_units),
        total_purchased_units=int(wallet.total_purchased_units),
        total_consumed_units=int(wallet.total_consumed_units),
        total_refunded_units=int(wallet.total_refunded_units),
        updated_at=updated_at_value,
        metadata=metadata,
    )


def _assert_owner_access(owner_key: str, auth_ctx: AuthContext) -> None:
    is_org_wallet = owner_key.startswith(ORG_KEY_PREFIX)
    caller_key_type = getattr(auth_ctx, "key_type", None)
    caller_org_id = getattr(auth_ctx, "org_id", None)

    if is_org_wallet:
        if caller_key_type != "org" or caller_org_id is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "org_wallet_requires_org_key",
                    "detail": "This wallet requires an org key.",
                },
            )
        expected_owner = f"{ORG_KEY_PREFIX}{caller_org_id}"
        if owner_key != expected_owner:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "org_key_mismatch",
                    "detail": (f"Org key does not match wallet owner: expected {expected_owner}, got {owner_key}"),
                },
            )
    else:
        if caller_key_type == "org" or caller_org_id is not None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "org_key_cannot_access_personal_wallet",
                    "detail": "Org keys may not access personal wallets.",
                },
            )
        caller_id = getattr(auth_ctx, "principal_id", None)
        if caller_id and owner_key != caller_id.strip().lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "reason": "principal_mismatch",
                    "detail": "Access to this wallet is not permitted.",
                },
            )


def _require_existing_wallet(registry: Any, owner_key: str) -> Any:
    wallet = registry.get_wallet(owner_key)
    if wallet is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No wallet found for owner_key: {owner_key!r}",
        )
    return wallet


def _get_or_zero_wallet(registry: Any, owner_key: str) -> Any:
    wallet = registry.get_wallet(owner_key)
    if wallet is not None:
        return wallet
    if hasattr(registry, "get_or_create_wallet"):
        return registry.get_or_create_wallet(owner_key)

    class _ZeroWallet:
        def __init__(self, owner_key_value: str) -> None:
            self.balance_units = 0
            self.wallet_id = f"wallet_missing_{uuid.uuid4().hex}"
            self.owner_key = str(owner_key_value).strip().lower()
            self.total_purchased_units = 0
            self.total_consumed_units = 0
            self.total_refunded_units = 0
            self.updated_at = datetime.now(UTC)
            self.metadata: dict[str, Any] = {}

    return _ZeroWallet(owner_key)


@router.get(
    "/packages",
    response_model=BillingPackagesResponse,
    summary="List available protection unit packages",
)
def get_packages() -> BillingPackagesResponse:
    packages = [_package_to_view(pid, pkg) for pid, pkg in PACKAGE_CATALOG.items()]
    unit_policy = UnitPolicyView(
        unit_definition=(f"One protection unit covers {TOKEN_CHUNK_SIZE:,} tokens of inspected AI interaction across all active guardrails."),
        token_chunk_size=TOKEN_CHUNK_SIZE,
        delivery_model="prepaid",
        buyer_positioning=("Units are consumed as AI actions pass through IronClaw guardrails. Unused units roll over until your balance is exhausted."),
        protection_layers=[
            ProtectionValueView(
                title="Prompt Injection Guard",
                detail="Detects and blocks adversarial instructions embedded in user input.",
            ),
            ProtectionValueView(
                title="Tool Call Enforcement",
                detail="Validates every tool invocation against your active policy set.",
            ),
            ProtectionValueView(
                title="Data Leakage Prevention",
                detail="Inspects outbound content for sensitive patterns before release.",
            ),
            ProtectionValueView(
                title="Trust Boundary Enforcement",
                detail="Maintains separation between agent tiers and external systems.",
            ),
        ],
        market_context=[
            "Enterprise AI security starts at the token layer.",
            "Every guardrail inspection is metered, auditable, and reproducible.",
            "IronClaw units give your team a shared enforcement budget with full telemetry.",
        ],
    )
    return BillingPackagesResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        packages=packages,
        unit_policy=unit_policy,
    )


@router.post(
    "/purchase",
    response_model=BillingPackagePurchaseResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Purchase a protection unit package",
)
def purchase_package(
    body: BillingPackagePurchaseRequest,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> BillingPackagePurchaseResponse:
    pkg = PACKAGE_CATALOG.get(body.package_id)
    if pkg is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Unknown package_id: {body.package_id!r}",
        )

    buyer_email_normalized = body.buyer_email
    owner_key = resolve_billing_owner(auth_ctx, buyer_email_normalized)
    registry = get_unit_wallet_registry()

    purchase_id = _new_purchase_id()
    created_at = _utc_now_iso()
    wallet = _get_or_zero_wallet(registry, owner_key)

    purchase_metadata = {
        **body.metadata,
        "package_id": body.package_id,
        "buyer_name": body.buyer_name,
        "buyer_email": buyer_email_normalized,
        "owner_key": owner_key,
        "payment_required": True,
        "payment_status": "pending",
        "fulfillment_status": "pending",
        "install_keys_provisioned": False,
        "units_credited": False,
    }

    purchase = BillingPackagePurchaseView(
        purchase_id=purchase_id,
        package_id=body.package_id,
        package_name=str(pkg["name"]),
        buyer_name=body.buyer_name,
        buyer_email=buyer_email_normalized,
        owner_key=owner_key,
        price_usd=float(pkg["price_usd"]),
        granted_units=0,
        token_coverage=int(pkg["included_units"]) * TOKEN_CHUNK_SIZE,
        tokens_per_unit=TOKEN_CHUNK_SIZE,
        created_at=created_at,
        payment_id=None,
        payment_status="pending",
        entitlement_status="not_active",
        install_key_id=None,
        masked_key=None,
        program=None,
        usage_summary={},
        openclaw_install_key=None,
        claude_code_install_key=None,
        hermes_install_key=None,
        metadata=purchase_metadata,
    )
    try:
        _append_purchase(purchase)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "status": "purchase_persistence_failed",
                "reason": "durable_purchase_storage_unavailable",
                "purchase_id": purchase_id,
            },
        ) from exc

    return BillingPackagePurchaseResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        purchase=purchase,
        wallet=_wallet_to_view(wallet),
    )


def _process_checkout_session_completed_webhook(
    payload: dict[str, Any],
    *,
    raw_webhook: bytes | None = None,
    stripe_signature: str | None = None,
) -> dict[str, Any]:
    if raw_webhook is not None:
        _verify_stripe_signature(raw_webhook, stripe_signature)

    event_type = str((payload or {}).get("type") or (payload or {}).get("event_type") or "").strip().lower()
    if event_type != "checkout.session.completed":
        return {
            "status": "ignored",
            "event_type": event_type,
            "reason": "unsupported_event_type",
        }

    event_data = ((payload or {}).get("data") or {}).get("object") or (payload or {}).get("object") or {}
    session_id = str(event_data.get("id") or (payload or {}).get("id") or "").strip()
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "invalid_payload", "reason": "missing_checkout_session_id"},
        )

    payment_status = _parse_checkout_status(event_data.get("payment_status") or event_data.get("status"))
    if payment_status not in {"paid", "succeeded", "success", "complete", "completed"}:
        return {
            "status": "ignored",
            "event_type": event_type,
            "session_id": session_id,
            "payment_status": payment_status,
            "reason": "payment_not_confirmed",
        }

    metadata = dict(event_data.get("metadata") or {})
    purchase_id = str(metadata.get("purchase_id") or "").strip()
    buyer_email = str((event_data.get("customer_details") or {}).get("email") or metadata.get("buyer_email") or "").strip().lower()
    owner_key = str(metadata.get("owner_key") or buyer_email or "").strip().lower()
    customer_id = str(event_data.get("customer") or metadata.get("customer_id") or "").strip()
    payload_hash = _compute_payload_hash(payload)

    existing_event = _read_event_ledger_record(session_id=session_id, payload_hash=payload_hash, purchase_id=purchase_id or None)
    if existing_event is not None:
        wallet = get_unit_wallet_registry().get_or_create_wallet(owner_key or buyer_email or purchase_id)
        return {
            "status": "duplicate",
            "event_id": str(payload.get("id") or event_data.get("id") or session_id),
            "purchase_id": purchase_id,
            "session_id": session_id,
            "payload_hash": payload_hash,
            "wallet": _wallet_to_view(wallet),
            "reason": "event_already_processed",
        }

    purchase = _find_matching_purchase(
        session_id=session_id,
        owner_key=owner_key or None,
        buyer_email=buyer_email or None,
        customer_id=customer_id or None,
        purchase_id=purchase_id or None,
    )
    if purchase is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "status": "purchase_not_found",
                "reason": "no_pending_purchase_for_checkout_session",
                "session_id": session_id,
            },
        )

    already_credited = bool(purchase.metadata.get("units_credited")) or bool(purchase.metadata.get("wallet_credited"))
    if already_credited:
        wallet = get_unit_wallet_registry().get_or_create_wallet(purchase.owner_key)
        _write_event_ledger_record(
            event_id=str(payload.get("id") or event_data.get("id") or session_id),
            event_type=event_type,
            session_id=session_id,
            purchase_id=purchase.purchase_id,
            payload_hash=payload_hash,
        )
        return {
            "status": "duplicate",
            "purchase_id": purchase.purchase_id,
            "session_id": session_id,
            "wallet": _wallet_to_view(wallet),
            "reason": "purchase_already_credited",
            "metadata": purchase.metadata,
        }

    pkg = PACKAGE_CATALOG.get(purchase.package_id)
    granted_units = int(purchase.granted_units or (pkg["included_units"] if pkg else 0))
    if granted_units <= 0 and pkg is not None:
        granted_units = int(pkg["included_units"])

    wallet = get_unit_wallet_registry().get_or_create_wallet(purchase.owner_key)
    try:
        updated_wallet = get_unit_wallet_registry().credit_units(
            owner_key=purchase.owner_key,
            units=granted_units,
            metadata={
                "source": "checkout.session.completed",
                "purchase_id": purchase.purchase_id,
                "checkout_session_id": session_id,
                "package_id": purchase.package_id,
                "event_type": event_type,
                "customer_id": customer_id,
                "payment_status": "paid",
                "fulfillment_status": "fulfilled",
                "payload_hash": payload_hash,
            },
        )
    except Exception:
        purchase.payment_status = "pending"
        purchase.entitlement_status = "not_active"
        purchase.metadata["payment_status"] = "pending"
        purchase.metadata["fulfillment_status"] = "pending"
        purchase.metadata["install_keys_provisioned"] = False
        purchase.metadata["units_credited"] = False
        purchase.metadata["wallet_credited"] = False
        purchase.metadata["checkout_session_id"] = session_id
        purchase.metadata["customer_id"] = customer_id
        purchase.metadata["owner_key"] = purchase.owner_key
        purchase.metadata["buyer_email"] = purchase.buyer_email
        purchase.metadata["package_id"] = purchase.package_id
        try:
            _PURCHASE_REPOSITORY.upsert(purchase)
        except Exception:
            logger.exception("billing: failed to rollback purchase state after wallet credit failure for purchase_id=%s", purchase.purchase_id)
        raise

    purchase.granted_units = granted_units
    purchase.payment_id = str(metadata.get("payment_id") or purchase.purchase_id)
    purchase.payment_status = "paid"
    purchase.entitlement_status = "active"
    purchase.metadata["payment_status"] = "paid"
    purchase.metadata["fulfillment_status"] = "fulfilled"
    purchase.metadata["install_keys_provisioned"] = False
    purchase.metadata["units_credited"] = True
    purchase.metadata["wallet_credited"] = True
    purchase.metadata["credit_event_hash"] = payload_hash
    purchase.metadata["checkout_session_id"] = session_id
    purchase.metadata["customer_id"] = customer_id
    purchase.metadata["owner_key"] = purchase.owner_key
    purchase.metadata["buyer_email"] = purchase.buyer_email
    purchase.metadata["package_id"] = purchase.package_id

    triggered = _provision_paid_install_keys(
        owner_key=purchase.owner_key,
        purchase_id=purchase.purchase_id,
        session_id=session_id,
        payment_id=str(metadata.get("payment_id") or purchase.purchase_id),
        buyer_email=purchase.buyer_email,
    )

    if triggered:
        purchase.metadata["install_keys_provisioned"] = True
        purchase.install_key_id = next(iter(triggered.values()), None)
        purchase.masked_key = purchase.install_key_id
        purchase.program = next(iter(sorted(triggered)), None)
        purchase.usage_summary = {
            "program": purchase.program,
            "entitlement_status": "active",
            "payment_status": "paid",
            "install_keys_provisioned": True,
        }
        purchase.openclaw_install_key = triggered.get("openclaw")
        purchase.claude_code_install_key = triggered.get("claude_code")
        purchase.hermes_install_key = triggered.get("hermes")
        purchase.metadata["issued_programs"] = sorted(triggered)

    try:
        _PURCHASE_REPOSITORY.upsert(purchase)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={
                "status": "purchase_persistence_failed",
                "reason": "durable_purchase_storage_unavailable",
                "purchase_id": purchase.purchase_id,
                "session_id": session_id,
            },
        ) from exc

    _write_event_ledger_record(
        event_id=str(payload.get("id") or event_data.get("id") or session_id),
        event_type=event_type,
        session_id=session_id,
        purchase_id=purchase.purchase_id,
        payload_hash=payload_hash,
    )
    return {
        "status": "fulfilled",
        "purchase_id": purchase.purchase_id,
        "session_id": session_id,
        "purchase": purchase.model_dump(mode="json"),
        "wallet": _wallet_to_view(updated_wallet),
        "metadata": purchase.metadata,
    }


def handle_checkout_session_completed_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    """Synchronous compatibility wrapper for direct use in tests and legacy callers."""
    return _process_checkout_session_completed_webhook(payload)


@router.post(
    "/webhook",
    status_code=status.HTTP_200_OK,
    summary="Process a Stripe checkout completion webhook for a pending purchase",
)
async def _handle_checkout_session_completed_webhook_route(
    request: Request,
    stripe_signature: str | None = Header(default=None, alias="stripe-signature"),
) -> dict[str, Any]:
    raw_webhook = await request.body()
    if not raw_webhook:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "invalid_payload", "reason": "missing_event_payload"},
        )

    try:
        payload = json.loads(raw_webhook.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "invalid_payload", "reason": "event_payload_not_json"},
        ) from None
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"status": "invalid_payload", "reason": "event_payload_must_be_object"},
        )

    return _process_checkout_session_completed_webhook(payload, raw_webhook=raw_webhook, stripe_signature=stripe_signature)


@router.post(
    "/webhook/stripe",
    status_code=status.HTTP_200_OK,
    summary="Legacy Stripe webhook alias",
)
def handle_checkout_session_completed_webhook_legacy(payload: dict[str, Any]) -> dict[str, Any]:
    return _process_checkout_session_completed_webhook(payload)


@router.get(
    "/purchases",
    summary="List recent in-process purchase records",
)
def list_purchases(
    limit: int = Query(default=50, ge=1, le=_PURCHASES_MAX_SIZE),
) -> dict[str, Any]:
    records = _PURCHASE_REPOSITORY.list_recent(limit)
    return {
        "status": "ok",
        "service": "IronClaw-Security",
        "timestamp": _utc_now_iso(),
        "count": len(records),
        "purchases": [p.model_dump(mode="json") for p in records],
    }


@router.get(
    "/wallet/{owner_key}",
    response_model=BillingWalletBalanceResponse,
    summary="Get wallet balance for an owner key",
)
def get_wallet_balance(
    owner_key: str,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> BillingWalletBalanceResponse:
    _assert_owner_access(owner_key, auth_ctx)
    registry = get_unit_wallet_registry()
    wallet = _require_existing_wallet(registry, owner_key)
    return BillingWalletBalanceResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        wallet=_wallet_to_view(wallet),
    )


@router.get(
    "/wallet/{owner_key}/ledger",
    response_model=BillingLedgerResponse,
    summary="Get ledger entries for a wallet",
)
def get_wallet_ledger(
    owner_key: str,
    limit: int = Query(default=50, ge=1, le=500),
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> BillingLedgerResponse:
    _assert_owner_access(owner_key, auth_ctx)
    registry = get_unit_wallet_registry()
    try:
        entries = registry.list_ledger_entries(owner_key=owner_key, limit=limit)
    except Exception:
        logger.exception("billing: list_ledger_entries failed for owner_key=%r", owner_key)
        entries = []
    entry_views = [
        WalletLedgerEntryView(
            entry_id=str(e.entry_id),
            wallet_id=str(e.wallet_id),
            owner_key=str(e.owner_key),
            entry_type=str(e.entry_type),
            units=int(e.units),
            balance_after=int(e.balance_after),
            created_at=str(e.created_at),
            metadata=dict(e.metadata) if e.metadata else {},
        )
        for e in entries
    ]
    return BillingLedgerResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        limit=limit,
        entries=entry_views,
    )


@router.post(
    "/wallet/{owner_key}/debit",
    response_model=WalletDebitResponse,
    summary="Debit units from a wallet",
)
def debit_wallet(
    owner_key: str,
    body: WalletDebitRequest,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> WalletDebitResponse:
    _assert_owner_access(owner_key, auth_ctx)

    if body.units is None and body.token_count is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Provide either 'units' or 'token_count'.",
        )

    if body.units is not None:
        units_to_debit = body.units
    else:
        units_to_debit = units_required_for_tokens(body.token_count)  # type: ignore[arg-type]

    registry = get_unit_wallet_registry()
    wallet = _get_or_zero_wallet(registry, owner_key)

    if wallet.balance_units < units_to_debit:
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "status": "insufficient_units",
                "error": "Insufficient protection units.",
                "owner_key": owner_key,
                "have": wallet.balance_units,
                "need": units_to_debit,
                "tokens_per_unit": TOKEN_CHUNK_SIZE,
                "timestamp": _utc_now_iso(),
            },
        )

    updated_wallet = registry.debit_units(
        owner_key=owner_key,
        units=units_to_debit,
        metadata={
            "reason": body.reason,
            "reference_id": body.reference_id,
            **body.metadata,
        },
    )
    return WalletDebitResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        units_debited=units_to_debit,
        token_count=body.token_count,
        wallet=_wallet_to_view(updated_wallet),
    )


@router.post(
    "/wallet/{owner_key}/refund",
    response_model=WalletRefundResponse,
    summary="Refund units to a wallet",
)
def refund_wallet(
    owner_key: str,
    body: WalletRefundRequest,
    auth_ctx: AuthContext = Depends(get_auth_context),
) -> WalletRefundResponse:
    _assert_owner_access(owner_key, auth_ctx)
    registry = get_unit_wallet_registry()
    _require_existing_wallet(registry, owner_key)
    updated_wallet = registry.refund_units(
        owner_key=owner_key,
        units=body.units,
        metadata={
            "reason": body.reason,
            "reference_id": body.reference_id,
            **body.metadata,
        },
    )
    return WalletRefundResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        owner_key=owner_key,
        units_refunded=body.units,
        wallet=_wallet_to_view(updated_wallet),
    )
