from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

InstallKeyProgram = Literal["openclaw", "claude_code", "hermes"]
InstallKeyIssueEventType = Literal["install_key_issued", "install_key_revoked", "install_key_provisioned"]
InstallKeyUsageEventType = Literal["install_key_usage_recorded"]


class _InstallKeySchemaBase(BaseModel):
    """Canonical schema base for install-key contracts.

    These models are intentionally strict and narrow:
    - no raw secret material is exposed
    - all timestamps are ISO-8601 UTC strings
    - install keys remain bound to a single owner + subscription + program
    """

    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )


def _normalize_iso_timestamp(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        normalized = value.strip()
        return normalized or None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _normalize_payment_status(value: Any) -> str:
    if value is None:
        return "unpaid"
    normalized = str(value).strip().lower()
    if not normalized:
        return "unpaid"
    if normalized in {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}:
        return "paid"
    return normalized


def _normalize_entitlement_status(value: Any) -> str:
    if value is None:
        return "not_active"
    normalized = str(value).strip().lower()
    if not normalized:
        return "not_active"
    if normalized in {"active", "paid", "enabled", "granted"}:
        return "active"
    return normalized


def _normalize_program(value: Any) -> str:
    if value is None:
        raise ValueError("program is required")
    normalized = str(value).strip().lower()
    if normalized not in {"openclaw", "claude_code", "hermes"}:
        raise ValueError("program must be one of: openclaw, claude_code, hermes")
    return normalized


class InstallKeyRecord(_InstallKeySchemaBase):
    """Canonical read model for an install key record.

    This schema intentionally omits the raw install key. The raw value is
    generated once and never stored in plaintext. The masked representation
    is safe to return to clients and dashboards.
    """

    key_id: str = Field(..., min_length=1, max_length=128, description="Unique install key ID.")
    owner_key: str = Field(..., min_length=1, max_length=512, description="Canonical owner identity for the wallet and entitlement.")
    subscription_id: str = Field(..., min_length=1, max_length=256, description="Billing subscription tied to this key.")
    program: InstallKeyProgram = Field(..., description="IronClaw program the key is scoped to.")
    masked_key: str = Field(..., min_length=1, max_length=512, description="Masked value that shows only a safe prefix/suffix.")
    label: str = Field(default="", max_length=256, description="Friendly label assigned to the key.")
    active: bool = Field(default=True, description="Whether the install key is enabled for use.")
    payment_status: str = Field(default="unpaid", description="Normalized payment status for the install key entitlement.")
    entitlements_status: str = Field(default="not_active", description="Normalized entitlement status for the install key.")
    issued_after_payment: bool = Field(default=False, description="Whether the key was issued only after a successful checkout/payment completion.")
    org_id: str | None = Field(default=None, max_length=256, description="Organization identifier if this key is org-scoped.")
    customer_id: str | None = Field(default=None, max_length=256, description="Stripe customer id or equivalent reference.")
    units_consumed: int = Field(default=0, ge=0, description="Cumulative units consumed by this key.")
    created_at: str = Field(..., description="ISO-8601 UTC timestamp when the key was created.")
    last_used_at: str | None = Field(default=None, description="ISO-8601 UTC timestamp of the most recent successful use.")
    revoked_at: str | None = Field(default=None, description="ISO-8601 UTC timestamp when the key was revoked.")
    purchase_reference: str | None = Field(default=None, max_length=512, description="Payment or purchase reference tied to the successful checkout.")
    checkout_session_id: str | None = Field(default=None, max_length=512, description="Stripe checkout session if known.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Opaque per-key metadata.")

    @field_validator("program", mode="before")
    @classmethod
    def _coerce_program(cls, value: Any) -> str:
        return _normalize_program(value)

    @field_validator("payment_status", mode="before")
    @classmethod
    def _normalize_payment_status_field(cls, value: Any) -> str:
        return _normalize_payment_status(value)

    @field_validator("entitlements_status", mode="before")
    @classmethod
    def _normalize_entitlement_status_field(cls, value: Any) -> str:
        return _normalize_entitlement_status(value)

    @field_validator("created_at", mode="before")
    @classmethod
    def _normalize_created_at(cls, value: Any) -> str:
        normalized = _normalize_iso_timestamp(value)
        if normalized is None:
            raise ValueError("created_at is required")
        return normalized

    @field_validator("last_used_at", "revoked_at", mode="before")
    @classmethod
    def _normalize_optional_timestamps(cls, value: Any) -> str | None:
        return _normalize_iso_timestamp(value)

    @model_validator(mode="after")
    def _enforce_paid_active_contract(self) -> InstallKeyRecord:
        if self.active and not self.issued_after_payment:
            raise ValueError("active install keys must be issued_after_payment=True and backed by a paid entitlement")
        if self.active:
            self.payment_status = "paid"
            self.entitlements_status = "active"
        return self

    @classmethod
    def from_core(cls, record: Any) -> InstallKeyRecord:
        """Create a schema instance from a runtime record / dataclass / dict-like object.

        Supports the concrete InstallKeyRecord used in app.core.install_keys and
        any object exposing a public_dict() or to_db_row() method.
        """
        if isinstance(record, cls):
            return record

        if hasattr(record, "public_dict"):
            payload = record.public_dict()
        elif hasattr(record, "to_db_row"):
            payload = record.to_db_row()
        elif isinstance(record, dict):
            payload = record
        else:
            payload = getattr(record, "__dict__", {}) or {}

        metadata = payload.get("metadata") or {}
        if not isinstance(metadata, dict):
            metadata = {"value": metadata}

        return cls(
            key_id=str(payload.get("key_id", "")),
            owner_key=str(payload.get("owner_key", "")),
            subscription_id=str(payload.get("subscription_id", "")),
            program=_normalize_program(payload.get("program")),
            masked_key=str(payload.get("masked_key", "")),
            label=str(payload.get("label") or ""),
            active=bool(payload.get("active", True)),
            payment_status=_normalize_payment_status(payload.get("payment_status", "unpaid")),
            entitlements_status=_normalize_entitlement_status(payload.get("entitlements_status", "not_active")),
            issued_after_payment=bool(payload.get("issued_after_payment", False)),
            org_id=payload.get("org_id"),
            customer_id=payload.get("customer_id"),
            units_consumed=int(payload.get("units_consumed", 0) or 0),
            created_at=_normalize_iso_timestamp(payload.get("created_at")) or "",
            last_used_at=_normalize_iso_timestamp(payload.get("last_used_at")),
            revoked_at=_normalize_iso_timestamp(payload.get("revoked_at")),
            purchase_reference=payload.get("purchase_reference"),
            checkout_session_id=payload.get("checkout_session_id"),
            metadata=metadata,
        )


class InstallKeyIssueEvent(_InstallKeySchemaBase):
    """Canonical event payload emitted when an install key is issued or provisioned."""

    event_id: str = Field(..., min_length=1, max_length=128, description="Unique event id.")
    event_type: InstallKeyIssueEventType = Field(
        default="install_key_issued",
        description="Type of install-key event emitted by the provisioning lifecycle.",
    )
    key_id: str = Field(..., min_length=1, max_length=128, description="Install key being issued.")
    owner_key: str = Field(..., min_length=1, max_length=512, description="Canonical owner identity.")
    subscription_id: str = Field(..., min_length=1, max_length=256, description="Subscription associated with the issue event.")
    program: InstallKeyProgram = Field(..., description="Program the key is scoped to.")
    masked_key: str = Field(..., min_length=1, max_length=512, description="Masked install key shown to the user.")
    label: str = Field(default="", max_length=256, description="Key label or friendly name.")
    org_id: str | None = Field(default=None, max_length=256, description="Organization identifier if this key is org-scoped.")
    customer_id: str | None = Field(default=None, max_length=256, description="Stripe/customer identity if known.")
    payment_status: str = Field(default="unpaid", description="Normalized payment status at issuance time.")
    entitlements_status: str = Field(default="not_active", description="Normalized entitlement status at issuance time.")
    issued_after_payment: bool = Field(default=False, description="Whether the key was issued only after payment success.")
    purchase_reference: str | None = Field(default=None, max_length=512, description="Purchase reference tied to the successful checkout.")
    checkout_session_id: str | None = Field(default=None, max_length=512, description="Stripe checkout session id if known.")
    issued_at: str = Field(..., description="ISO-8601 UTC timestamp when the key was issued.")
    source: str = Field(default="billing", max_length=128, description="Subsystem that issued the key (billing, cli, manual, etc.).")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Opaque per-event metadata.")

    @field_validator("program", mode="before")
    @classmethod
    def _coerce_program(cls, value: Any) -> str:
        return _normalize_program(value)

    @field_validator("payment_status", mode="before")
    @classmethod
    def _normalize_payment_status_field(cls, value: Any) -> str:
        return _normalize_payment_status(value)

    @field_validator("entitlements_status", mode="before")
    @classmethod
    def _normalize_entitlement_status_field(cls, value: Any) -> str:
        return _normalize_entitlement_status(value)

    @field_validator("event_type", mode="before")
    @classmethod
    def _coerce_event_type(cls, value: Any) -> str:
        if value is None:
            return "install_key_issued"
        normalized = str(value).strip()
        if normalized not in {"install_key_issued", "install_key_revoked", "install_key_provisioned"}:
            raise ValueError("event_type must be one of: install_key_issued, install_key_revoked, install_key_provisioned")
        return normalized

    @field_validator("issued_at", mode="before")
    @classmethod
    def _normalize_issued_at(cls, value: Any) -> str:
        normalized = _normalize_iso_timestamp(value)
        if normalized is None:
            raise ValueError("issued_at is required")
        return normalized


class InstallKeyUsageEvent(_InstallKeySchemaBase):
    """Canonical telemetry event emitted when an install key debits wallet units."""

    event_id: str = Field(..., min_length=1, max_length=128, description="Unique usage event id.")
    event_type: InstallKeyUsageEventType = Field(
        default="install_key_usage_recorded",
        description="Usage event type emitted by the runtime or API layer.",
    )
    key_id: str = Field(..., min_length=1, max_length=128, description="Install key that consumed units.")
    owner_key: str = Field(..., min_length=1, max_length=512, description="Canonical owner identity.")
    program: InstallKeyProgram = Field(..., description="Program the key is scoped to.")
    units: int = Field(..., gt=0, description="Units consumed in this event.")
    units_remaining: int = Field(..., ge=0, description="Wallet balance after the usage debit.")
    balance_after: int | None = Field(default=None, ge=0, description="Explicit post-debit wallet balance.")
    recorded_at: str = Field(..., description="ISO-8601 UTC timestamp when the usage was recorded.")
    source: str = Field(default="runtime", max_length=128, description="Subsystem that created the usage event.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Opaque usage metadata including key_id and program when needed.")

    @field_validator("program", mode="before")
    @classmethod
    def _coerce_program(cls, value: Any) -> str:
        return _normalize_program(value)

    @field_validator("event_type", mode="before")
    @classmethod
    def _coerce_event_type(cls, value: Any) -> str:
        if value is None:
            return "install_key_usage_recorded"
        normalized = str(value).strip()
        if normalized != "install_key_usage_recorded":
            raise ValueError("event_type must be 'install_key_usage_recorded'")
        return normalized

    @field_validator("recorded_at", mode="before")
    @classmethod
    def _normalize_recorded_at(cls, value: Any) -> str:
        normalized = _normalize_iso_timestamp(value)
        if normalized is None:
            raise ValueError("recorded_at is required")
        return normalized


class InstallKeyDashboardSummary(_InstallKeySchemaBase):
    """Canonical dashboard summary for a single owner / wallet scope.

    This schema is intentionally aggregate-friendly: it allows the UI and API
    layer to show active keys, usage totals, program counts, and the concrete
    key records without duplicating logic across the billing, wallet, and
    install-key services.
    """

    owner_key: str = Field(..., min_length=1, max_length=512, description="Owner this summary is for.")
    has_active_subscription: bool = Field(default=False, description="Whether the owner has an active paid subscription.")
    total_keys: int = Field(default=0, ge=0, description="Total install key records for this owner.")
    active_keys: int = Field(default=0, ge=0, description="Number of active install keys.")
    total_units_consumed: int = Field(default=0, ge=0, description="Total units consumed across all keys.")
    wallet_balance_units: int = Field(default=0, ge=0, description="Current balance in the owner's wallet.")
    last_used_at: str | None = Field(default=None, description="Most recent install-key usage timestamp across all keys.")
    keys: list[InstallKeyRecord] = Field(default_factory=list, description="Install keys for this owner, including inactive/revoked rows.")
    by_program: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by program, keyed by 'openclaw' and 'claude_code'.",
    )
    metadata: dict[str, Any] = Field(default_factory=dict, description="Opaque summary metadata for external systems.")

    @field_validator("by_program", mode="before")
    @classmethod
    def _normalize_by_program(cls, value: Any) -> dict[str, int]:
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ValueError("by_program must be a dict[str, int]")
        normalized: dict[str, int] = {}
        for raw_key, raw_value in value.items():
            program = _normalize_program(raw_key)
            normalized[program] = int(raw_value)
        return normalized

    @field_validator("last_used_at", mode="before")
    @classmethod
    def _normalize_last_used_at(cls, value: Any) -> str | None:
        return _normalize_iso_timestamp(value)


__all__ = [
    "InstallKeyProgram",
    "InstallKeyIssueEventType",
    "InstallKeyUsageEventType",
    "InstallKeyRecord",
    "InstallKeyIssueEvent",
    "InstallKeyUsageEvent",
    "InstallKeyDashboardSummary",
]
