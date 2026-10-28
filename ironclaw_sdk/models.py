from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator

ScanVerdict = Literal["allow", "block"]

SandboxLane = Literal[
    "none",
    "prompt_injection",
    "code_execution",
    "exfiltration",
    "high_risk_misc",
]

ReviewStatus = Literal["none", "pending", "approved", "rejected"]

MaxSeverity = Literal["low", "medium", "high", "critical"]

TargetType = Literal["prompt", "github_repo", "skill", "archive", "url", "text", "local_path"]
InstallKeyProgram = Literal[
    "openclaw",
    "claude_code",
    "cursor",
    "goose",
    "gemini_cli",
    "copilot",
    "hermes",
    "security_guardian",
]
PaymentStatus = Literal["pending", "paid", "failed", "refunded", "cancelled", "expired", "unpaid"]
EntitlementStatus = Literal["not_active", "active", "disabled", "revoked"]


class ScanRequest(BaseModel):
    target_type: TargetType
    target_value: str = Field(min_length=1, max_length=5000)
    client_id: str | None = None


class ScanFlags(BaseModel):
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    sandbox_lane: SandboxLane = "none"
    max_severity: MaxSeverity | None = None
    primary_category: str | None = None
    untrusted: bool = False


class ScanResponse(BaseModel):
    scan_id: str | None = None
    verdict: ScanVerdict
    summary: str
    target_type: str
    target_value: str
    risk_score: int = Field(ge=0, le=100)
    matched_patterns: list[str] = Field(default_factory=list)
    risky_files: list[str] = Field(default_factory=list)
    checks_loaded: list[str] = Field(default_factory=list)
    failed_checks: list[str] = Field(default_factory=list)
    quarantine_reason: str | None = None
    review_status: ReviewStatus = "none"
    untrusted: bool = False
    sandbox_lane: SandboxLane = "none"
    timestamp: str | None = None
    max_severity: MaxSeverity | None = None
    primary_category: str | None = None
    explanation: str | None = None
    client_id: str | None = None


class BatchScanRequest(BaseModel):
    items: list[ScanRequest] = Field(min_length=1, max_length=100)


class BatchScanResponse(BaseModel):
    count: int
    items: list[ScanResponse]


# ------------------------------------------------------------------
# Billing / install-key models  (mirror the canonical backend contract)
# ------------------------------------------------------------------


class BillingPackagePurchaseRequest(BaseModel):
    package_id: str = Field(min_length=1, max_length=120)
    buyer_name: str = Field(min_length=1, max_length=120)
    buyer_email: str = Field(min_length=3, max_length=254)
    metadata: dict[str, Any] = Field(default_factory=dict)


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


class OwnerKeyBinding(BaseModel):
    owner_key: str
    org_id: str | None = None
    customer_id: str | None = None
    buyer_email: str | None = None


class BillingPackagePurchaseResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    purchase: BillingPackagePurchaseView
    wallet: WalletBalanceView


class InstallKeySlotView(BaseModel):
    key_id: str | None = None
    program: InstallKeyProgram | str
    platform: str | None = None
    masked_key: str | None = None
    label: str = ""
    status: str = "locked"
    active: bool = False
    payment_status: PaymentStatus | str = "unpaid"
    entitlements_status: EntitlementStatus | str = "not_active"
    issued_after_payment: bool = False
    units_used: int = 0
    units_remaining: int = 0
    blocked_attacks: int = 0
    created_at: str | None = None
    last_used_at: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    usage_summary: dict[str, Any] = Field(default_factory=dict)


class InstallKeyRecordView(BaseModel):
    key_id: str
    owner_key: str
    program: InstallKeyProgram | str
    platform: str | None = None
    masked_key: str | None = None
    label: str = ""
    active: bool = True
    payment_status: PaymentStatus | str = "unpaid"
    entitlements_status: EntitlementStatus | str = "not_active"
    issued_after_payment: bool = False
    org_id: str | None = None
    customer_id: str | None = None
    units_consumed: int = 0
    created_at: str | None = None
    last_used_at: str | None = None
    revoked_at: str | None = None
    purchase_reference: str | None = None
    checkout_session_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class InstallKeysResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    owner_key: str
    has_active_entitlement: bool
    keys: list[InstallKeySlotView]


# ------------------------------------------------------------------
# Guard bundle models  (mirrors POST /policy/guard-bundle contract)
# ------------------------------------------------------------------


class GuardBundleRequest(BaseModel):
    """Input for the /policy/guard-bundle endpoint.

    Every slot is optional; pass only the slots relevant to the current
    agentic step. At least one slot must be non-None.
    """

    user_prompt: str | None = None
    retrieved_doc: str | None = None
    tool_output: str | None = None
    model_output: str | None = None


class GuardBundleSlotResult(BaseModel):
    """Per-slot verdict returned by the guard-bundle endpoint."""

    verdict: ScanVerdict
    summary: str
    risk_score: int = Field(ge=0, le=100)
    matched_patterns: list[str] = Field(default_factory=list)
    scan_id: str | None = None
    explanation: str | None = None


class GuardBundleResponse(BaseModel):
    """Structured response from POST /policy/guard-bundle."""

    highest_verdict: ScanVerdict
    should_halt: bool
    should_warn: bool
    user_prompt: GuardBundleSlotResult | dict[str, Any] | None = None
    retrieved_doc: GuardBundleSlotResult | dict[str, Any] | None = None
    tool_output: GuardBundleSlotResult | dict[str, Any] | None = None
    model_output: GuardBundleSlotResult | dict[str, Any] | None = None

    @model_validator(mode="after")
    def _normalize_verdict_flags(self) -> GuardBundleResponse:
        self.should_halt = self.highest_verdict == "block"
        self.should_warn = False
        return self


# ------------------------------------------------------------------
# API error envelope models
# ------------------------------------------------------------------


class AuthError(BaseModel):
    status_code: int
    detail: str


class APIError(BaseModel):
    status_code: int
    body: str


__all__ = [
    "ScanVerdict",
    "SandboxLane",
    "ReviewStatus",
    "MaxSeverity",
    "TargetType",
    "ScanRequest",
    "ScanFlags",
    "ScanResponse",
    "BatchScanRequest",
    "BatchScanResponse",
    "BillingPackagePurchaseRequest",
    "BillingPackagePurchaseView",
    "BillingPackagePurchaseResponse",
    "WalletBalanceView",
    "OwnerKeyBinding",
    "InstallKeyProgram",
    "PaymentStatus",
    "EntitlementStatus",
    "InstallKeySlotView",
    "InstallKeyRecordView",
    "InstallKeysResponse",
    "GuardBundleRequest",
    "GuardBundleResponse",
    "GuardBundleSlotResult",
    "AuthError",
    "APIError",
]
