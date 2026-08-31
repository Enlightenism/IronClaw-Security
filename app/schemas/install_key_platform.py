from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

InstallKeyProgram = Literal["openclaw", "claude_code", "hermes"]
InstallKeyPlatformStatus = Literal["active", "pending", "inactive", "revoked", "not_configured"]


def _normalize_program(value: Any) -> str:
    if value is None:
        raise ValueError("program is required")
    normalized = str(value).strip().lower()
    if normalized not in {"openclaw", "claude_code", "hermes"}:
        raise ValueError("program must be one of: openclaw, claude_code, hermes")
    return normalized


def _normalize_status(value: Any, *, default: str) -> str:
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if not normalized:
        return default
    return normalized


class InstallKeyPlatform(BaseModel):
    """Contract for platform-specific install-key metadata used by backend and dashboard views.

    This schema intentionally models the install-key trust domain rather than the
    generic system API-key domain. It captures the platform identity, its
    canonical install-key program and format family, the owning principal for the
    paid entitlement, and the dashboard-safe status fields used to render cards or
    grouped platform sections.
    """

    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    platform: str = Field(..., min_length=1, max_length=128, description="Normalized platform name, including aliases such as ironclaw or anthropic.")
    program: InstallKeyProgram = Field(..., description="Canonical install-key program that owns the format family.")
    family: str = Field(..., min_length=1, max_length=128, description="Canonical install-key family or compatibility group.")
    display_name: str = Field(..., min_length=1, max_length=128, description="Human-friendly label shown in the UI.")
    label: str = Field(default="", max_length=256, description="Friendly label used for a specific installation instance or card.")
    owner_key: str | None = Field(default=None, max_length=512, description="Resolved owner identity tied to the active paid entitlement.")
    payment_status: str = Field(default="unpaid", description="Normalized payment lifecycle status for the install key entitlement.")
    entitlements_status: str = Field(default="not_active", description="Normalized entitlement lifecycle status for the install key.")
    active: bool = Field(default=False, description="Whether the install key is active and available for use.")
    status: InstallKeyPlatformStatus = Field(default="not_configured", description="Dashboard-oriented lifecycle state for the platform card.")
    key_id: str | None = Field(default=None, max_length=128, description="Install-key record identifier when available.")
    masked_key: str | None = Field(default=None, max_length=512, description="Masked install key value safe to display in the dashboard.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Opaque platform metadata, including aliases and compatibility references.")

    @field_validator("platform", mode="before")
    @classmethod
    def _normalize_platform(cls, value: Any) -> str:
        if value is None:
            raise ValueError("platform is required")
        normalized = str(value).strip().lower().replace("-", "_")
        if not normalized:
            raise ValueError("platform is required")
        return normalized

    @field_validator("program", mode="before")
    @classmethod
    def _normalize_program_field(cls, value: Any) -> str:
        return _normalize_program(value)

    @field_validator("family", mode="before")
    @classmethod
    def _normalize_family(cls, value: Any) -> str:
        if value is None:
            raise ValueError("family is required")
        normalized = str(value).strip().lower().replace("-", "_")
        if not normalized:
            raise ValueError("family is required")
        return normalized

    @field_validator("payment_status", mode="before")
    @classmethod
    def _normalize_payment_status_field(cls, value: Any) -> str:
        normalized = _normalize_status(value, default="unpaid")
        if normalized in {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}:
            return "paid"
        return normalized

    @field_validator("entitlements_status", mode="before")
    @classmethod
    def _normalize_entitlement_status_field(cls, value: Any) -> str:
        normalized = _normalize_status(value, default="not_active")
        if normalized in {"active", "paid", "enabled", "granted"}:
            return "active"
        return normalized

    @field_validator("status", mode="before")
    @classmethod
    def _normalize_status_field(cls, value: Any) -> str:
        normalized = _normalize_status(value, default="not_configured")
        if normalized not in {"active", "pending", "inactive", "revoked", "not_configured"}:
            return "pending"
        return normalized

    @model_validator(mode="after")
    def _enforce_contract(self) -> InstallKeyPlatform:
        if self.active:
            self.payment_status = "paid"
            self.entitlements_status = "active"
            self.status = "active"
        elif self.payment_status == "paid" and self.entitlements_status == "active":
            self.status = "active"
        elif self.payment_status == "pending" or self.entitlements_status == "pending":
            self.status = "pending"
        elif self.status == "revoked":
            self.active = False
        elif self.status == "not_configured":
            self.active = False
        return self

    @property
    def is_paid(self) -> bool:
        return self.payment_status == "paid" and self.entitlements_status == "active"

    @property
    def has_active_entitlement(self) -> bool:
        return self.is_paid and self.active

    @classmethod
    def from_runtime_payload(cls, payload: dict[str, Any]) -> InstallKeyPlatform:
        """Build a schema instance from a runtime payload or dict-like object."""
        if not isinstance(payload, dict):
            raise TypeError("payload must be a dict-like object")

        return cls(
            platform=str(payload.get("platform") or payload.get("name") or payload.get("slug") or "").strip(),
            program=payload.get("program") or payload.get("canonical_program") or payload.get("family") or "openclaw",
            family=str(payload.get("family") or payload.get("program") or payload.get("canonical_program") or "openclaw").strip(),
            display_name=str(payload.get("display_name") or payload.get("label") or payload.get("platform") or "Install Key").strip(),
            label=str(payload.get("label") or payload.get("display_name") or "").strip(),
            owner_key=payload.get("owner_key"),
            payment_status=payload.get("payment_status", "unpaid"),
            entitlements_status=payload.get("entitlements_status", "not_active"),
            active=bool(payload.get("active", False)),
            status=payload.get("status", "not_configured"),
            key_id=payload.get("key_id"),
            masked_key=payload.get("masked_key"),
            metadata=dict(payload.get("metadata") or {}),
        )


class InstallKeyPlatformGroup(BaseModel):
    """Dashboard-friendly grouping contract for multiple platform cards with the same install-key family."""

    model_config = ConfigDict(
        extra="forbid",
        from_attributes=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    family: str = Field(..., min_length=1, max_length=128, description="Shared format family for the grouped platforms.")
    program: InstallKeyProgram = Field(..., description="Canonical program for the group.")
    display_name: str = Field(..., min_length=1, max_length=128, description="Display label for the shared family group.")
    platforms: list[str] = Field(default_factory=list, description="Normalized platform names that share the same install-key format family.")
    cards: list[InstallKeyPlatform] = Field(default_factory=list, description="Dashboard cards for each platform in the group.")
    status: InstallKeyPlatformStatus = Field(default="not_configured", description="Group-level status for the shared format family.")

    @field_validator("family", mode="before")
    @classmethod
    def _normalize_group_family(cls, value: Any) -> str:
        if value is None:
            raise ValueError("family is required")
        normalized = str(value).strip().lower().replace("-", "_")
        if not normalized:
            raise ValueError("family is required")
        return normalized

    @field_validator("program", mode="before")
    @classmethod
    def _normalize_group_program(cls, value: Any) -> str:
        return _normalize_program(value)

    @field_validator("platforms", mode="before")
    @classmethod
    def _normalize_platforms(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value.strip().lower().replace("-", "_")] if value.strip() else []
        return [str(item).strip().lower().replace("-", "_") for item in value if str(item).strip()]

    @model_validator(mode="after")
    def _apply_group_status(self) -> InstallKeyPlatformGroup:
        if any(card.active for card in self.cards):
            self.status = "active"
        elif any(card.payment_status == "paid" and card.entitlements_status == "active" for card in self.cards):
            self.status = "active"
        elif any(card.status == "pending" for card in self.cards):
            self.status = "pending"
        elif self.cards and all(card.status == "not_configured" for card in self.cards):
            self.status = "not_configured"
        else:
            self.status = "inactive"
        return self


__all__ = [
    "InstallKeyPlatform",
    "InstallKeyPlatformGroup",
    "InstallKeyPlatformStatus",
    "InstallKeyProgram",
]
