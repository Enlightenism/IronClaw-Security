from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator


class Scope(StrEnum):
    """Canonical permission scopes enforced at the API schema layer."""

    SYSTEM = "system"
    ADMIN = "admin"

    SCAN_READ = "scan:read"
    SCAN_WRITE = "scan:write"
    SCAN_EXECUTE = "scan:execute"

    TOOL_READ = "tool:read"
    TOOL_WRITE = "tool:write"
    TOOL_EXECUTE = "tool:execute"

    POLICY_READ = "policy:read"
    POLICY_WRITE = "policy:write"

    AUDIT_READ = "audit:read"
    TELEMETRY_READ = "telemetry:read"
    TELEMETRY_WRITE = "telemetry:write"

    REVIEW_READ = "review:read"
    REVIEW_WRITE = "review:write"
    REVIEW_APPROVE = "review:approve"

    TRUST_READ = "trust:read"
    TRUST_WRITE = "trust:write"

    THREAT_READ = "threat:read"
    THREAT_WRITE = "threat:write"

    WEBHOOK_READ = "webhook:read"
    WEBHOOK_WRITE = "webhook:write"

    IOC_READ = "ioc:read"
    IOC_WRITE = "ioc:write"

    KEYS_READ = "keys:read"
    KEYS_WRITE = "keys:write"
    KEYS_ROTATE = "keys:rotate"

    ORG_READ = "org:read"
    ORG_WRITE = "org:write"

    @classmethod
    def _missing_(cls, value: object) -> None:  # type: ignore[override]
        return None

    @classmethod
    def from_string(cls, value: str) -> Scope:
        try:
            return cls(value)
        except ValueError as exc:
            raise ValueError(f"Unknown scope: {value!r}") from exc

    @classmethod
    def validate_scope_list(cls, scopes: list[str]) -> list[Scope]:
        return [cls.from_string(s) for s in scopes]


class APIKeyCreate(BaseModel):
    display_name: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Human-readable label for this key.",
    )
    scopes: list[Scope] = Field(
        default_factory=lambda: [Scope.SYSTEM],
        description="Permission scopes granted to this key.",
    )
    key_type: str = Field(
        default="personal",
        description="Key type: 'personal' or 'org'.",
        pattern=r"^(personal|org)$",
    )
    org_id: str | None = Field(
        default=None,
        max_length=128,
        description="Org identifier; required when key_type='org'.",
    )
    rate_plan: str = Field(
        default="internal",
        max_length=64,
        description="Rate plan identifier for quota enforcement.",
    )
    owner_key: str = Field(
        default="ironclaw-system",
        max_length=128,
        description="Logical owner of this key (service or user ID).",
    )
    created_by: str = Field(
        default="system",
        max_length=128,
        description="Identity issuing this key creation request.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary metadata attached to the key record.",
    )

    @field_validator("scopes", mode="before")
    @classmethod
    def _coerce_scopes(cls, v: Any) -> list[Any]:
        if isinstance(v, str):
            return [v]
        return list(v) if v is not None else [Scope.SYSTEM]

    @model_validator(mode="after")
    def _org_key_requires_org_id(self) -> APIKeyCreate:
        if self.key_type == "org" and not self.org_id:
            raise ValueError("org_id is required when key_type='org'.")
        return self

    model_config = {"str_strip_whitespace": True}


class APIKey(BaseModel):
    """Internal read model for an API key record.

    scopes is typed list[Union[Scope, str]] so that the coerce validator
    can pass through unrecognised raw strings without Pydantic re-validating
    them as Scope enum members. This matches the test contract:
    invalid scopes are stored as-is; valid ones are coerced to Scope.
    """

    key_id: str = Field(..., description="Unique key identifier (e.g. key_<hex>).")
    display_name: str = Field(..., description="Human-readable label.")
    masked_key: str = Field(..., description="Partially masked key value (prefix…suffix).")
    fingerprint: str = Field(..., description="SHA-256 hex fingerprint of the raw key.")
    scopes: list[Scope | str] = Field(
        default_factory=list,
        description="Granted permission scopes. Known values are Scope members; unknown values are preserved as raw strings.",
    )
    key_type: str = Field(default="personal", description="'personal' or 'org'.")
    org_id: str | None = Field(default=None, description="Org this key belongs to, if any.")
    owner_key: str = Field(default="ironclaw-system", description="Logical owner.")
    rate_plan: str = Field(default="internal", description="Rate plan identifier.")
    active: bool = Field(default=True, description="Whether the key is currently active.")
    created_at: str = Field(..., description="ISO-8601 UTC creation timestamp.")
    created_by: str = Field(default="system", description="Identity that created the key.")
    last_used_at: str | None = Field(default=None, description="ISO-8601 UTC last-used timestamp.")
    revoked_at: str | None = Field(default=None, description="ISO-8601 UTC revocation timestamp.")
    revoked_by: str | None = Field(default=None, description="Identity that revoked this key.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Attached metadata.")

    @field_validator("scopes", mode="before")
    @classmethod
    def _coerce_scopes(cls, v: Any) -> list[Any]:
        if isinstance(v, (list, tuple, set)):
            result: list[Any] = []
            for item in v:
                try:
                    result.append(Scope(item) if not isinstance(item, Scope) else item)
                except ValueError:
                    result.append(item)
            return result
        return []

    model_config = {"str_strip_whitespace": True}


class APIKeyResponse(BaseModel):
    """External API response model for an API key.

    CONTRACT: raw key is NEVER present in this model.
    """

    key_id: str = Field(..., description="Unique key identifier.")
    display_name: str = Field(..., description="Human-readable label.")
    key_prefix: str = Field(
        ...,
        description="First characters of the key up to the masked boundary (e.g. 'ic_abc'). Never the full key.",
    )
    scopes: list[Scope] = Field(default_factory=list, description="Granted permission scopes.")
    key_type: str = Field(default="personal", description="'personal' or 'org'.")
    org_id: str | None = Field(default=None, description="Org this key belongs to, if any.")
    owner_key: str = Field(default="ironclaw-system", description="Logical owner.")
    rate_plan: str = Field(default="internal", description="Rate plan identifier.")
    active: bool = Field(default=True, description="Whether the key is currently active.")
    created_at: str = Field(..., description="ISO-8601 UTC creation timestamp.")
    created_by: str = Field(default="system", description="Identity that created the key.")
    last_used_at: str | None = Field(default=None, description="ISO-8601 UTC last-used timestamp.")
    revoked_at: str | None = Field(default=None, description="ISO-8601 UTC revocation timestamp.")
    revoked_by: str | None = Field(default=None, description="Identity that revoked this key.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Attached metadata.")

    @classmethod
    def from_record(cls, record: Any) -> APIKeyResponse:
        masked: str = getattr(record, "masked_key", "") or ""
        prefix = masked.split("...")[0] if "..." in masked else masked[:6]

        raw_scopes = getattr(record, "scopes", ()) or ()
        coerced: list[Scope] = []
        for s in raw_scopes:
            try:
                coerced.append(Scope(s) if not isinstance(s, Scope) else s)
            except ValueError:
                pass

        return cls(
            key_id=getattr(record, "key_id", ""),
            display_name=getattr(record, "display_name", ""),
            key_prefix=prefix,
            scopes=coerced,
            key_type=getattr(record, "key_type", "personal"),
            org_id=getattr(record, "org_id", None),
            owner_key=getattr(record, "owner_key", "ironclaw-system"),
            rate_plan=getattr(record, "rate_plan", "internal"),
            active=getattr(record, "active", True),
            created_at=getattr(record, "created_at", ""),
            created_by=getattr(record, "created_by", "system"),
            last_used_at=getattr(record, "last_used_at", None),
            revoked_at=getattr(record, "revoked_at", None),
            revoked_by=getattr(record, "revoked_by", None),
            metadata=dict(getattr(record, "metadata", {}) or {}),
        )

    model_config = {"str_strip_whitespace": True}


class APIKeyIssuance(BaseModel):
    """One-time issuance envelope returned immediately after key creation."""

    raw_key: str = Field(
        ...,
        description="The full API key value. Shown exactly once. Store it securely.",
    )
    key: APIKeyResponse = Field(..., description="Sanitized key record (no raw key).")


class AuthContext(BaseModel):
    """Pydantic schema representation of an authenticated request context."""

    api_key: str | None = Field(
        default=None,
        description="Masked or partial API key value. NEVER the raw key.",
    )
    principal_type: str = Field(
        default="api_key",
        description="Type of principal: 'api_key', 'service', 'anonymous'.",
    )
    principal_id: str | None = Field(
        default=None,
        description="Unique identifier of the authenticated principal.",
    )
    session_id: str | None = Field(
        default=None,
        description="Session identifier if applicable.",
    )
    org_id: str | None = Field(
        default=None,
        description="Organisation identifier if applicable.",
    )
    permissions: list[str] = Field(
        default_factory=list,
        description="Raw permission strings active for this context.",
    )
    roles: list[str] = Field(
        default_factory=list,
        description="Roles assigned to this principal.",
    )
    authenticated: bool = Field(
        default=False,
        description="True when the principal was successfully authenticated.",
    )
    auth_source: str = Field(
        default="none",
        description="Source of authentication: 'api_key', 'registry', 'configured', 'none'.",
    )
    auth_method: str | None = Field(
        default=None,
        description="Specific auth method used (e.g. 'header', 'bearer').",
    )
    key_type: str = Field(
        default="personal",
        description="Key type that was authenticated: 'personal' or 'org'.",
    )
    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Arbitrary string metadata attached to the auth context.",
    )

    @classmethod
    def from_core(cls, ctx: Any) -> AuthContext:
        return cls(
            api_key=getattr(ctx, "api_key", None),
            principal_type=getattr(ctx, "principal_type", "api_key"),
            principal_id=getattr(ctx, "principal_id", None),
            session_id=getattr(ctx, "session_id", None),
            org_id=getattr(ctx, "org_id", None),
            permissions=list(getattr(ctx, "permissions", ())),
            roles=list(getattr(ctx, "roles", ())),
            authenticated=getattr(ctx, "authenticated", False),
            auth_source=getattr(ctx, "auth_source", "none"),
            auth_method=getattr(ctx, "auth_method", None),
            key_type=getattr(ctx, "key_type", "personal"),
            metadata=dict(getattr(ctx, "metadata", {})),
        )

    def has_scope(self, scope: Scope) -> bool:
        return scope.value in self.permissions

    def has_any_scope(self, *scopes: Scope) -> bool:
        return any(self.has_scope(s) for s in scopes)

    def has_all_scopes(self, *scopes: Scope) -> bool:
        return all(self.has_scope(s) for s in scopes)

    def is_admin(self) -> bool:
        return Scope.ADMIN.value in self.permissions or Scope.SYSTEM.value in self.permissions

    model_config = {"str_strip_whitespace": True}


class TokenIntrospection(BaseModel):
    """RFC 7662-aligned token introspection response for IronClaw API keys."""

    active: bool = Field(
        ...,
        description="True if the key is currently valid and usable.",
    )
    key_id: str | None = Field(default=None, description="Unique key identifier.")
    key_prefix: str | None = Field(
        default=None,
        description="Safe displayable prefix of the key (never the raw value).",
    )
    scopes: list[Scope] = Field(default_factory=list, description="Scopes granted to the token.")
    key_type: str | None = Field(default=None, description="'personal' or 'org'.")
    principal_id: str | None = Field(default=None, description="Owning principal identifier.")
    org_id: str | None = Field(default=None, description="Organisation the token belongs to, if any.")
    owner_key: str | None = Field(default=None, description="Logical owner of the key.")
    rate_plan: str | None = Field(default=None, description="Rate plan active for this token.")
    issued_at: str | None = Field(default=None, description="ISO-8601 UTC timestamp when the key was created.")
    last_used_at: str | None = Field(default=None, description="ISO-8601 UTC timestamp of most recent authenticated use.")
    revoked_at: str | None = Field(default=None, description="ISO-8601 UTC revocation timestamp. Present only if revoked.")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Arbitrary metadata attached to the key record.")

    @classmethod
    def inactive(cls) -> TokenIntrospection:
        return cls(active=False)

    @classmethod
    def from_record(cls, record: Any) -> TokenIntrospection:
        if record is None:
            return cls.inactive()

        is_active: bool = bool(getattr(record, "active", False))
        if not is_active:
            return cls(
                active=False,
                key_id=getattr(record, "key_id", None),
                revoked_at=getattr(record, "revoked_at", None),
            )

        masked: str = getattr(record, "masked_key", "") or ""
        prefix = masked.split("...")[0] if "..." in masked else masked[:6]

        raw_scopes = getattr(record, "scopes", ()) or ()
        coerced: list[Scope] = []
        for s in raw_scopes:
            try:
                coerced.append(Scope(s) if not isinstance(s, Scope) else s)
            except ValueError:
                pass

        return cls(
            active=True,
            key_id=getattr(record, "key_id", None),
            key_prefix=prefix or None,
            scopes=coerced,
            key_type=getattr(record, "key_type", "personal"),
            principal_id=getattr(record, "key_id", None),
            org_id=getattr(record, "org_id", None),
            owner_key=getattr(record, "owner_key", None),
            rate_plan=getattr(record, "rate_plan", None),
            issued_at=getattr(record, "created_at", None),
            last_used_at=getattr(record, "last_used_at", None),
            revoked_at=None,
            metadata=dict(getattr(record, "metadata", {}) or {}),
        )

    model_config = {"str_strip_whitespace": True}


__all__ = [
    "Scope",
    "APIKeyCreate",
    "APIKey",
    "APIKeyResponse",
    "APIKeyIssuance",
    "AuthContext",
    "TokenIntrospection",
]
