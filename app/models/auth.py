from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AuthContextModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authenticated: bool = False
    principal_id: str | None = None
    principal_type: str = "anonymous"
    org_id: str | None = None
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    session_id: str | None = None
    auth_method: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class PrincipalModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    principal_type: str
    org_id: str | None = None
    email: str | None = None
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)
    active: bool = True
    service_name: str | None = None
    metadata: dict[str, str] = Field(default_factory=dict)


class SessionPrincipalModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    principal_type: str
    org_id: str | None = None
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)


class SessionPolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    idle_timeout_seconds: int = 1800
    absolute_timeout_seconds: int = 43200
    renewal_window_seconds: int = 300
    require_ip_binding: bool = False
    require_user_agent_binding: bool = True
    enforce_secret_rotation: bool = True


class SessionRecordModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str
    principal: SessionPrincipalModel
    secret_fingerprint: str
    issued_at: str
    expires_at: str
    idle_expires_at: str
    last_seen_at: str
    created_ip: str | None = None
    last_ip: str | None = None
    user_agent: str | None = None
    rotated_at: str | None = None
    revoked_at: str | None = None
    revocation_reason: str | None = None
    active: bool = True
    metadata: dict[str, str] = Field(default_factory=dict)


class SessionValidationModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    valid: bool
    reason: str
    session_id: str | None = None
    principal_id: str | None = None
    org_id: str | None = None
    should_rotate: bool = False
    metadata: dict[str, str] = Field(default_factory=dict)


class AuthResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authenticated: bool
    context: AuthContextModel
    principal: PrincipalModel | None = None
    session: SessionRecordModel | None = None
    validation: SessionValidationModel | None = None
    reason: str = "unknown"


class AuthResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool = True
    auth: AuthResultModel


class PrincipalResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal: PrincipalModel


class PermissionResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    authorized: bool
    scope: str
    principal_id: str | None = None
    org_id: str | None = None
    permissions: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)