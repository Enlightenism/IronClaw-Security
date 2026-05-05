from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class PermissionDecisionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    permission: str
    principal_id: str | None = None
    principal_type: str
    org_id: str | None = None
    reason: str
    matched_permissions: list[str] = Field(default_factory=list)
    matched_roles: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class AccessControlDecisionModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    action: str
    principal_id: str | None = None
    principal_type: str
    org_id: str | None = None
    reason: str
    permission: str | None = None
    required_roles: list[str] = Field(default_factory=list)
    matched_roles: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class PermissionServiceResultModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    scope: str
    reason: str
    principal_id: str | None = None
    org_id: str | None = None
    permissions: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)


class PermissionRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    permission: str
    resource_org_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class AccessControlRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: str
    required_permission: str | None = None
    required_roles: list[str] = Field(default_factory=list)
    resource_org_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class RolePermissionsModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role_name: str
    permissions: list[str] = Field(default_factory=list)


class PermissionSummaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str | None = None
    org_id: str | None = None
    authenticated: bool = False
    permissions: list[str] = Field(default_factory=list)
    roles: list[str] = Field(default_factory=list)