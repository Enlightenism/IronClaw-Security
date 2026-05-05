from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PrincipalReferenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    principal_type: str
    org_id: str | None = None


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


class PrincipalStatusModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    principal_type: str
    org_id: str | None = None
    active: bool = True
    roles: list[str] = Field(default_factory=list)


class PrincipalSummaryModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal_id: str
    principal_type: str
    org_id: str | None = None
    display_name: str | None = None
    active: bool = True


class PrincipalListResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[PrincipalModel] = Field(default_factory=list)
    total: int = 0


class PrincipalResponseModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    principal: PrincipalModel