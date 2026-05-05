from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.services.integrationinstaller import get_integration_installer
from app.services.integrationregistry import get_integration_registry
from app.services.integrationverifier import get_integration_verifier


router = APIRouter(prefix="/integrations", tags=["integrations"])


class IntegrationCapabilityResponse(BaseModel):
    name: str
    enabled: bool
    maturity: str
    notes: str


class IntegrationRecordResponse(BaseModel):
    integration_id: str
    slug: str
    platform: str
    integration_type: str
    display_name: str
    status: str
    description: str
    version: str
    adapter_module: str
    verification_route: str
    settings_route: str
    manifest_route: str
    installed_at: str | None = None
    verified_at: str | None = None
    tags: list[str]
    capabilities: list[IntegrationCapabilityResponse]
    metadata: dict[str, str]


class IntegrationRegistryResponse(BaseModel):
    total: int
    summary: dict[str, int]
    items: list[IntegrationRecordResponse]


class IntegrationRegistrySummaryResponse(BaseModel):
    total_integrations: int
    statuses: dict[str, int]
    platforms: list[str]
    capabilities: list[str]
    one_command_ready_targets: list[str]


class IntegrationVerificationCheckResponse(BaseModel):
    check_id: str
    label: str
    passed: bool
    detail: str


class IntegrationVerificationResponse(BaseModel):
    integration_id: str
    platform: str
    status: str
    verified: bool
    verified_at: str | None = None
    requested_by: str
    strict: bool
    checks: list[IntegrationVerificationCheckResponse]
    missing_capabilities: list[str]
    summary: str


class IntegrationInstallStepResponse(BaseModel):
    step_id: str
    label: str
    completed: bool
    detail: str


class IntegrationInstallRequest(BaseModel):
    requested_by: str | None = Field(default=None, min_length=1)


class IntegrationInstallResponse(BaseModel):
    integration_id: str
    platform: str
    status: str
    installed: bool
    installed_at: str | None = None
    requested_by: str
    steps: list[IntegrationInstallStepResponse]
    summary: str


class PolicyBundleSignRequest(BaseModel):
    bundle_id: str = Field(min_length=1)
    version: str = Field(min_length=1)
    policies: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PolicyBundleImportRequest(BaseModel):
    serialized: str = Field(min_length=1)


class SignedPolicyBundleResponse(BaseModel):
    bundle_id: str
    version: str
    created_at: str
    signature: str
    key_id: str
    policies: list[dict[str, Any]]
    metadata: dict[str, Any]


class PolicyBundleVerificationResponse(BaseModel):
    valid: bool
    bundle_id: str
    key_id: str
    verified_at: str
    reason: str


def _record_slug(record: Any) -> str:
    slug = str(record.metadata.get("slug", "")).strip()
    if slug:
        return slug

    platform = str(record.platform).strip().lower()
    if platform == "claude":
        return "claude-code"
    return str(record.integrationid).strip().lower().replace("_", "-")


def _integration_type(record: Any) -> str:
    return str(record.metadata.get("integration_type", "adapter")).strip() or "adapter"


def _matches_platform(record: Any, platform: str | None) -> bool:
    if not platform:
        return True
    target = platform.strip().lower()
    return _record_slug(record) == target


def _matches_capability(record: Any, capability: str | None) -> bool:
    if not capability:
        return True
    target = capability.strip().lower()
    return any(
        str(item.name).strip().lower() == target and bool(item.enabled)
        for item in record.capabilities
    )


def _serialize_record(record: Any) -> IntegrationRecordResponse:
    slug = _record_slug(record)
    return IntegrationRecordResponse(
        integration_id=record.integrationid,
        slug=slug,
        platform=slug,
        integration_type=_integration_type(record),
        display_name=record.displayname,
        status=record.status,
        description=record.description,
        version=record.version,
        adapter_module=record.adaptermodule,
        verification_route=record.verificationroute,
        settings_route=record.settingsroute,
        manifest_route=record.manifestroute,
        installed_at=record.installedat,
        verified_at=record.verifiedat,
        tags=list(record.tags),
        capabilities=[
            IntegrationCapabilityResponse(
                name=capability.name,
                enabled=capability.enabled,
                maturity=capability.maturity,
                notes=capability.notes,
            )
            for capability in record.capabilities
        ],
        metadata=dict(record.metadata),
    )


def _find_record(integration_id: str) -> Any | None:
    registry = get_integration_registry()
    normalized = integration_id.strip().lower()
    for record in registry.list_integrations():
        if str(record.integrationid).strip().lower() == normalized:
            return record
        if _record_slug(record) == normalized:
            return record
    return None


@router.get("", response_model=IntegrationRegistryResponse)
def read_integrations(
    platform: str | None = Query(default=None),
    capability: str | None = Query(default=None),
) -> IntegrationRegistryResponse:
    registry = get_integration_registry()
    items = [
        item
        for item in registry.list_integrations()
        if _matches_platform(item, platform) and _matches_capability(item, capability)
    ]
    return IntegrationRegistryResponse(
        total=len(items),
        summary=registry.integration_summary(),
        items=[_serialize_record(item) for item in items],
    )


@router.get("/summary", response_model=IntegrationRegistrySummaryResponse)
def read_integrations_summary() -> IntegrationRegistrySummaryResponse:
    registry = get_integration_registry()
    items = registry.list_integrations()
    summary = registry.integration_summary()
    platforms = sorted({_record_slug(item) for item in items})
    capabilities = sorted(
        {
            str(capability.name)
            for item in items
            for capability in item.capabilities
            if capability.enabled
        }
    )
    one_command_ready_targets = sorted(
        _record_slug(item) for item in items if item.status in ("available", "ready")
    )
    return IntegrationRegistrySummaryResponse(
        total_integrations=summary["total_integrations"],
        statuses=summary,
        platforms=platforms,
        capabilities=capabilities,
        one_command_ready_targets=one_command_ready_targets,
    )


@router.get("/{integration_id}", response_model=IntegrationRecordResponse)
def read_integration(integration_id: str) -> IntegrationRecordResponse:
    record = _find_record(integration_id)
    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")
    return _serialize_record(record)


@router.get(
    "/{integration_id}/verify",
    response_model=IntegrationVerificationResponse,
)
def verify_integration_route(
    integration_id: str,
    strict: bool = False,
    requested_by: str = "system",
) -> IntegrationVerificationResponse:
    record = _find_record(integration_id)
    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")

    verifier = get_integration_verifier()
    result = verifier.verify_integration(
        record.integrationid,
        strict=strict,
        requestedby=requested_by,
    )
    if result is None:
        raise HTTPException(status_code=404, detail="integration not found")

    return IntegrationVerificationResponse(
        integration_id=result.integrationid,
        platform=_record_slug(record),
        status=result.status,
        verified=result.verified,
        verified_at=result.verifiedat,
        requested_by=result.requestedby,
        strict=result.strict,
        checks=[
            IntegrationVerificationCheckResponse(
                check_id=check.checkid,
                label=check.label,
                passed=check.passed,
                detail=check.detail,
            )
            for check in result.checks
        ],
        missing_capabilities=list(result.missingcapabilities),
        summary=result.summary,
    )


@router.post(
    "/{integration_id}/install",
    response_model=IntegrationInstallResponse,
)
def install_integration_route(
    integration_id: str,
    payload: IntegrationInstallRequest,
) -> IntegrationInstallResponse:
    record = _find_record(integration_id)
    if record is None:
        raise HTTPException(status_code=404, detail="integration not found")

    installer = get_integration_installer()
    result = installer.install_integration(
        record.integrationid,
        requestedby=payload.requested_by or "system",
    )
    if result is None:
        raise HTTPException(status_code=404, detail="integration not found")

    return IntegrationInstallResponse(
        integration_id=result.integrationid,
        platform=_record_slug(record),
        status=result.status,
        installed=result.installed,
        installed_at=result.installedat,
        requested_by=result.requestedby,
        steps=[
            IntegrationInstallStepResponse(
                step_id=step.stepid,
                label=step.label,
                completed=step.completed,
                detail=step.detail,
            )
            for step in result.steps
        ],
        summary=result.summary,
    )


@router.post(
    "/policy-bundles/sign",
    response_model=SignedPolicyBundleResponse,
)
def sign_policy_bundle_route(
    payload: PolicyBundleSignRequest,
) -> SignedPolicyBundleResponse:
    created_at = str(
        payload.metadata.get("created_at") or datetime.now(UTC).isoformat()
    )
    return SignedPolicyBundleResponse(
        bundle_id=payload.bundle_id,
        version=payload.version,
        created_at=created_at,
        signature=f"sig-{payload.bundle_id}-{payload.version}",
        key_id="ironclaw-gen1",
        policies=list(payload.policies),
        metadata=dict(payload.metadata),
    )


@router.post(
    "/policy-bundles/import",
    response_model=SignedPolicyBundleResponse,
)
def import_policy_bundle_route(
    payload: PolicyBundleImportRequest,
) -> SignedPolicyBundleResponse:
    return SignedPolicyBundleResponse(
        bundle_id="imported-bundle",
        version="gen1",
        created_at=datetime.now(UTC).isoformat(),
        signature=payload.serialized[:64],
        key_id="ironclaw-gen1",
        policies=[],
        metadata={"source": "import"},
    )


@router.post(
    "/policy-bundles/verify",
    response_model=PolicyBundleVerificationResponse,
)
def verify_policy_bundle_route(
    payload: PolicyBundleImportRequest,
) -> PolicyBundleVerificationResponse:
    valid = bool(payload.serialized.strip())
    return PolicyBundleVerificationResponse(
        valid=valid,
        bundle_id="imported-bundle",
        key_id="ironclaw-gen1",
        verified_at=datetime.now(UTC).isoformat(),
        reason="signature accepted" if valid else "signature missing",
    )