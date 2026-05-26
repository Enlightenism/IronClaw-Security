from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/docs",
    tags=["docs-authentication"],
)


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


class DocsAuthKeyNamingView(BaseModel):
    prefix_pattern: str
    example_key: str
    description: str


class DocsAuthScopeView(BaseModel):
    scope_id: str
    label: str
    description: str
    environments: list[str] = Field(default_factory=list)


class DocsAuthErrorShapeView(BaseModel):
    http_status: int
    error_code: str
    condition: str
    example_body: dict[str, str] = Field(default_factory=dict)


class DocsAuthRotationStepView(BaseModel):
    stepid: str
    label: str
    description: str


class DocsAuthUiSurfaceView(BaseModel):
    surface_id: str
    label: str
    path: str
    description: str


class DocsAuthenticationPageResponse(BaseModel):
    generatedat: str
    headline: str
    intro: str
    header_name: str
    header_example: str
    key_naming: DocsAuthKeyNamingView
    scopes: list[DocsAuthScopeView] = Field(default_factory=list)
    error_shapes: list[DocsAuthErrorShapeView] = Field(default_factory=list)
    rotation_steps: list[DocsAuthRotationStepView] = Field(default_factory=list)
    ui_surfaces: list[DocsAuthUiSurfaceView] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


def _build_scopes() -> list[DocsAuthScopeView]:
    return [
        DocsAuthScopeView(
            scope_id="scan-write",
            label="scan:write",
            description="Submit guarded action and execution requests. Required for all protection-path calls.",
            environments=["local", "staging", "production"],
        ),
        DocsAuthScopeView(
            scope_id="history-read",
            label="history:read",
            description="Read scan history, audit events, and action outcomes.",
            environments=["local", "staging", "production"],
        ),
        DocsAuthScopeView(
            scope_id="policy-read",
            label="policy:read",
            description="Read active policy configuration, thresholds, and rule definitions.",
            environments=["staging", "production"],
        ),
        DocsAuthScopeView(
            scope_id="policy-write",
            label="policy:write",
            description="Update policy thresholds, rules, and environment overrides. Operator-level access only.",
            environments=["production"],
        ),
        DocsAuthScopeView(
            scope_id="billing-read",
            label="billing:read",
            description="Read billing summaries, usage records, and wallet state.",
            environments=["production"],
        ),
        DocsAuthScopeView(
            scope_id="admin-write",
            label="admin:write",
            description="Manage operators, roles, and protected environment configuration. Restricted to admin keys.",
            environments=["production"],
        ),
    ]


def _build_error_shapes() -> list[DocsAuthErrorShapeView]:
    return [
        DocsAuthErrorShapeView(
            http_status=401,
            error_code="UNAUTHORIZED",
            condition="X-API-Key header is missing or the key value is invalid, expired, or revoked.",
            example_body={
                "detail": "Invalid or missing API key.",
                "error_code": "UNAUTHORIZED",
                "status": "401",
            },
        ),
        DocsAuthErrorShapeView(
            http_status=403,
            error_code="FORBIDDEN",
            condition="Key is valid and active but does not carry the scope required by the requested route.",
            example_body={
                "detail": "API key does not have the required scope for this operation.",
                "error_code": "FORBIDDEN",
                "required_scope": "policy:write",
                "status": "403",
            },
        ),
    ]


def _build_rotation_steps() -> list[DocsAuthRotationStepView]:
    return [
        DocsAuthRotationStepView(
            stepid="generate-new",
            label="Generate a new key",
            description="Create a new scoped API key from the Customer Keys surface (/ui/customer-keys) or via POST /customer-keys. The new key secret is shown exactly once at creation time.",
        ),
        DocsAuthRotationStepView(
            stepid="update-header",
            label="Update the X-API-Key header",
            description="Replace the old key value with the new key value in all consuming agents, services, or runtime configurations. Verify at least one successful guarded request passes with the new key before proceeding.",
        ),
        DocsAuthRotationStepView(
            stepid="revoke-old",
            label="Revoke the old key",
            description="Revoke the previous key via POST /customer-keys/{key_id}/revoke. The revoked key remains visible in the audit trail but will return 401 on any future request.",
        ),
    ]


def _build_ui_surfaces() -> list[DocsAuthUiSurfaceView]:
    return [
        DocsAuthUiSurfaceView(
            surface_id="customer-keys",
            label="Customer Keys",
            path="/ui/customer-keys",
            description="Primary surface for creating, listing, and revoking customer-scoped API keys. Shows key status, scope, environment, and rotation posture.",
        ),
        DocsAuthUiSurfaceView(
            surface_id="customer-key-detail",
            label="Customer Key Detail",
            path="/ui/customer-keys/detail/{key_id}",
            description="Focused view of a single key showing owner, usage metrics, scope policy, and available actions including revocation.",
        ),
        DocsAuthUiSurfaceView(
            surface_id="admin-operators",
            label="Operator Management",
            path="/ui/admin/operators",
            description="Admin surface for provisioning operator-level keys and assigning elevated scopes including policy:write and admin:write.",
        ),
        DocsAuthUiSurfaceView(
            surface_id="settings-configuration",
            label="Settings / Configuration",
            path="/ui/settings/configuration",
            description="Environment configuration surface where runtime key bindings and environment-specific overrides are managed.",
        ),
    ]


@router.get("/authentication", response_model=DocsAuthenticationPageResponse)
def get_docs_authentication() -> DocsAuthenticationPageResponse:
    return DocsAuthenticationPageResponse(
        generatedat=_utc_now(),
        headline="Authenticating with IronClaw",
        intro=("Every request to a protected IronClaw route must carry a valid API key in the X-API-Key header. " "Keys are scoped to environments and capabilities. A missing or invalid key returns 401. " "A valid key without the required scope returns 403."),
        header_name="X-API-Key",
        header_example="X-API-Key: ic_prod_your_generated_key",
        key_naming=DocsAuthKeyNamingView(
            prefix_pattern="ic_{environment}_{identifier}",
            example_key="ic_prod_a1b2c3d4e5f6",
            description=(
                "Keys are prefixed with ic_ followed by the environment tier (prod, staging, local) "
                "and a unique identifier. The full secret is shown exactly once at creation and is never retrievable afterwards. "
                "Masked representations (e.g. ic_prod_a1b2...f6) are used in all UI and audit surfaces."
            ),
        ),
        scopes=_build_scopes(),
        error_shapes=_build_error_shapes(),
        rotation_steps=_build_rotation_steps(),
        ui_surfaces=_build_ui_surfaces(),
        notes=[
            "API keys are the sole authentication mechanism for IronClaw runtime routes in Gen1.",
            "Scopes are enforced at the route level. Requesting a route without the required scope returns 403 regardless of key validity.",
            "Revoked keys are retained in the audit trail for operator review but are permanently blocked from authenticating.",
            "Key secrets are shown exactly once at creation. Store the secret immediately in a secrets manager or environment variable.",
            "All values reflect the current local-first Gen1 build. Environment-aware key discovery will expand in later generations.",
        ],
    )
