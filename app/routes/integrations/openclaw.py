from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.adapters.openclaw_adapter import (
    OpenClawAdapter,
    build_openclaw_adapter,
    build_openclaw_adapter_request,
    evaluate_openclaw_request,
)
from app.orchestrator.policy_enforcer import (
    TOOL_GUARDED_ACTIONS,
    build_policy_engine,
)
from app.services.integration_registry import initialize_integration_registry
from app.services.secret_scanner import evaluate_secret_scanner_request, scan_for_secrets

router = APIRouter(
    prefix="/integrations/openclaw",
    tags=["openclaw"],
)

_ADAPTER_VERSION = "1.0.0"
_PLATFORM = "openclaw"
_ADAPTER_NAME = "ironclaw-openclaw"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _trace_id() -> str:
    return f"oc-{uuid.uuid4().hex}"


def _build_secret_scan_context(
    *,
    trace_id: str,
    action_type: str,
    target: str,
    builder_id: str | None,
    workflow_id: str | None,
    client_id: str | None,
    session_id: str | None,
) -> dict[str, Any]:
    return {
        "trace_id": trace_id,
        "platform": _PLATFORM,
        "action_type": action_type,
        "target": target,
        "builder_id": builder_id,
        "workflow_id": workflow_id,
        "client_id": client_id,
        "session_id": session_id,
    }


def _run_secret_scan(*, scan_payload: str, context: dict[str, Any]) -> dict[str, Any]:
    try:
        scan_result = evaluate_secret_scanner_request(content=scan_payload, context=context)
        return scan_result if isinstance(scan_result, dict) else scan_result.model_dump()
    except Exception:
        try:
            raw_findings = scan_for_secrets(scan_payload)
            return {
                "findings": raw_findings,
                "scanned": True,
                "source": "fallback",
            }
        except Exception:
            return {"scanned": False, "findings": [], "source": "error"}


def _build_audit_trail(
    *,
    trace_id: str,
    decision_id: str | None,
    action_type: str,
    target: str,
    builder_id: str | None,
    workflow_id: str | None,
    client_id: str | None,
    session_id: str | None,
    risk_score_input: int,
    risk_score_final: int,
    risk_level: str,
    verdict: str,
    should_hold: bool,
    matched_rule_count: int,
    evaluated_at: str,
    metadata: dict[str, Any],
    secret_scan_triggered: bool,
) -> dict[str, Any]:
    return {
        "trace_id": trace_id,
        "decision_id": decision_id,
        "platform": _PLATFORM,
        "adapter_name": _ADAPTER_NAME,
        "action_type": action_type,
        "target": target,
        "builder_id": builder_id,
        "workflow_id": workflow_id,
        "client_id": client_id,
        "session_id": session_id,
        "risk_score_input": risk_score_input,
        "risk_score_final": risk_score_final,
        "risk_level": risk_level,
        "verdict": verdict,
        "should_hold": should_hold,
        "matched_rule_count": matched_rule_count,
        "evaluated_at": evaluated_at,
        "metadata": metadata,
        "secret_scan_triggered": secret_scan_triggered,
    }


def _build_adapter() -> OpenClawAdapter:
    try:
        registry = initialize_integration_registry()
        return build_openclaw_adapter(registry)
    except KeyError:
        from app.services.integration_registry import IntegrationRecord

        fallback_record = IntegrationRecord(
            integration_id="integration-openclaw",
            name="OpenClaw",
            platform=_PLATFORM,
            enabled=True,
            metadata={"runtime": _PLATFORM, "workflow_mode": "builder-guard"},
        )
        return OpenClawAdapter(
            record=fallback_record,
            protocol_version=_ADAPTER_VERSION,
            health="ready",
            metadata={"runtime": _PLATFORM, "workflow_mode": "builder-guard"},
        )


# ---------- Request / Response Models ----------


class OpenClawEvaluateRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="Type of OpenClaw action: tool_call, workflow_step, builder_action, etc.",
        examples=["workflow_step"],
    )
    target: str = Field(
        ...,
        description="Target resource, workflow name, builder node, or tool identifier.",
        examples=["deploy-pipeline"],
    )
    content: str = Field(
        default="",
        description="Full content of the action payload or prompt text.",
    )
    builder_id: str | None = Field(
        default=None,
        description="OpenClaw builder identifier for workflow correlation.",
    )
    workflow_id: str | None = Field(
        default=None,
        description="OpenClaw workflow identifier for audit correlation.",
    )
    client_id: str | None = Field(
        default=None,
        description="Caller agent or client identifier.",
    )
    session_id: str | None = Field(
        default=None,
        description="Session identifier for audit correlation.",
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Caller-supplied risk hint (0–100). Policy engine may escalate.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary caller metadata attached to the audit trail.",
    )


class OpenClawEvaluateResponse(BaseModel):
    trace_id: str
    adapter_name: str
    platform: str
    mode: str
    verdict: str
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
    should_hold: bool
    risk_score: int
    risk_level: str
    summary: str
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    decision_id: str | None
    reviewed_at: str
    audit_trail: dict[str, Any]
    secret_scan: dict[str, Any]


class OpenClawHandshakeRequest(BaseModel):
    client_id: str | None = Field(
        default=None,
        description="Caller identity for connection validation.",
    )
    protocol_version: str = Field(
        default="1.0.0",
        description="Requested protocol version.",
    )
    builder_id: str | None = Field(
        default=None,
        description="OpenClaw builder identifier for handshake context.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional connection metadata.",
    )


class OpenClawHandshakeResponse(BaseModel):
    status: str
    platform: str
    adapter_name: str
    protocol_version: str
    integration_health: str
    connected_at: str
    capabilities: list[dict[str, Any]]
    policy_mode: str
    metadata: dict[str, Any]


class OpenClawManifestResponse(BaseModel):
    adapter_name: str
    platform: str
    protocol_version: str
    supported_action_types: list[str]
    guarded_tool_categories: list[str]
    policy_bindings: dict[str, Any]
    capabilities: list[dict[str, Any]]
    generated_at: str


# ---------- Routes ----------


@router.post(
    "/evaluate",
    response_model=OpenClawEvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate an OpenClaw workflow action or builder payload",
    description=(
        "Accepts an OpenClaw builder or workflow action payload. Runs pre-flight secret "
        "scanning on the incoming content before routing through the IronClaw policy engine. "
        "Returns a verdict (allow/warn/quarantine/block) with the OpenClaw-specific "
        "should_hold flag, full reasoning, secret scan results, and an auditable decision trail."
    ),
)
async def evaluate_openclaw(
    body: OpenClawEvaluateRequest,
) -> OpenClawEvaluateResponse:
    trace_id = _trace_id()

    scan_payload = f"{body.target}\n{body.content}".strip()
    secret_scan_result = _run_secret_scan(
        scan_payload=scan_payload,
        context=_build_secret_scan_context(
            trace_id=trace_id,
            action_type=body.action_type,
            target=body.target,
            builder_id=body.builder_id,
            workflow_id=body.workflow_id,
            client_id=body.client_id,
            session_id=body.session_id,
        ),
    )

    secrets_found: list[Any] = secret_scan_result.get("findings", [])
    if secrets_found:
        return OpenClawEvaluateResponse(
            trace_id=trace_id,
            adapter_name=_ADAPTER_NAME,
            platform=_PLATFORM,
            mode="enforce",
            verdict="block",
            should_allow=False,
            should_warn=False,
            should_quarantine=True,
            should_block=True,
            should_hold=True,
            risk_score=100,
            risk_level="critical",
            summary="Secret scan detected sensitive data in payload. Request blocked before policy evaluation.",
            matched_rules=["secret-scan-pre-flight"],
            reasons=[
                {
                    "rule": "secret-scan-pre-flight",
                    "detail": f"{len(secrets_found)} secret(s) detected in payload.",
                    "findings_count": len(secrets_found),
                }
            ],
            decision_id=None,
            reviewed_at=_utc_now(),
            audit_trail=_build_audit_trail(
                trace_id=trace_id,
                decision_id=None,
                action_type=body.action_type,
                target=body.target,
                builder_id=body.builder_id,
                workflow_id=body.workflow_id,
                client_id=body.client_id,
                session_id=body.session_id,
                risk_score_input=body.risk_score,
                risk_score_final=100,
                risk_level="critical",
                verdict="block",
                should_hold=True,
                matched_rule_count=1,
                evaluated_at=_utc_now(),
                metadata=body.metadata,
                secret_scan_triggered=True,
            ),
            secret_scan=secret_scan_result,
        )

    try:
        adapter_request = build_openclaw_adapter_request(
            action_type=body.action_type,
            target=body.target,
            content=body.content,
            builder_id=body.builder_id,
            workflow_id=body.workflow_id,
            client_id=body.client_id,
            session_id=body.session_id,
            metadata={
                **body.metadata,
                "trace_id": trace_id,
                "session_id": body.session_id,
            },
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=str(exc),
        ) from exc

    engine = build_policy_engine()

    try:
        response = evaluate_openclaw_request(
            engine,
            adapter_request,
            risk_score=body.risk_score,
            mode="enforce",
            trace_id=trace_id,
            metadata=body.metadata,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Policy evaluation failed: {exc}",
        ) from exc

    audit_trail = _build_audit_trail(
        trace_id=trace_id,
        decision_id=response.decision_id,
        action_type=body.action_type,
        target=body.target,
        builder_id=body.builder_id,
        workflow_id=body.workflow_id,
        client_id=body.client_id,
        session_id=body.session_id,
        risk_score_input=body.risk_score,
        risk_score_final=response.risk_score,
        risk_level=response.risk_level,
        verdict=response.verdict,
        should_hold=response.should_hold,
        matched_rule_count=len(response.matched_rules),
        evaluated_at=response.reviewed_at,
        metadata=body.metadata,
        secret_scan_triggered=False,
    )

    return OpenClawEvaluateResponse(
        trace_id=trace_id,
        adapter_name=response.adapter_name,
        platform=response.platform,
        mode=response.mode,
        verdict=response.verdict,
        should_allow=response.should_allow,
        should_warn=response.should_warn,
        should_quarantine=response.should_quarantine,
        should_block=response.should_block,
        should_hold=response.should_hold,
        risk_score=response.risk_score,
        risk_level=response.risk_level,
        summary=response.summary,
        matched_rules=list(response.matched_rules),
        reasons=list(response.reasons),
        decision_id=response.decision_id,
        reviewed_at=response.reviewed_at,
        audit_trail=audit_trail,
        secret_scan=secret_scan_result,
    )


@router.post(
    "/handshake",
    response_model=OpenClawHandshakeResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate OpenClaw integration connection and return health manifest",
    description=("Validates the OpenClaw integration connection configuration. Returns integration health status and capability manifest so callers can confirm IronClaw is reachable and correctly wired before sending live OpenClaw workflow payloads."),
)
async def openclaw_handshake(
    body: OpenClawHandshakeRequest,
) -> OpenClawHandshakeResponse:
    adapter = _build_adapter()

    try:
        from app.adapters.base import AdapterExecutionRequest

        handshake_req = AdapterExecutionRequest(
            action_type="handshake",
            target="ironclaw",
            payload={
                "client_id": body.client_id,
                "protocol_version": body.protocol_version,
                "builder_id": body.builder_id,
                **body.metadata,
            },
        )
        handshake_result = adapter.execute(handshake_req)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"OpenClaw adapter handshake failed: {exc}",
        ) from exc

    engine = build_policy_engine()
    policy_mode = engine.mode

    capabilities: list[dict[str, Any]] = [
        {"name": "workflow-guard", "description": "Gate-keeps OpenClaw builder workflow actions through IronClaw policy"},
        {"name": "secret-scan", "description": "Pre-flight secret scanning on all workflow payloads"},
        {"name": "should-hold", "description": "OpenClaw-specific hold flag for non-allow verdicts"},
        {"name": "audit-trail", "description": "Full auditable decision trail per workflow action"},
    ]

    return OpenClawHandshakeResponse(
        status="ok",
        platform=_PLATFORM,
        adapter_name=_ADAPTER_NAME,
        protocol_version=_ADAPTER_VERSION,
        integration_health=adapter.health,
        connected_at=_utc_now(),
        capabilities=capabilities,
        policy_mode=policy_mode,
        metadata={
            "client_id": body.client_id,
            "builder_id": body.builder_id,
            "requested_protocol_version": body.protocol_version,
            "handshake_status": handshake_result.status,
            **body.metadata,
        },
    )


@router.get(
    "/manifest",
    response_model=OpenClawManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Return OpenClaw supported capabilities, guarded action categories, and policy bindings",
    description=(
        "Returns the full capability manifest for the OpenClaw integration: supported action types, guarded workflow categories derived from the active policy engine, and policy rule bindings. Consumers use this to understand what IronClaw will guard across OpenClaw builder workflows and how."
    ),
)
async def openclaw_manifest() -> OpenClawManifestResponse:
    engine = build_policy_engine()

    policy_bindings: dict[str, Any] = {
        "mode": engine.mode,
        "total_rules": len(engine.rules),
        "verdicts": {
            "block": [r.rule_id for r in engine.rules if r.verdict == "block"],
            "quarantine": [r.rule_id for r in engine.rules if r.verdict == "quarantine"],
            "warn": [r.rule_id for r in engine.rules if r.verdict == "warn"],
            "allow": [r.rule_id for r in engine.rules if r.verdict == "allow"],
        },
        "tags": sorted({tag for rule in engine.rules for tag in rule.tags}),
    }

    openclaw_action_types = sorted(
        TOOL_GUARDED_ACTIONS
        | {
            "tool_call",
            "workflow_step",
            "builder_action",
            "prompt_submission",
            "message",
            "approval",
            "http_request",
            "network_request",
            "deploy_action",
            "config_write",
        }
    )

    guarded_categories = sorted({action for rule in engine.rules for action in rule.action_types} | TOOL_GUARDED_ACTIONS)

    capabilities: list[dict[str, Any]] = [
        {"name": "workflow-guard", "description": "Gate-keeps OpenClaw builder workflow actions through IronClaw policy"},
        {"name": "secret-scan", "description": "Pre-flight secret scanning on all workflow payloads"},
        {"name": "should-hold", "description": "OpenClaw-specific hold flag for non-allow verdicts"},
        {"name": "audit-trail", "description": "Full auditable decision trail per workflow action"},
        {"name": "policy-enforcement", "description": "Runtime policy enforcement with configurable enforce/monitor modes"},
    ]

    return OpenClawManifestResponse(
        adapter_name=_ADAPTER_NAME,
        platform=_PLATFORM,
        protocol_version=_ADAPTER_VERSION,
        supported_action_types=openclaw_action_types,
        guarded_tool_categories=guarded_categories,
        policy_bindings=policy_bindings,
        capabilities=capabilities,
        generated_at=_utc_now(),
    )
