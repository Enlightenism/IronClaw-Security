from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.adapters.generic_agent_adapter import (
    GenericAgentAdapter,
    build_generic_agent_adapter,
    build_generic_agent_adapter_request,
    evaluate_generic_agent_request,
)
from app.orchestrator.policy_enforcer import (
    TOOL_GUARDED_ACTIONS,
    build_policy_engine,
)
from app.services.integration_registry import initialize_integration_registry
from app.services.secret_scanner import evaluate_secret_scanner_request, scan_for_secrets

router = APIRouter(
    prefix="/integrations/hermes",
    tags=["hermes"],
)

_ADAPTER_VERSION = "1.0.0"
_PLATFORM = "hermes"
_ADAPTER_NAME = "ironclaw-hermes"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _trace_id() -> str:
    return f"hermes-{uuid.uuid4().hex}"


def _build_secret_scan_context(
    *,
    trace_id: str,
    action_type: str,
    target: str,
    client_id: str | None,
    session_id: str | None,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    return {
        "trace_id": trace_id,
        "platform": _PLATFORM,
        "action_type": action_type,
        "target": target,
        "client_id": client_id,
        "session_id": session_id,
        "metadata": metadata,
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
    client_id: str | None,
    session_id: str | None,
    risk_score_input: int,
    risk_score_final: int,
    risk_level: str,
    verdict: str,
    matched_rule_count: int,
    evaluated_at: str,
    metadata: dict[str, Any],
    secret_scan_triggered: bool,
    should_review: bool,
) -> dict[str, Any]:
    return {
        "trace_id": trace_id,
        "decision_id": decision_id,
        "platform": _PLATFORM,
        "adapter_name": _ADAPTER_NAME,
        "action_type": action_type,
        "target": target,
        "client_id": client_id,
        "session_id": session_id,
        "risk_score_input": risk_score_input,
        "risk_score_final": risk_score_final,
        "risk_level": risk_level,
        "verdict": verdict,
        "should_review": should_review,
        "matched_rule_count": matched_rule_count,
        "evaluated_at": evaluated_at,
        "metadata": metadata,
        "secret_scan_triggered": secret_scan_triggered,
    }


def _build_capabilities(*, include_runtime_details: bool = True) -> list[dict[str, Any]]:
    capabilities = [
        {
            "name": "prompt-guard",
            "description": "Inspect Hermes prompts before execution and policy evaluation.",
            "required": True,
        },
        {
            "name": "tool-plan-guard",
            "description": "Validate Hermes tool plans and chained execution steps before dispatch.",
            "required": True,
        },
        {
            "name": "command-guard",
            "description": "Review shell commands and subprocess actions before Hermes dispatches them.",
            "required": True,
        },
        {
            "name": "workspace-guard",
            "description": "Review file reads, writes, edits, and workspace mutations before execution.",
            "required": True,
        },
        {
            "name": "secret-scan",
            "description": "Pre-flight secret scanning on Hermes prompts, actions, and command payloads.",
            "required": True,
        },
        {
            "name": "audit-trail",
            "description": "Persist the Hermes decision trail, matched rules, and risk outcome.",
            "required": True,
        },
        {
            "name": "policy-enforcement",
            "description": "Apply IronClaw policy decisions with allow, warn, quarantine, and block verdicts.",
            "required": True,
        },
    ]
    if include_runtime_details:
        capabilities.extend(
            [
                {
                    "name": "execution-boundary",
                    "description": "Enforce runtime execution boundaries for shell, file, and workflow actions.",
                    "required": False,
                },
                {
                    "name": "workflow-guard",
                    "description": "Review multi-step Hermes workflow plans before actions are dispatched.",
                    "required": False,
                },
            ]
        )
    return capabilities


def _normalize_capabilities(raw_caps: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    standard_caps = _build_capabilities()
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()

    for cap in raw_caps or []:
        if not isinstance(cap, dict):
            continue
        name = str(cap.get("name") or cap.get("capability") or "").strip()
        if not name:
            continue
        normalized = dict(cap)
        normalized["name"] = name
        if name not in seen:
            merged.append(normalized)
            seen.add(name)

    for cap in standard_caps:
        name = str(cap.get("name") or "").strip()
        if name and name not in seen:
            merged.append(dict(cap))
            seen.add(name)

    return merged


def _canonical_adapter_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    normalized = dict(metadata or {})
    normalized["runtime"] = _PLATFORM
    normalized["guard_mode"] = "strict"
    return normalized


def _build_adapter() -> GenericAgentAdapter:
    try:
        registry = initialize_integration_registry()
        record = registry.items.get("integration-hermes")
        if record is not None:
            return GenericAgentAdapter(
                record=record,
                protocol_version=_ADAPTER_VERSION,
                health="ready",
                metadata={"runtime": _PLATFORM, "guard_mode": "strict"},
            )
    except Exception:
        pass

    try:
        registry = initialize_integration_registry()
        return build_generic_agent_adapter(registry)
    except KeyError:
        return GenericAgentAdapter(
            protocol_version=_ADAPTER_VERSION,
            health="ready",
            metadata={"runtime": _PLATFORM, "guard_mode": "strict"},
        )


class HermesEvaluateRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="Hermes runtime action: prompt_submission, tool_plan, shell_command, file_edit, workflow_step, tool_call, or approval.",
        examples=["prompt_submission", "tool_plan", "shell_command", "workflow_step"],
    )
    target: str = Field(
        ...,
        description="Target resource, command, workflow subject, file path, tool name, or API endpoint.",
        examples=["bash", "/workspace/project/app.py", "tool://web-search"],
    )
    content: str = Field(
        default="",
        description="Prompt text, command payload, workflow plan, or execution content associated with the Hermes action.",
    )
    client_id: str | None = Field(
        default=None,
        description="Caller client or agent identifier.",
    )
    session_id: str | None = Field(
        default=None,
        description="Hermes session identifier associated with the runtime call.",
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Caller-supplied risk hint (0-100) used before policy evaluation.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional Hermes runtime, workflow, workspace, and execution metadata.",
    )


class HermesEvaluateResponse(BaseModel):
    trace_id: str
    adapter_name: str
    platform: str
    mode: str
    verdict: str
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
    should_review: bool
    risk_score: int
    risk_level: str
    summary: str
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    decision_id: str | None
    reviewed_at: str
    audit_trail: dict[str, Any]
    secret_scan: dict[str, Any]


class HermesPolicyDecisionResponse(BaseModel):
    trace_id: str
    adapter_name: str
    platform: str
    verdict: str
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
    should_review: bool
    risk_score: int
    risk_level: str
    summary: str
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    decision_id: str | None
    reviewed_at: str
    audit_trail: dict[str, Any]
    metadata: dict[str, Any] = Field(default_factory=dict)


class HermesHandshakeRequest(BaseModel):
    client_id: str | None = Field(
        default=None,
        description="Caller identity for Hermes connection validation.",
    )
    protocol_version: str = Field(
        default="1.0.0",
        description="Requested Hermes protocol version.",
    )
    session_id: str | None = Field(
        default=None,
        description="Hermes session identifier associated with the handshake.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional connection metadata provided by the caller.",
    )


class HermesHandshakeResponse(BaseModel):
    status: str
    platform: str
    adapter_name: str
    protocol_version: str
    integration_health: str
    connected_at: str
    capabilities: list[dict[str, Any]]
    policy_mode: str
    metadata: dict[str, Any]


class HermesManifestResponse(BaseModel):
    adapter_name: str
    platform: str
    protocol_version: str
    supported_action_types: list[str]
    guarded_tool_categories: list[str]
    policy_bindings: dict[str, Any]
    capabilities: list[dict[str, Any]]
    generated_at: str


@router.get(
    "/health",
    status_code=status.HTTP_200_OK,
    summary="Return Hermes integration health",
    description="Returns the Hermes adapter health and the standard runtime guard status.",
)
async def hermes_health() -> dict[str, Any]:
    adapter = _build_adapter()
    return {
        "status": "ok",
        "platform": _PLATFORM,
        "adapter_name": _ADAPTER_NAME,
        "integration_health": adapter.health,
        "protocol_version": _ADAPTER_VERSION,
        "checked_at": _utc_now(),
    }


@router.post(
    "/evaluate",
    response_model=HermesEvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a Hermes action before dispatch",
    description=("Runs a pre-flight secret scan and policy evaluation for Hermes actions before prompts, shell commands, file writes, or workflow steps are dispatched."),
)
async def evaluate_hermes(body: HermesEvaluateRequest) -> HermesEvaluateResponse:
    trace_id = _trace_id()
    scan_payload = f"{body.target}\n{body.content}".strip()
    secret_scan_context = _build_secret_scan_context(
        trace_id=trace_id,
        action_type=body.action_type,
        target=body.target,
        client_id=body.client_id,
        session_id=body.session_id,
        metadata=body.metadata,
    )
    secret_scan_result = _run_secret_scan(scan_payload=scan_payload, context=secret_scan_context)

    if secret_scan_result.get("findings"):
        return HermesEvaluateResponse(
            trace_id=trace_id,
            adapter_name=_ADAPTER_NAME,
            platform=_PLATFORM,
            mode="enforce",
            verdict="block",
            should_allow=False,
            should_warn=False,
            should_quarantine=True,
            should_block=True,
            should_review=True,
            risk_score=100,
            risk_level="critical",
            summary="Secret scan detected sensitive data in the Hermes request payload. Action blocked before dispatch.",
            matched_rules=["secret-scan-pre-flight"],
            reasons=[
                {
                    "rule": "secret-scan-pre-flight",
                    "detail": f"{len(secret_scan_result.get('findings', []))} secret(s) detected in payload.",
                    "findings_count": len(secret_scan_result.get("findings", [])),
                }
            ],
            decision_id=None,
            reviewed_at=_utc_now(),
            audit_trail=_build_audit_trail(
                trace_id=trace_id,
                decision_id=None,
                action_type=body.action_type,
                target=body.target,
                client_id=body.client_id,
                session_id=body.session_id,
                risk_score_input=body.risk_score,
                risk_score_final=100,
                risk_level="critical",
                verdict="block",
                matched_rule_count=1,
                evaluated_at=_utc_now(),
                metadata=body.metadata,
                secret_scan_triggered=True,
                should_review=True,
            ),
            secret_scan=secret_scan_result,
        )

    try:
        adapter_request = build_generic_agent_adapter_request(
            action_type=body.action_type,
            target=body.target,
            content=body.content,
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
        response = evaluate_generic_agent_request(
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

    response.platform = _PLATFORM
    response.adapter_name = _ADAPTER_NAME
    response.metadata["runtime"] = _PLATFORM
    response.metadata["guard_mode"] = "strict"

    audit_trail = _build_audit_trail(
        trace_id=trace_id,
        decision_id=response.decision_id,
        action_type=body.action_type,
        target=body.target,
        client_id=body.client_id,
        session_id=body.session_id,
        risk_score_input=body.risk_score,
        risk_score_final=response.risk_score,
        risk_level=response.risk_level,
        verdict=response.verdict,
        matched_rule_count=len(response.matched_rules),
        evaluated_at=response.reviewed_at,
        metadata=body.metadata,
        secret_scan_triggered=False,
        should_review=response.should_review,
    )

    return HermesEvaluateResponse(
        trace_id=trace_id,
        adapter_name=response.adapter_name,
        platform=response.platform,
        mode=response.mode,
        verdict=response.verdict,
        should_allow=response.should_allow,
        should_warn=response.should_warn,
        should_quarantine=response.should_quarantine,
        should_block=response.should_block,
        should_review=response.should_review,
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
    "/policy-decision",
    response_model=HermesPolicyDecisionResponse,
    status_code=status.HTTP_200_OK,
    summary="Return the normalized policy decision for a Hermes action",
    description="Evaluates a Hermes action and returns the canonical policy verdict, matched rules, and audit trail without mutating the runtime.",
)
async def hermes_policy_decision(body: HermesEvaluateRequest) -> HermesPolicyDecisionResponse:
    response = await evaluate_hermes(body)
    return HermesPolicyDecisionResponse(
        trace_id=response.trace_id,
        adapter_name=response.adapter_name,
        platform=response.platform,
        verdict=response.verdict,
        should_allow=response.should_allow,
        should_warn=response.should_warn,
        should_quarantine=response.should_quarantine,
        should_block=response.should_block,
        should_review=response.should_review,
        risk_score=response.risk_score,
        risk_level=response.risk_level,
        summary=response.summary,
        matched_rules=response.matched_rules,
        reasons=response.reasons,
        decision_id=response.decision_id,
        reviewed_at=response.reviewed_at,
        audit_trail=response.audit_trail,
        metadata={"action_type": body.action_type, "target": body.target},
    )


@router.post(
    "/handshake",
    response_model=HermesHandshakeResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate Hermes integration connection and return health status",
    description=("Validates the Hermes integration connection and returns the adapter health status together with the capability manifest used to guard workflow steps, shell actions, workspace mutations, and tool dispatch."),
)
async def hermes_handshake(body: HermesHandshakeRequest) -> HermesHandshakeResponse:
    adapter = _build_adapter()

    try:
        from app.adapters.base import AdapterExecutionRequest

        handshake_req = AdapterExecutionRequest(
            action_type="handshake",
            target="hermes",
            payload={
                "client_id": body.client_id,
                "protocol_version": body.protocol_version,
                "session_id": body.session_id,
                **body.metadata,
            },
        )
        handshake_result = adapter.execute(handshake_req)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Hermes adapter handshake failed: {exc}",
        ) from exc

    engine = build_policy_engine()
    capabilities = _normalize_capabilities(
        [
            {"name": "prompt-guard", "description": "Guard Hermes prompts before dispatch."},
            {"name": "secret-scan", "description": "Pre-flight scanning of prompt and command payloads."},
            {"name": "workspace-guard", "description": "Review file writes and edits before they are applied."},
            {"name": "command-guard", "description": "Assess shell commands and local process actions."},
            {"name": "audit-trail", "description": "Persist the evaluation trail and risk decision."},
        ]
    )

    adapter_metadata = _canonical_adapter_metadata(getattr(adapter, "metadata", None))

    return HermesHandshakeResponse(
        status="ok",
        platform=_PLATFORM,
        adapter_name=_ADAPTER_NAME,
        protocol_version=_ADAPTER_VERSION,
        integration_health=adapter.health,
        connected_at=_utc_now(),
        capabilities=capabilities,
        policy_mode=engine.mode,
        metadata={
            **adapter_metadata,
            "client_id": body.client_id,
            "session_id": body.session_id,
            "requested_protocol_version": body.protocol_version,
            "handshake_status": handshake_result.status,
            **body.metadata,
        },
    )


@router.get(
    "/manifest",
    response_model=HermesManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Return the Hermes capability manifest and guarded action types",
    description="Returns the supported Hermes action types, policy bindings, and capability manifest used by the IronClaw guardrail layer.",
)
async def hermes_manifest() -> HermesManifestResponse:
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

    hermes_action_types = sorted(
        TOOL_GUARDED_ACTIONS
        | {
            "tool_call",
            "tool_plan",
            "prompt_submission",
            "shell_command",
            "file_edit",
            "workflow_step",
            "approval",
            "message",
        }
    )
    guarded_categories = sorted({action for rule in engine.rules for action in rule.action_types} | TOOL_GUARDED_ACTIONS)
    capabilities = _normalize_capabilities(
        [
            {"name": "prompt-guard", "description": "Guard Hermes prompts before dispatch."},
            {"name": "secret-scan", "description": "Pre-flight scanning of prompt and command payloads."},
            {"name": "workspace-guard", "description": "Review file writes and edits before they are applied."},
            {"name": "command-guard", "description": "Assess shell commands and local process actions."},
            {"name": "audit-trail", "description": "Persist the evaluation trail and risk decision."},
            {"name": "policy-enforcement", "description": "Runtime policy enforcement in active or monitor mode."},
        ]
    )

    return HermesManifestResponse(
        adapter_name=_ADAPTER_NAME,
        platform=_PLATFORM,
        protocol_version=_ADAPTER_VERSION,
        supported_action_types=hermes_action_types,
        guarded_tool_categories=guarded_categories,
        policy_bindings=policy_bindings,
        capabilities=capabilities,
        generated_at=_utc_now(),
    )
