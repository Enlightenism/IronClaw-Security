from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.adapters.generic_agent_adapter import (
    GenericAgentAdapter,
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
    prefix="/integrations/goose",
    tags=["goose"],
)

_ADAPTER_VERSION = "1.0.0"
_PLATFORM = "goose"
_ADAPTER_NAME = "ironclaw-goose"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _trace_id() -> str:
    return f"goose-{uuid.uuid4().hex}"


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
        "matched_rule_count": matched_rule_count,
        "evaluated_at": evaluated_at,
        "metadata": metadata,
        "secret_scan_triggered": secret_scan_triggered,
    }


def _build_capabilities(*, include_runtime_details: bool = True) -> list[dict[str, Any]]:
    capabilities = [
        {
            "name": "prompt-guard",
            "description": "Inspect Goose prompts before execution and policy evaluation.",
            "required": True,
        },
        {
            "name": "tool-plan-guard",
            "description": "Validate Goose tool plans and chained execution steps before dispatch.",
            "required": True,
        },
        {
            "name": "shell-guard",
            "description": "Review shell and subprocess commands before Goose sends them to the runtime.",
            "required": True,
        },
        {
            "name": "plugin-call-guard",
            "description": "Intercept Goose plugin and extension executions before the runtime acts on them.",
            "required": True,
        },
        {
            "name": "secret-scan",
            "description": "Pre-flight secret scanning on Goose prompts, tool payloads, shell content, and plugin arguments.",
            "required": True,
        },
        {
            "name": "audit-trail",
            "description": "Persist the full Goose decision trail, matched rules, and risk outcome.",
            "required": True,
        },
        {
            "name": "policy-enforcement",
            "description": "Apply IronClaw policy enforcement with allow, warn, quarantine, and block verdicts.",
            "required": True,
        },
    ]
    if include_runtime_details:
        capabilities.extend(
            [
                {
                    "name": "execution-boundary",
                    "description": "Enforce Goose execution boundaries across shell, plugin, and local tool calls.",
                    "required": False,
                },
                {
                    "name": "http-tool-guard",
                    "description": "Review local HTTP and tool-call actions before outbound dispatch.",
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
        record = registry.items.get("integration-goose")
        if record is not None:
            return GenericAgentAdapter(
                record=record,
                protocol_version=_ADAPTER_VERSION,
                health="ready",
                metadata={"runtime": _PLATFORM, "guard_mode": "strict"},
            )
    except Exception:
        pass

    return GenericAgentAdapter(
        protocol_version=_ADAPTER_VERSION,
        health="ready",
        metadata={"runtime": _PLATFORM, "guard_mode": "strict"},
    )


class GooseEvaluateRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="Goose action type: prompt_submission, tool_plan, shell_command, plugin_call, tool_call, or message.",
        examples=["prompt_submission", "tool_plan", "shell_command", "plugin_call"],
    )
    target: str = Field(
        ...,
        description="Target resource, plugin name, tool name, command, or prompt subject.",
        examples=["bash", "nonebot.plugin.tools", "tool-plan://run-build"],
    )
    content: str = Field(
        default="",
        description="Prompt text, tool plan, shell payload, or plugin call arguments.",
    )
    client_id: str | None = Field(
        default=None,
        description="Caller client or agent identifier.",
    )
    session_id: str | None = Field(
        default=None,
        description="Goose session identifier for audit correlation.",
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Caller-supplied risk hint (0-100).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional Goose runtime, workflow, and execution metadata.",
    )


class GooseEvaluateResponse(BaseModel):
    trace_id: str
    adapter_name: str
    platform: str
    mode: str
    verdict: str
    should_allow: bool
    should_warn: bool
    should_quarantine: bool
    should_block: bool
    risk_score: int
    risk_level: str
    summary: str
    matched_rules: list[str]
    reasons: list[dict[str, Any]]
    decision_id: str | None
    reviewed_at: str
    audit_trail: dict[str, Any]
    secret_scan: dict[str, Any]


class GooseHandshakeRequest(BaseModel):
    client_id: str | None = Field(
        default=None,
        description="Caller identity for connection validation.",
    )
    protocol_version: str = Field(
        default="1.0.0",
        description="Requested protocol version.",
    )
    session_id: str | None = Field(
        default=None,
        description="Goose session identifier associated with the handshake.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional connection metadata and runtime context.",
    )


class GooseHandshakeResponse(BaseModel):
    status: str
    platform: str
    adapter_name: str
    protocol_version: str
    integration_health: str
    connected_at: str
    capabilities: list[dict[str, Any]]
    policy_mode: str
    metadata: dict[str, Any]


class GooseManifestResponse(BaseModel):
    adapter_name: str
    platform: str
    protocol_version: str
    supported_action_types: list[str]
    guarded_tool_categories: list[str]
    policy_bindings: dict[str, Any]
    capabilities: list[dict[str, Any]]
    generated_at: str


@router.post(
    "/evaluate",
    response_model=GooseEvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a Goose prompt, tool plan, shell command, or plugin action",
    description=("Accepts a Goose prompt, tool plan, shell command, or plugin-call payload. Runs secret scanning on the incoming content before policy evaluation and returns a verdict with a full audit trail."),
)
async def evaluate_goose(body: GooseEvaluateRequest) -> GooseEvaluateResponse:
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
        return GooseEvaluateResponse(
            trace_id=trace_id,
            adapter_name=_ADAPTER_NAME,
            platform=_PLATFORM,
            mode="enforce",
            verdict="block",
            should_allow=False,
            should_warn=False,
            should_quarantine=True,
            should_block=True,
            risk_score=100,
            risk_level="critical",
            summary="Secret scan detected sensitive data in the Goose payload. Action blocked before dispatch.",
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
    response.metadata = _canonical_adapter_metadata(response.metadata)

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
    )

    return GooseEvaluateResponse(
        trace_id=trace_id,
        adapter_name=response.adapter_name,
        platform=response.platform,
        mode=response.mode,
        verdict=response.verdict,
        should_allow=response.should_allow,
        should_warn=response.should_warn,
        should_quarantine=response.should_quarantine,
        should_block=response.should_block,
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
    response_model=GooseHandshakeResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate Goose integration health and connection state",
    description=("Validates the Goose integration connection and returns the adapter health and runtime capability manifest used to guard prompts, shell actions, and plugin calls."),
)
async def goose_handshake(body: GooseHandshakeRequest) -> GooseHandshakeResponse:
    adapter = _build_adapter()

    try:
        from app.adapters.base import AdapterExecutionRequest

        handshake_req = AdapterExecutionRequest(
            action_type="handshake",
            target="goose",
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
            detail=f"Goose adapter handshake failed: {exc}",
        ) from exc

    engine = build_policy_engine()
    capabilities = _normalize_capabilities(
        [
            {"name": "prompt-guard", "description": "Inspect Goose prompts before execution."},
            {"name": "tool-plan-guard", "description": "Validate tool plans and chained commands."},
            {"name": "shell-guard", "description": "Review shell commands before dispatch."},
            {"name": "plugin-call-guard", "description": "Guard plugin and extension calls."},
            {"name": "secret-scan", "description": "Pre-flight scanning of prompt and command payloads."},
            {"name": "audit-trail", "description": "Persist the decision trail."},
        ]
    )

    adapter_metadata = _canonical_adapter_metadata(getattr(adapter, "metadata", None))

    return GooseHandshakeResponse(
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
    response_model=GooseManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Return Goose capability manifest and guarded action categories",
    description=("Returns Goose supported action types, guarded tool categories, and policy bindings used by the IronClaw guardrail layer."),
)
async def goose_manifest() -> GooseManifestResponse:
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

    goose_action_types = sorted(
        TOOL_GUARDED_ACTIONS
        | {
            "prompt_submission",
            "tool_plan",
            "shell_command",
            "plugin_call",
            "tool_call",
            "message",
            "approval",
            "network_request",
            "http_request",
            "local_tool_action",
        }
    )
    guarded_categories = sorted({action for rule in engine.rules for action in rule.action_types} | TOOL_GUARDED_ACTIONS)
    capabilities = _normalize_capabilities(
        [
            {"name": "prompt-guard", "description": "Inspect Goose prompts before execution."},
            {"name": "tool-plan-guard", "description": "Validate tool plans and chained commands."},
            {"name": "shell-guard", "description": "Review shell commands before dispatch."},
            {"name": "plugin-call-guard", "description": "Guard plugin and extension calls."},
            {"name": "secret-scan", "description": "Pre-flight scanning of prompt and command payloads."},
            {"name": "audit-trail", "description": "Persist the decision trail."},
            {"name": "policy-enforcement", "description": "Runtime policy enforcement in enforce or monitor mode."},
        ]
    )

    return GooseManifestResponse(
        adapter_name=_ADAPTER_NAME,
        platform=_PLATFORM,
        protocol_version=_ADAPTER_VERSION,
        supported_action_types=goose_action_types,
        guarded_tool_categories=guarded_categories,
        policy_bindings=policy_bindings,
        capabilities=capabilities,
        generated_at=_utc_now(),
    )
