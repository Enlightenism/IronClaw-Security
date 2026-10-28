from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal
import uuid

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.adapters.claude_code_adapter import (
    ClaudeCodeAdapter,
    build_claude_code_adapter,
    build_claude_code_adapter_request,
    evaluate_claude_code_request,
)
from app.orchestrator.policy_enforcer import (
    TOOL_GUARDED_ACTIONS,
    build_policy_engine,
)
from app.services.integration_registry import initialize_integration_registry
from app.services.secret_scanner import evaluate_secret_scanner_request, scan_for_secrets

router = APIRouter(
    prefix="/integrations/claude-code",
    tags=["claude-code"],
)


_ADAPTER_VERSION = "1.0.0"
_PLATFORM = "claude-code"
_ADAPTER_NAME = "ironclaw-claude-code"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _trace_id() -> str:
    return f"cc-{uuid.uuid4().hex}"


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
    verdict: Literal["allow", "block"],
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
            "name": "tool-call-guard",
            "description": "Guard Claude Code tool calls and command execution through IronClaw policy decisions.",
            "required": True,
        },
        {
            "name": "secret-scan",
            "description": "Pre-flight secret scanning on all inbound prompt, command, and tool-call payloads.",
            "required": True,
        },
        {
            "name": "audit-trail",
            "description": "Persist the full evaluation path, matched rules, and review outcome for each Claude Code action.",
            "required": True,
        },
        {
            "name": "policy-enforcement",
            "description": "Apply runtime policy enforcement with allow and block verdicts.",
            "required": True,
        },
    ]
    if include_runtime_details:
        capabilities.append(
            {
                "name": "execution-boundary",
                "description": "Enforce Claude Code execution boundaries for shell commands, file writes, and network operations.",
                "required": False,
            }
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
    normalized["runtime"] = "claude-code"
    normalized["guard_mode"] = "strict"
    return normalized


def _build_adapter() -> ClaudeCodeAdapter:
    try:
        registry = initialize_integration_registry()
        adapter = build_claude_code_adapter(registry)
    except KeyError:
        adapter = ClaudeCodeAdapter(
            protocol_version=_ADAPTER_VERSION,
            health="ready",
            metadata={"runtime": "claude-code", "guard_mode": "strict"},
        )

    adapter.runtime = "claude-code"
    adapter.guard_mode = "strict"
    adapter.metadata = _canonical_adapter_metadata(getattr(adapter, "metadata", None))
    return adapter


class ClaudeCodeEvaluateRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="Claude Code runtime action type: tool_call, shell_command, file_write, network_request, prompt_submission, workflow_step, approval, or message.",
        examples=["tool_call", "shell_command", "file_write"],
    )
    target: str = Field(
        ...,
        description="Target resource, tool name, file path, or command.",
        examples=["bash"],
    )
    content: str = Field(
        default="",
        description="Full content of the tool call payload or prompt text.",
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
        description="Arbitrary caller metadata attached to the audit trail; includes request, agent, environment, and workflow context.",
    )


class ClaudeCodeEvaluateResponse(BaseModel):
    trace_id: str
    adapter_name: str
    platform: str
    mode: str
    verdict: Literal["allow", "block"]
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


class ClaudeCodeHandshakeRequest(BaseModel):
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
        description="Optional Claude Code session or builder identifier used for correlation.",
    )
    session_id: str | None = Field(
        default=None,
        description="Optional session identifier tied to the handshake context.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional connection metadata, environment details, and request trace context.",
    )


class ClaudeCodeHandshakeResponse(BaseModel):
    status: str
    platform: str
    adapter_name: str
    protocol_version: str
    integration_health: str
    connected_at: str
    capabilities: list[dict[str, Any]]
    policy_mode: str
    metadata: dict[str, Any]


class ClaudeCodeManifestResponse(BaseModel):
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
    response_model=ClaudeCodeEvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a Claude Code tool call or prompt payload",
    description=(
        "Accepts a Claude Code tool call or prompt payload. Runs secret scanning on the incoming content before routing through ClaudeCodeAdapter.execute() backed by the IronClaw policy engine. Returns an allow/block verdict with full reasoning, secret scan results, and an auditable decision trail."
    ),
)
async def evaluate_claude_code(
    body: ClaudeCodeEvaluateRequest,
) -> ClaudeCodeEvaluateResponse:
    trace_id = _trace_id()

    scan_payload = f"{body.target}\n{body.content}".strip()
    secret_scan_result = _run_secret_scan(
        scan_payload=scan_payload,
        context=_build_secret_scan_context(
            trace_id=trace_id,
            action_type=body.action_type,
            target=body.target,
            client_id=body.client_id,
            session_id=body.session_id,
            metadata=body.metadata,
        ),
    )

    secrets_found: list[Any] = secret_scan_result.get("findings", [])
    if secrets_found:
        return ClaudeCodeEvaluateResponse(
            trace_id=trace_id,
            adapter_name=_ADAPTER_NAME,
            platform=_PLATFORM,
            mode="enforce",
            verdict="block",
            should_allow=False,
            should_warn=False,
            should_quarantine=False,
            should_block=True,
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
        adapter_request = build_claude_code_adapter_request(
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
        response = evaluate_claude_code_request(
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

    return ClaudeCodeEvaluateResponse(
        trace_id=trace_id,
        adapter_name=response.adapter_name,
        platform=response.platform,
        mode=response.mode,
        verdict=response.verdict,
        should_allow=response.verdict == "allow",
        should_warn=False,
        should_quarantine=False,
        should_block=response.verdict == "block",
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
    response_model=ClaudeCodeHandshakeResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate Claude Code integration connection and return health manifest",
    description=("Validates the Claude Code integration connection configuration. Returns integration health status and capability manifest so callers can confirm IronClaw is reachable and correctly wired before sending live payloads."),
)
async def claude_code_handshake(
    body: ClaudeCodeHandshakeRequest,
) -> ClaudeCodeHandshakeResponse:
    adapter = _build_adapter()

    try:
        handshake = adapter.handshake()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Claude Code adapter handshake failed: {exc}",
        ) from exc

    engine = build_policy_engine()
    policy_mode = engine.mode

    raw_caps: list[dict[str, Any]] = []
    if hasattr(handshake, "capabilities") and handshake.capabilities:
        for cap in handshake.capabilities:
            raw_caps.append(cap if isinstance(cap, dict) else cap)

    handshake_meta: dict[str, Any] = {}
    if hasattr(handshake, "metadata") and handshake.metadata:
        handshake_meta = _canonical_adapter_metadata(handshake.metadata)

    capabilities = _normalize_capabilities(raw_caps)

    return ClaudeCodeHandshakeResponse(
        status="ok",
        platform=_PLATFORM,
        adapter_name=_ADAPTER_NAME,
        protocol_version=getattr(handshake, "protocol_version", _ADAPTER_VERSION),
        integration_health=getattr(handshake, "status", adapter.health),
        connected_at=getattr(handshake, "connected_at", _utc_now()),
        capabilities=capabilities,
        policy_mode=policy_mode,
        metadata={
            **handshake_meta,
            "client_id": body.client_id,
            "builder_id": body.builder_id,
            "session_id": body.session_id,
            "requested_protocol_version": body.protocol_version,
            **body.metadata,
        },
    )


@router.get(
    "/manifest",
    response_model=ClaudeCodeManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Return Claude Code supported capabilities, guarded tool categories, and policy bindings",
    description=("Returns the full capability manifest for the Claude Code integration: supported action types, guarded tool categories derived from the active policy engine, and policy rule bindings. Consumers use this to understand what IronClaw will guard and how."),
)
async def claude_code_manifest() -> ClaudeCodeManifestResponse:
    adapter = _build_adapter()

    try:
        manifest_data = adapter.manifest()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Claude Code manifest build failed: {exc}",
        ) from exc

    engine = build_policy_engine()

    policy_bindings: dict[str, Any] = {
        "mode": engine.mode,
        "total_rules": len(engine.rules),
        "verdicts": {
            "block": [r.rule_id for r in engine.rules if r.verdict == "block"],
            "quarantine": [],
            "warn": [],
            "allow": [r.rule_id for r in engine.rules if r.verdict == "allow"],
        },
        "tags": sorted({tag for rule in engine.rules for tag in rule.tags}),
    }

    claude_code_action_types = sorted(
        TOOL_GUARDED_ACTIONS
        | {
            "tool_call",
            "prompt_submission",
            "message",
            "approval",
            "http_request",
            "network_request",
        }
    )

    guarded_categories = sorted({action for rule in engine.rules for action in rule.action_types} | TOOL_GUARDED_ACTIONS)

    raw_caps: list[dict[str, Any]] = []
    if manifest_data is not None:
        manifest_meta = _canonical_adapter_metadata(getattr(manifest_data, "metadata", None))
        if hasattr(manifest_data, "metadata"):
            manifest_data.metadata = manifest_meta
        caps_attr = getattr(manifest_data, "capabilities", None)
        if caps_attr:
            for cap in caps_attr:
                raw_caps.append(cap if isinstance(cap, dict) else cap)

    capabilities = _normalize_capabilities(raw_caps)

    return ClaudeCodeManifestResponse(
        adapter_name=_ADAPTER_NAME,
        platform=_PLATFORM,
        protocol_version=_ADAPTER_VERSION,
        supported_action_types=claude_code_action_types,
        guarded_tool_categories=guarded_categories,
        policy_bindings=policy_bindings,
        capabilities=capabilities,
        generated_at=_utc_now(),
    )
