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
    prefix="/integrations/agent-skills",
    tags=["agent-skills"],
)

_ADAPTER_VERSION = "1.0.0"
_PLATFORM = "security-guardian"
_ADAPTER_NAME = "ironclaw-agent-skills"
_PACKAGE_MODEL = "shared-cross-runtime-skill-bundle"
_RUNTIME_SCOPE = "cross-runtime"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _trace_id() -> str:
    return f"skills-{uuid.uuid4().hex}"


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
        "package_model": _PACKAGE_MODEL,
        "runtime_scope": _RUNTIME_SCOPE,
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
        "package_model": _PACKAGE_MODEL,
        "runtime_scope": _RUNTIME_SCOPE,
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
            "name": "skill-package-guard",
            "description": "Inspect the shared security skill package and install bundle before activation.",
            "required": True,
        },
        {
            "name": "bundle-distribution-guard",
            "description": "Review universal security bundle distribution and package-sync operations before they reach a target runtime.",
            "required": True,
        },
        {
            "name": "workflow-bundle-guard",
            "description": "Validate multi-agent security bundles, skill flows, and workflow policies before dispatch.",
            "required": True,
        },
        {
            "name": "tool-policy-guard",
            "description": "Assess tool policies and protected command paths used by the shared Guardian skill package.",
            "required": True,
        },
        {
            "name": "command-guard",
            "description": "Gate command execution, shell tasks, and install automation triggered by the shared skills bundle.",
            "required": True,
        },
        {
            "name": "secret-scan",
            "description": "Pre-flight scanning for sensitive values in manifest files, install payloads, prompts, and command metadata.",
            "required": True,
        },
        {
            "name": "audit-trail",
            "description": "Persist the full security bundle decision trail, matched rules, and review outcome.",
            "required": True,
        },
        {
            "name": "policy-enforcement",
            "description": "Apply IronClaw policy decisions with allow, warn, quarantine, and block verdicts to skill actions.",
            "required": True,
        },
    ]
    if include_runtime_details:
        capabilities.extend(
            [
                {
                    "name": "multi-agent-sync",
                    "description": "Enforce synchronization boundaries for cross-runtime skill package installs and repo-based distribution flows.",
                    "required": False,
                },
                {
                    "name": "workspace-guard",
                    "description": "Review file and repo mutation requests triggered by the Guardian package.",
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
        record = registry.items.get("integration-security-guardian")
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


class AgentSkillsEvaluateRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="Shared skill action type: skill_install, bundle_distribution, workflow_bundle, tool_policy, command_guard, prompt_review, tool_call, or approval.",
        examples=["skill_install", "bundle_distribution", "workflow_bundle", "tool_policy"],
    )
    target: str = Field(
        ...,
        description="Target installation path, bundle ID, command, repo path, or skill family name.",
        examples=["security-guardian", "github.com/org/skills-bundle", "bash"],
    )
    content: str = Field(
        default="",
        description="Previously generated security bundle instructions, prompt payload, command text, or package manifest content.",
    )
    client_id: str | None = Field(
        default=None,
        description="Caller client or agent identifier.",
    )
    session_id: str | None = Field(
        default=None,
        description="Cross-agent session identifier used for audit correlation.",
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Caller-supplied risk hint (0-100).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional security bundle metadata, installation context, and package distribution details.",
    )


class AgentSkillsEvaluateResponse(BaseModel):
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


class AgentSkillsHandshakeRequest(BaseModel):
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
        description="Cross-agent session identifier associated with the handshake.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional shared security skill bundle context and cross-runtime environment details.",
    )


class AgentSkillsHandshakeResponse(BaseModel):
    status: str
    platform: str
    adapter_name: str
    protocol_version: str
    integration_health: str
    connected_at: str
    capabilities: list[dict[str, Any]]
    policy_mode: str
    metadata: dict[str, Any]


class AgentSkillsManifestResponse(BaseModel):
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
    response_model=AgentSkillsEvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a shared security skill bundle or package action",
    description=("Accepts a shared skills package action such as bundle installation, security bundle sync, workflow validation, tool policy enforcement, or command guard review. Runs secret scanning before policy evaluation and returns a verdict with a full audit trail."),
)
async def evaluate_agent_skills(body: AgentSkillsEvaluateRequest) -> AgentSkillsEvaluateResponse:
    trace_id = _trace_id()
    bundle_context = str(body.metadata.get("bundle_id") or body.metadata.get("package_name") or "")
    scan_payload = f"{body.target}\n{body.content}\n{bundle_context}".strip()
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
        return AgentSkillsEvaluateResponse(
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
            summary="Secret scan detected sensitive material in the shared skills payload. Action blocked before dispatch.",
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
            agent_name="security-guardian",
            runtime_name=_PLATFORM,
            client_id=body.client_id,
            session_id=body.session_id,
            metadata={
                **body.metadata,
                "trace_id": trace_id,
                "bundle_id": bundle_context,
                "runtime": _PLATFORM,
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

    return AgentSkillsEvaluateResponse(
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
    response_model=AgentSkillsHandshakeResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate shared skills package health and connection state",
    description=("Validates the shared skills package connection and returns the adapter health and capability manifest used to guard bundle installs, workflow distribution, and package-driven security actions."),
)
async def agent_skills_handshake(body: AgentSkillsHandshakeRequest) -> AgentSkillsHandshakeResponse:
    adapter = _build_adapter()

    try:
        from app.adapters.base import AdapterExecutionRequest

        handshake_req = AdapterExecutionRequest(
            action_type="handshake",
            target="security-guardian",
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
            detail=f"Agent skills adapter handshake failed: {exc}",
        ) from exc

    engine = build_policy_engine()
    capabilities = _normalize_capabilities(
        [
            {"name": "skill-package-guard", "description": "Inspect security skill package bundles before activation."},
            {"name": "bundle-distribution-guard", "description": "Review multi-agent bundle distribution actions."},
            {"name": "workflow-bundle-guard", "description": "Validate aggregated workflow and policy bundles."},
            {"name": "tool-policy-guard", "description": "Guard tool policy enforcement and command automation."},
            {"name": "command-guard", "description": "Review commands and shell actions before execution."},
            {"name": "secret-scan", "description": "Scan prompts and manifests for sensitive data."},
            {"name": "audit-trail", "description": "Persist risk and install decisions."},
        ]
    )

    adapter_metadata = _canonical_adapter_metadata(getattr(adapter, "metadata", None))
    metadata = {
        **adapter_metadata,
        "client_id": body.client_id,
        "session_id": body.session_id,
        "requested_protocol_version": body.protocol_version,
        "handshake_status": handshake_result.status,
        "package_model": _PACKAGE_MODEL,
        "runtime_scope": _RUNTIME_SCOPE,
        **body.metadata,
    }

    return AgentSkillsHandshakeResponse(
        status="ok",
        platform=_PLATFORM,
        adapter_name=_ADAPTER_NAME,
        protocol_version=_ADAPTER_VERSION,
        integration_health=adapter.health,
        connected_at=_utc_now(),
        capabilities=capabilities,
        policy_mode=engine.mode,
        metadata=metadata,
    )


@router.get(
    "/manifest",
    response_model=AgentSkillsManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Return the shared skills package capability manifest and guarded action categories",
    description=("Returns the shared security skills package supported actions, guarded tool categories, and policy bindings used by the IronClaw security engine."),
)
async def agent_skills_manifest() -> AgentSkillsManifestResponse:
    engine = build_policy_engine()

    policy_bindings: dict[str, Any] = {
        "mode": engine.mode,
        "package_model": _PACKAGE_MODEL,
        "runtime_scope": _RUNTIME_SCOPE,
        "total_rules": len(engine.rules),
        "verdicts": {
            "block": [r.rule_id for r in engine.rules if r.verdict == "block"],
            "quarantine": [r.rule_id for r in engine.rules if r.verdict == "quarantine"],
            "warn": [r.rule_id for r in engine.rules if r.verdict == "warn"],
            "allow": [r.rule_id for r in engine.rules if r.verdict == "allow"],
        },
        "tags": sorted({tag for rule in engine.rules for tag in rule.tags}),
    }

    skill_action_types = sorted(
        TOOL_GUARDED_ACTIONS
        | {
            "skill_install",
            "bundle_distribution",
            "workflow_bundle",
            "tool_policy",
            "command_guard",
            "prompt_review",
            "tool_call",
            "approval",
            "message",
            "repository_sync",
            "package_manifest",
            "bundle_validation",
        }
    )
    guarded_categories = sorted({action for rule in engine.rules for action in rule.action_types} | TOOL_GUARDED_ACTIONS)
    capabilities = _normalize_capabilities(
        [
            {"name": "skill-package-guard", "description": "Inspect security skill package bundles before activation."},
            {"name": "bundle-distribution-guard", "description": "Review multi-agent bundle distribution actions."},
            {"name": "workflow-bundle-guard", "description": "Validate aggregated workflow and policy bundles."},
            {"name": "tool-policy-guard", "description": "Guard tool policy enforcement and command automation."},
            {"name": "command-guard", "description": "Review commands and shell actions before execution."},
            {"name": "secret-scan", "description": "Scan prompts and manifests for sensitive data."},
            {"name": "audit-trail", "description": "Persist risk and install decisions."},
            {"name": "policy-enforcement", "description": "Runtime policy enforcement in enforce or monitor mode."},
        ]
    )

    return AgentSkillsManifestResponse(
        adapter_name=_ADAPTER_NAME,
        platform=_PLATFORM,
        protocol_version=_ADAPTER_VERSION,
        supported_action_types=skill_action_types,
        guarded_tool_categories=guarded_categories,
        policy_bindings=policy_bindings,
        capabilities=capabilities,
        generated_at=_utc_now(),
    )
