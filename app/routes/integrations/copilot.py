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
    prefix="/integrations/copilot",
    tags=["copilot"],
)

_ADAPTER_VERSION = "1.0.0"
_PLATFORM = "copilot"
_ADAPTER_NAME = "ironclaw-copilot"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _trace_id() -> str:
    return f"copilot-{uuid.uuid4().hex}"


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
            "description": "Inspect Copilot prompts and generated code context before execution.",
            "required": True,
        },
        {
            "name": "code-execution-guard",
            "description": "Review code execution and terminal task requests before Copilot dispatches them.",
            "required": True,
        },
        {
            "name": "shell-task-guard",
            "description": "Assess shell workflows, dev tasks, and repository automation before they run.",
            "required": True,
        },
        {
            "name": "test-run-guard",
            "description": "Gate test execution, quality checks, and command-based validation during Copilot workflows.",
            "required": True,
        },
        {
            "name": "file-edit-plan-guard",
            "description": "Review file modification plans and patch intent before Copilot edits the workspace.",
            "required": True,
        },
        {
            "name": "secret-scan",
            "description": "Pre-flight scanning for sensitive data in Copilot prompts, terminal output, and edit plans.",
            "required": True,
        },
        {
            "name": "audit-trail",
            "description": "Persist the full Copilot decision path, matched rules, and review outcome.",
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
                    "description": "Enforce Copilot execution boundaries for code, shell, and repo actions.",
                    "required": False,
                },
                {
                    "name": "workspace-guard",
                    "description": "Review file and repository mutation plans before patch application.",
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


def _build_adapter() -> GenericAgentAdapter:
    try:
        registry = initialize_integration_registry()
        return build_generic_agent_adapter(registry)
    except KeyError:
        return GenericAgentAdapter(
            protocol_version=_ADAPTER_VERSION,
            health="ready",
            metadata={"runtime": _PLATFORM, "guard_mode": "strict"},
        )


class CopilotEvaluateRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="Copilot action type: code_execution, shell_task, test_run, file_edit_plan, prompt_review, tool_call, or approval.",
        examples=["code_execution", "shell_task", "test_run", "file_edit_plan"],
    )
    target: str = Field(
        ...,
        description="Target file path, repository resource, shell command, test target, or task name.",
        examples=["bash", "pytest tests/test_api.py", "src/service/auth.py"],
    )
    content: str = Field(
        default="",
        description="Prompt text, command payload, test command, or planned file-edit context.",
    )
    client_id: str | None = Field(
        default=None,
        description="Caller client or agent identifier.",
    )
    session_id: str | None = Field(
        default=None,
        description="Copilot session identifier used for audit correlation.",
    )
    risk_score: int = Field(
        default=0,
        ge=0,
        le=100,
        description="Caller-supplied risk hint (0-100).",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional Copilot runtime, repo, task, or workflow metadata.",
    )


class CopilotEvaluateResponse(BaseModel):
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


class CopilotHandshakeRequest(BaseModel):
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
        description="Copilot session identifier associated with the handshake.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional connection metadata, repo context, and runtime environment details.",
    )


class CopilotHandshakeResponse(BaseModel):
    status: str
    platform: str
    adapter_name: str
    protocol_version: str
    integration_health: str
    connected_at: str
    capabilities: list[dict[str, Any]]
    policy_mode: str
    metadata: dict[str, Any]


class CopilotManifestResponse(BaseModel):
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
    response_model=CopilotEvaluateResponse,
    status_code=status.HTTP_200_OK,
    summary="Evaluate a Copilot code execution, shell task, test run, or file edit plan",
    description=("Accepts a Copilot runtime action such as code execution, shell task, test run, or file edit plan. Runs secret scanning on the incoming content before policy evaluation and returns a verdict with a full audit trail."),
)
async def evaluate_copilot(body: CopilotEvaluateRequest) -> CopilotEvaluateResponse:
    trace_id = _trace_id()
    repo_context = str(body.metadata.get("repo_path") or body.metadata.get("workspace") or "")
    scan_payload = f"{body.target}\n{body.content}\n{repo_context}".strip()
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
        return CopilotEvaluateResponse(
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
            summary="Secret scan detected sensitive data in the Copilot payload. Action blocked before dispatch.",
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
            agent_name="github-copilot",
            runtime_name=_PLATFORM,
            client_id=body.client_id,
            session_id=body.session_id,
            metadata={
                **body.metadata,
                "trace_id": trace_id,
                "repo_path": repo_context,
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
    )

    return CopilotEvaluateResponse(
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
    response_model=CopilotHandshakeResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate Copilot integration health and connection state",
    description=("Validates the Copilot integration connection and returns the adapter health and capability manifest used to guard code execution, shell tasks, test runs, and patch plans."),
)
async def copilot_handshake(body: CopilotHandshakeRequest) -> CopilotHandshakeResponse:
    adapter = _build_adapter()

    try:
        from app.adapters.base import AdapterExecutionRequest

        handshake_req = AdapterExecutionRequest(
            action_type="handshake",
            target="copilot",
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
            detail=f"Copilot adapter handshake failed: {exc}",
        ) from exc

    engine = build_policy_engine()
    capabilities = _normalize_capabilities(
        [
            {"name": "prompt-guard", "description": "Inspect prompts before execution."},
            {"name": "code-execution-guard", "description": "Review code-execution tasks before dispatch."},
            {"name": "shell-task-guard", "description": "Assess shell task execution before runtime."},
            {"name": "test-run-guard", "description": "Validate test execution requests before launch."},
            {"name": "file-edit-plan-guard", "description": "Review patch and file-edit plans before application."},
            {"name": "secret-scan", "description": "Scan prompts and runtime payloads for secrets."},
            {"name": "audit-trail", "description": "Persist policy and review decisions."},
        ]
    )

    return CopilotHandshakeResponse(
        status="ok",
        platform=_PLATFORM,
        adapter_name=_ADAPTER_NAME,
        protocol_version=_ADAPTER_VERSION,
        integration_health=adapter.health,
        connected_at=_utc_now(),
        capabilities=capabilities,
        policy_mode=engine.mode,
        metadata={
            "client_id": body.client_id,
            "session_id": body.session_id,
            "requested_protocol_version": body.protocol_version,
            "handshake_status": handshake_result.status,
            **body.metadata,
        },
    )


@router.get(
    "/manifest",
    response_model=CopilotManifestResponse,
    status_code=status.HTTP_200_OK,
    summary="Return Copilot capability manifest and guarded action categories",
    description=("Returns Copilot supported action types, guarded tool categories, and policy bindings used by the IronClaw guardrail layer."),
)
async def copilot_manifest() -> CopilotManifestResponse:
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

    copilot_action_types = sorted(
        TOOL_GUARDED_ACTIONS
        | {
            "code_execution",
            "shell_task",
            "test_run",
            "file_edit_plan",
            "prompt_review",
            "tool_call",
            "approval",
            "message",
            "repository_action",
            "patch_application",
            "workspace_mutation",
        }
    )
    guarded_categories = sorted({action for rule in engine.rules for action in rule.action_types} | TOOL_GUARDED_ACTIONS)
    capabilities = _normalize_capabilities(
        [
            {"name": "prompt-guard", "description": "Inspect prompts before execution."},
            {"name": "code-execution-guard", "description": "Review code execution tasks before dispatch."},
            {"name": "shell-task-guard", "description": "Assess shell task execution before runtime."},
            {"name": "test-run-guard", "description": "Validate test execution requests before launch."},
            {"name": "file-edit-plan-guard", "description": "Review patch and file-edit plans before application."},
            {"name": "secret-scan", "description": "Scan prompts and runtime payloads for secrets."},
            {"name": "audit-trail", "description": "Persist policy and review decisions."},
            {"name": "policy-enforcement", "description": "Runtime policy enforcement in enforce or monitor mode."},
        ]
    )

    return CopilotManifestResponse(
        adapter_name=_ADAPTER_NAME,
        platform=_PLATFORM,
        protocol_version=_ADAPTER_VERSION,
        supported_action_types=copilot_action_types,
        guarded_tool_categories=guarded_categories,
        policy_bindings=policy_bindings,
        capabilities=capabilities,
        generated_at=_utc_now(),
    )
