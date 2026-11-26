"""Sandbox-first return gate orchestrator. Fail closed."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import logging
from typing import Any
import uuid

from app.config import RISK_THRESHOLD_ALLOW_MAX
from app.detection.outputsanitizer import build_output_sanitizer
from app.runtime.return_scanner import ALLOW_VERDICT, BLOCK_VERDICT, scan_return
from app.schemas.telemetry import TelemetryEventType
from app.services.actionexecuteservice import ActionExecutionRequest, get_action_execute_service
from app.services.audit_store import record_gate_audit_event
from app.services.detonationservice import build_detonation_service
from app.services.malwareservice import build_malware_service
from app.services.sandbox_broker_client import SandboxBrokerClient
from app.services.secretsredaction import build_secrets_redaction_service
from app.services.telemetry import append_telemetry_event
from app.supabaseclient import TOKENS_PER_UNIT

logger = logging.getLogger(__name__)

BLOCKED_REPLACEMENT_TEXT = "[BLOCKED BY IRONCLAW RETURN GATE] The original tool output was withheld because it failed the return-gate scan."
RETURN_SCAN_ACTION = "scan"
RETURN_SCAN_TIMEOUT_SECONDS = 10.0
RETURN_UNIT_ACTION = "return_scan"
RETURN_CHARS_PER_TOKEN = 4
RETURN_WINDOW_CHARS = TOKENS_PER_UNIT * RETURN_CHARS_PER_TOKEN
# Overlap keeps a pattern that straddles a window boundary whole in at least one window.
RETURN_WINDOW_OVERLAP_CHARS = 4_000
STAGE_SECURITY_GATE = "security_gate"
STAGE_SANDBOX = "sandbox"
STAGE_METERING = "metering"
FAIL_CLOSED_RISK_SCORE = 100


@dataclass(frozen=True)
class ReturnGateDecision:
    verdict: str
    sandbox_id: str
    stage: str
    reasons: list[str] = field(default_factory=list)
    risk_score: int = 0
    released_text: str | None = None

    @property
    def blocked(self) -> bool:
        return self.verdict != ALLOW_VERDICT


def new_sandbox_id() -> str:
    return f"return-{uuid.uuid4().hex}"


def _block(sandbox_id: str, stage: str, reason: str) -> ReturnGateDecision:
    return ReturnGateDecision(BLOCK_VERDICT, sandbox_id, stage, [reason], FAIL_CLOSED_RISK_SCORE)


def _broker_decision(data: Any, sandbox_id: str) -> ReturnGateDecision:
    if not isinstance(data, Mapping):
        return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
    risk_score = data.get("risk_score")
    reasons = data.get("reasons")
    if isinstance(risk_score, bool) or not isinstance(risk_score, int):
        return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
    if not isinstance(reasons, list):
        return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
    if data.get("verdict") == ALLOW_VERDICT and data.get("status") == "completed" and data.get("executor") == "docker" and data.get("untrusted") is not True:
        if not 0 <= risk_score <= RISK_THRESHOLD_ALLOW_MAX or reasons:
            return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
        released_text = data.get("released_text")
        if not isinstance(released_text, str):
            return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
        return ReturnGateDecision(
            ALLOW_VERDICT,
            sandbox_id,
            STAGE_SANDBOX,
            released_text=released_text,
        )
    if data.get("verdict") not in (ALLOW_VERDICT, BLOCK_VERDICT):
        return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
    if data.get("verdict") == ALLOW_VERDICT and (data.get("status") != "completed" or data.get("executor") != "docker" or data.get("untrusted") is True):
        return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
    if data.get("verdict") == BLOCK_VERDICT:
        if data.get("status") != "blocked" or data.get("executor") != "docker" or data.get("untrusted") is not True or risk_score < FAIL_CLOSED_RISK_SCORE or not reasons:
            return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
        if data.get("released_text") is not None:
            return _block(sandbox_id, STAGE_SANDBOX, "invalid_sandbox_response")
    return _block(
        sandbox_id,
        STAGE_SANDBOX,
        str(data.get("reason") or "sandbox_blocked"),
    )


def split_return_windows(content: str) -> list[str]:
    if len(content) <= RETURN_WINDOW_CHARS:
        return [content]
    stride = RETURN_WINDOW_CHARS - RETURN_WINDOW_OVERLAP_CHARS
    windows: list[str] = []
    start = 0
    while True:
        end = start + RETURN_WINDOW_CHARS
        windows.append(content[start:end])
        if end >= len(content):
            return windows
        start += stride


def _metering_block(
    sandbox_id: str,
    *,
    owner_key: str | None,
    units: int,
    install_key_id: str | None,
    program: str | None,
) -> ReturnGateDecision | None:
    if not owner_key:
        return _block(sandbox_id, STAGE_METERING, "billing_owner_unresolved")
    try:
        receipt = get_action_execute_service().execute(
            ActionExecutionRequest(
                owner_key=owner_key,
                action_name=RETURN_UNIT_ACTION,
                requested_units=units,
                metadata={"sandbox_id": sandbox_id, "windows": units},
                install_key_id=install_key_id,
                program=program,
                event_id=f"{install_key_id}:{sandbox_id}" if install_key_id else None,
            )
        )
    except Exception:
        logger.exception("return gate unit metering failed; blocking", extra={"sandbox_id": sandbox_id})
        return _block(sandbox_id, STAGE_METERING, "usage_metering_unavailable")
    if not receipt.executed:
        return _block(sandbox_id, STAGE_METERING, "protection_units_unavailable")
    return None


def _record_decision(
    decision: ReturnGateDecision,
    *,
    platform: str,
    agent_id: str | None,
    client_id: str | None,
    session_id: str | None,
    owner_key: str | None,
    install_key_id: str | None = None,
) -> None:
    try:
        append_telemetry_event(
            TelemetryEventType.RETURN_GATE_DECISION,
            {
                "sandbox_id": decision.sandbox_id,
                "verdict": decision.verdict,
                "stage": decision.stage,
                "reasons": decision.reasons,
                "risk_score": decision.risk_score,
                "platform": platform,
                "agent_id": agent_id,
                "client_id": client_id,
                "session_id": session_id,
            },
        )
    except Exception:
        logger.exception("return gate telemetry write failed", extra={"sandbox_id": decision.sandbox_id})
    record_gate_audit_event(
        gate="return",
        verdict=decision.verdict,
        platform=platform,
        reason_codes=decision.reasons,
        owner_key=owner_key,
        decision_id=decision.sandbox_id,
        session_id=session_id,
        agent_id=agent_id,
        details={"stage": decision.stage, "risk_score": decision.risk_score, "install_key_id": install_key_id},
    )


def run_return_gate(
    *,
    platform: str,
    payload: dict[str, Any],
    content: str = "",
    action_type: str = "tool_output",
    target: str = "return",
    client_id: str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    broker_client: SandboxBrokerClient | None = None,
    owner_key: str | None = None,
    install_key_id: str | None = None,
    program: str | None = None,
) -> ReturnGateDecision:
    sandbox_id = new_sandbox_id()
    windows = split_return_windows(content)
    decision = _metering_block(
        sandbox_id,
        owner_key=owner_key,
        units=len(windows),
        install_key_id=install_key_id,
        program=program,
    )
    if decision is None:
        decision = _scan_windows(
            sandbox_id,
            windows,
            platform=platform,
            agent_id=agent_id,
            client_id=client_id,
            session_id=session_id,
            payload=payload,
            action_type=action_type,
            target=target,
            broker_client=broker_client,
        )
    if decision.verdict == ALLOW_VERDICT:
        decision = ReturnGateDecision(
            verdict=decision.verdict,
            sandbox_id=decision.sandbox_id,
            stage=decision.stage,
            reasons=list(decision.reasons),
            risk_score=decision.risk_score,
            released_text=content,
        )

    _record_decision(
        decision,
        platform=platform,
        agent_id=agent_id,
        client_id=client_id,
        session_id=session_id,
        owner_key=owner_key,
        install_key_id=install_key_id,
    )
    return decision


def _sanitize_isolated_return(
    *,
    sandbox_id: str,
    content: str,
    payload: Mapping[str, Any],
) -> ReturnGateDecision | None:
    payload_text = content
    redaction = build_secrets_redaction_service().redact_text(payload_text)
    if redaction.findings_detected > 0:
        return _block(
            sandbox_id,
            STAGE_SECURITY_GATE,
            "secret_redaction_block",
        )

    malware = build_malware_service().analyze_bytes(
        payload_text.encode("utf-8", errors="replace"),
        file_name=(str(payload.get("file_name") or payload.get("file_path") or "") or None),
    )
    if malware.verdict == BLOCK_VERDICT:
        return _block(
            sandbox_id,
            STAGE_SECURITY_GATE,
            "malware_text_assessment",
        )

    detonation = build_detonation_service().detonate_text(payload_text)
    if detonation.verdict == BLOCK_VERDICT:
        return _block(
            sandbox_id,
            STAGE_SECURITY_GATE,
            "detonation_text_assessment",
        )

    sanitizer = build_output_sanitizer().sanitize(
        payload_text,
        context="isolated_agent_output",
        redact_secrets=True,
        block_unsafe_commands=True,
    )
    if sanitizer.blocked:
        return _block(
            sandbox_id,
            STAGE_SECURITY_GATE,
            "output_sanitizer_block",
        )
    return None


def _scan_windows(
    sandbox_id: str,
    windows: list[str],
    *,
    platform: str,
    agent_id: str | None,
    client_id: str | None,
    session_id: str | None,
    payload: dict[str, Any],
    action_type: str,
    target: str,
    broker_client: SandboxBrokerClient | None,
) -> ReturnGateDecision:
    for index, window in enumerate(windows):
        sandbox_decision = _sandbox_decision(
            sandbox_id,
            platform=platform,
            agent_id=agent_id,
            content=window,
            payload=payload,
            target=target,
            broker_client=broker_client,
            window_index=index,
            window_count=len(windows),
        )
        if sandbox_decision.blocked:
            return sandbox_decision

        try:
            scan = scan_return(
                payload,
                content=window,
                platform=platform,
                action_type=action_type,
                target=target,
                client_id=client_id,
                session_id=session_id,
                sandbox_allowed=True,
            )
        except Exception:
            logger.exception("return gate security scan failed; blocking", extra={"sandbox_id": sandbox_id, "window": index})
            return _block(sandbox_id, STAGE_SECURITY_GATE, "return_scan_error")
        if scan.blocked:
            return ReturnGateDecision(
                BLOCK_VERDICT,
                sandbox_id,
                STAGE_SECURITY_GATE,
                scan.reasons,
                scan.risk_score,
            )
        isolated_result = _sanitize_isolated_return(
            sandbox_id=sandbox_id,
            content=window,
            payload=payload,
        )
        if isolated_result is not None:
            return isolated_result
    return ReturnGateDecision(ALLOW_VERDICT, sandbox_id, STAGE_SANDBOX)


def _sandbox_decision(
    sandbox_id: str,
    *,
    platform: str,
    agent_id: str | None,
    content: str,
    payload: dict[str, Any],
    target: str,
    broker_client: SandboxBrokerClient | None,
    window_index: int,
    window_count: int,
) -> ReturnGateDecision:
    client = broker_client or SandboxBrokerClient()
    sandbox_payload = {
        "sandbox_id": sandbox_id,
        "platform": platform,
        "agent_id": agent_id,
        "content": content,
        "return": payload,
        "window": {"index": window_index, "count": window_count},
    }
    try:
        data = client.run(RETURN_SCAN_ACTION, target, sandbox_payload, timeout_seconds=RETURN_SCAN_TIMEOUT_SECONDS)
    except Exception:
        logger.exception("return gate broker call failed; blocking", extra={"sandbox_id": sandbox_id})
        return _block(sandbox_id, STAGE_SANDBOX, "broker_error")
    return _broker_decision(data, sandbox_id)
