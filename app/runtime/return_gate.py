"""Return gate orchestrator: in-process scan, then an isolated sandbox scan through the host broker. Fail closed."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import logging
from typing import Any
import uuid

from app.runtime.return_scanner import ALLOW_VERDICT, BLOCK_VERDICT, scan_return
from app.schemas.telemetry import TelemetryEventType
from app.services.actionexecuteservice import ActionExecutionRequest, get_action_execute_service
from app.services.audit_store import record_gate_audit_event
from app.services.sandbox_broker_client import SandboxBrokerClient
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
STAGE_SCAN_ERROR = "scan_error"
STAGE_INPROCESS = "inprocess"
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

    @property
    def blocked(self) -> bool:
        return self.verdict != ALLOW_VERDICT


def new_sandbox_id() -> str:
    return f"return-{uuid.uuid4().hex}"


def _block(sandbox_id: str, stage: str, reason: str) -> ReturnGateDecision:
    return ReturnGateDecision(BLOCK_VERDICT, sandbox_id, stage, [reason], FAIL_CLOSED_RISK_SCORE)


def _broker_decision(data: Mapping[str, Any], sandbox_id: str) -> ReturnGateDecision:
    if data.get("verdict") == ALLOW_VERDICT and data.get("status") == "completed" and not data.get("untrusted"):
        return ReturnGateDecision(ALLOW_VERDICT, sandbox_id, STAGE_SANDBOX)
    return _block(sandbox_id, STAGE_SANDBOX, str(data.get("reason") or "sandbox_blocked"))


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
        details={"stage": decision.stage, "risk_score": decision.risk_score},
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

    _record_decision(
        decision,
        platform=platform,
        agent_id=agent_id,
        client_id=client_id,
        session_id=session_id,
        owner_key=owner_key,
    )
    return decision


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
        try:
            scan = scan_return(
                payload,
                content=window,
                platform=platform,
                action_type=action_type,
                target=target,
                client_id=client_id,
                session_id=session_id,
            )
        except Exception:
            logger.exception("return gate in-process scan failed; blocking", extra={"sandbox_id": sandbox_id, "window": index})
            return _block(sandbox_id, STAGE_SCAN_ERROR, "return_scan_error")
        if scan.blocked:
            return ReturnGateDecision(BLOCK_VERDICT, sandbox_id, STAGE_INPROCESS, scan.reasons, scan.risk_score)
        decision = _sandbox_decision(
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
        if decision.blocked:
            return decision
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
