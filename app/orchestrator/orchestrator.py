from __future__ import annotations

from dataclasses import asdict, dataclass, field
import logging
from pathlib import Path
from typing import Any, Literal

from app.config import RISK_THRESHOLD_ALLOW_MAX, RISK_THRESHOLD_BLOCK_MIN
from app.orchestrator.agent_registry import (
    AgentDescriptor,
    AgentRegistry,
    ProtectedAction,
    discover_agents,
    get_agent_by_id,
    get_agent_by_path,
)
from client import IronClawClient

OrchestratorDecisionSource = Literal["registry_only", "guard_api", "guard_api_fallback"]
logger = logging.getLogger(__name__)


def _text(value: Any, default: str = "") -> str:
    if value is None:
        return default
    result = str(value).strip()
    return result or default


def _normalize_root(project_root: str | Path) -> Path:
    return Path(project_root).expanduser().resolve()


def _normalize_relative_path(file_path: str) -> str:
    return _text(file_path).replace("\\", "/").strip()


def _clamp_risk(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    return max(0, min(100, parsed))


def _is_valid_risk_score(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 100


def _normalized_tags(agent: AgentDescriptor) -> list[str]:
    return [str(tag).strip() for tag in getattr(agent, "tags", []) if str(tag).strip()]


def _registry_risk_score(agent: AgentDescriptor, action_type: ProtectedAction) -> int:
    score = 0
    threat_profile = _text(getattr(agent, "threat_profile", "standard")).lower()

    if action_type not in getattr(agent, "protected_actions", []):
        score += 20

    if threat_profile == "sensitive":
        score += 25
    elif threat_profile == "execution_capable":
        score += 35
    elif threat_profile == "security_critical":
        score += 50

    if action_type in {"tool_call", "shell_command"}:
        score += 20
    elif action_type in {"network_request", "git_operation"}:
        score += 10

    return _clamp_risk(score)


def _resolve_agent(
    registry: AgentRegistry,
    file_path: str | None = None,
    agent_id: str | None = None,
) -> AgentDescriptor:
    normalized_agent_id = _text(agent_id)
    normalized_file_path = _normalize_relative_path(file_path or "")

    if normalized_agent_id:
        agent = get_agent_by_id(registry, normalized_agent_id)
        if agent is not None:
            return agent
        raise ValueError(f"Unknown agent_id: {normalized_agent_id}")

    if normalized_file_path:
        agent = get_agent_by_path(registry, normalized_file_path)
        if agent is not None:
            return agent
        raise ValueError(f"Unknown file_path: {normalized_file_path}")

    raise ValueError("Either file_path or agent_id must be provided.")


def _default_summary_for_registry_only(agent: AgentDescriptor, action_type: ProtectedAction) -> str:
    if action_type not in agent.protected_actions:
        return f"Action '{action_type}' is not explicitly registered for agent {agent.agent_id}, but the file remains under orchestration visibility."

    return f"Agent {agent.agent_id} is assigned to {agent.relative_path} and recognizes protected action '{action_type}'."


def _fallback_decision_from_registry(
    agent: AgentDescriptor,
    action_type: ProtectedAction,
    target: str,
    content: str,
    client_id: str | None,
    session_id: str | None,
    *,
    fail_secure: bool = True,
) -> OrchestrationDecision:
    registry_risk = _registry_risk_score(agent, action_type)
    summary = _default_summary_for_registry_only(agent, action_type)
    if fail_secure:
        summary = f"{summary} Guard API was unavailable; fail-closed fallback blocked this action."
    else:
        summary = f"{summary} Guard API was unavailable; block-only policy prevented a fail-open fallback."

    return OrchestrationDecision(
        agent_id=agent.agent_id,
        file_path=agent.relative_path,
        action_type=action_type,
        target=target,
        content=content,
        allowed=False,
        verdict="block",
        should_halt=True,
        should_warn=False,
        summary=summary,
        risk_score=max(registry_risk, RISK_THRESHOLD_BLOCK_MIN),
        matched_patterns=[],
        decision_source="guard_api_fallback",
        registry_tags=_normalized_tags(agent),
        registry_threat_profile=agent.threat_profile,
        scan_id=None,
        client_id=client_id,
        session_id=session_id,
    )


@dataclass(slots=True)
class OrchestrationDecision:
    agent_id: str
    file_path: str
    action_type: ProtectedAction
    target: str
    content: str
    allowed: bool
    verdict: Literal["allow", "block"]
    should_halt: bool
    should_warn: bool
    summary: str
    risk_score: int
    matched_patterns: list[str] = field(default_factory=list)
    decision_source: OrchestratorDecisionSource = "registry_only"
    registry_tags: list[str] = field(default_factory=list)
    registry_threat_profile: str = "standard"
    scan_id: str | None = None
    client_id: str | None = None
    session_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IronClawOrchestrator:
    def __init__(
        self,
        project_root: str | Path,
        base_url: str = "http://127.0.0.1:8010",
        client: IronClawClient | None = None,
    ) -> None:
        self.project_root = _normalize_root(project_root)
        self.base_url = _text(base_url, "http://127.0.0.1:8010")
        self.client = client or IronClawClient(base_url=self.base_url)
        self.registry: AgentRegistry = discover_agents(self.project_root)

    def refresh_registry(self) -> AgentRegistry:
        self.registry = discover_agents(self.project_root)
        return self.registry

    def list_agents(self) -> list[AgentDescriptor]:
        return list(self.registry.items)

    def get_agent(self, *, file_path: str | None = None, agent_id: str | None = None) -> AgentDescriptor:
        return _resolve_agent(self.registry, file_path=file_path, agent_id=agent_id)

    def route_action(
        self,
        *,
        action_type: ProtectedAction,
        target: str,
        content: str = "",
        file_path: str | None = None,
        agent_id: str | None = None,
        client_id: str | None = None,
        session_id: str | None = None,
        use_guard_api: bool = True,
        fail_secure_fallback: bool = True,
    ) -> OrchestrationDecision:
        normalized_target = _text(target)
        normalized_content = content if isinstance(content, str) else _text(content)
        agent = self.get_agent(file_path=file_path, agent_id=agent_id)
        resolved_client_id = _text(client_id) or agent.agent_id

        if not use_guard_api:
            summary = _default_summary_for_registry_only(agent, action_type)
            registry_risk = _registry_risk_score(agent, action_type)
            should_block = action_type not in agent.protected_actions or agent.threat_profile in {"sensitive", "execution_capable", "security_critical"} or registry_risk > RISK_THRESHOLD_ALLOW_MAX
            verdict: Literal["allow", "block"] = "block" if should_block else "allow"
            if should_block:
                summary = f"{summary} Registry-only policy blocked this action."
            return OrchestrationDecision(
                agent_id=agent.agent_id,
                file_path=agent.relative_path,
                action_type=action_type,
                target=normalized_target,
                content=normalized_content,
                allowed=not should_block,
                verdict=verdict,
                should_halt=should_block,
                should_warn=False,
                summary=summary,
                risk_score=(max(registry_risk, RISK_THRESHOLD_BLOCK_MIN) if should_block else registry_risk),
                matched_patterns=[],
                decision_source="registry_only",
                registry_tags=_normalized_tags(agent),
                registry_threat_profile=agent.threat_profile,
                scan_id=None,
                client_id=resolved_client_id,
                session_id=_text(session_id) or None,
            )

        try:
            decision = self.client.guard_action_decision(
                action_type=action_type,
                target=normalized_target,
                content=normalized_content,
                client_id=resolved_client_id,
                session_id=_text(session_id) or None,
            )
            raw_verdict = _text(getattr(decision, "verdict", "")).lower()
            raw_should_halt = getattr(decision, "should_halt", None)
            raw_should_warn = getattr(decision, "should_warn", None)
            raw_risk_score = getattr(decision, "risk_score", None)
            raw_matched_patterns = getattr(decision, "matched_patterns", None)
            risk_score = _clamp_risk(
                raw_risk_score,
                default=RISK_THRESHOLD_BLOCK_MIN,
            )
            matched_patterns = [_text(item) for item in raw_matched_patterns or [] if _text(item)]
            allowed = raw_verdict == "allow" and raw_should_halt is False and raw_should_warn is False and _is_valid_risk_score(raw_risk_score) and risk_score <= RISK_THRESHOLD_ALLOW_MAX and isinstance(raw_matched_patterns, list) and not matched_patterns
            summary = _text(
                getattr(decision, "summary", ""),
                "Guard API decision completed.",
            )
            if not allowed and (raw_verdict != "block" or raw_should_halt is not True):
                summary = f"{summary} Block-only policy blocked the action because the guard result was incomplete or not a clean allow."
            return OrchestrationDecision(
                agent_id=agent.agent_id,
                file_path=agent.relative_path,
                action_type=action_type,
                target=normalized_target,
                content=normalized_content,
                allowed=allowed,
                verdict="allow" if allowed else "block",
                should_halt=not allowed,
                should_warn=False,
                summary=summary,
                risk_score=(risk_score if allowed else max(risk_score, RISK_THRESHOLD_BLOCK_MIN)),
                matched_patterns=matched_patterns,
                decision_source="guard_api",
                registry_tags=_normalized_tags(agent),
                registry_threat_profile=agent.threat_profile,
                scan_id=_text(getattr(decision, "scan_id", "")) or None,
                client_id=resolved_client_id,
                session_id=_text(session_id) or None,
            )
        except Exception:
            logger.exception("Guard API orchestration failed; blocking the action.")
            return _fallback_decision_from_registry(
                agent=agent,
                action_type=action_type,
                target=normalized_target,
                content=normalized_content,
                client_id=resolved_client_id,
                session_id=_text(session_id) or None,
                fail_secure=fail_secure_fallback,
            )


if __name__ == "__main__":
    orchestrator = IronClawOrchestrator(project_root=Path())
    print(f"Loaded {len(orchestrator.list_agents())} agents from {orchestrator.project_root}")
