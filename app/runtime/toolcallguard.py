from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.runtime.commandsupervisor import CommandPolicy, build_command_supervisor
from app.runtime.filereturnguard import FileReturnPolicy, build_file_return_guard
from app.runtime.networkguard import NetworkPolicy, build_network_guard

COMMAND_TOOL_NAMES = {
    "shell",
    "bash",
    "terminal",
    "command",
    "execute",
    "run",
    "subprocess",
}
NETWORK_TOOL_NAMES = {
    "fetch",
    "http",
    "https",
    "request",
    "webhook",
    "download",
    "upload",
    "api",
}
FILE_TOOL_NAMES = {
    "file",
    "artifact",
    "upload",
    "download",
    "return_file",
    "read_file",
    "write_file",
}
DEFAULT_HIGH_RISK_TOOLS = {
    "powershell",
    "cmd",
    "bash",
    "shell",
    "terminal",
    "curl",
    "wget",
    "python_exec",
}


@dataclass(slots=True)
class ToolCallRequest:
    tool_name: str
    actiontype: str = "toolcall"
    target: str = "runtime"
    command: str | Sequence[str] | None = None
    network_url: str | None = None
    network_method: str = "GET"
    artifact_paths: list[str] = field(default_factory=list)
    content: str | bytes | None = None
    cwd: str | None = None
    environment_scope: str = "sandbox"
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "toolname": self.tool_name,
            "actiontype": self.actiontype,
            "target": self.target,
            "command": self.command,
            "networkurl": self.network_url,
            "networkmethod": self.network_method,
            "artifactpaths": list(self.artifact_paths),
            "cwd": self.cwd,
            "environmentscope": self.environment_scope,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class ToolCallDecision:
    verdict: str
    allowed: bool
    should_review: bool
    should_block: bool
    should_quarantine: bool
    risk_delta: int
    tool_name: str
    actiontype: str
    target: str
    reasons: list[dict[str, Any]] = field(default_factory=list)
    command_policy: dict[str, Any] = field(default_factory=dict)
    network_policy: dict[str, Any] = field(default_factory=dict)
    artifact_policies: list[dict[str, Any]] = field(default_factory=list)
    matched_rules: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "riskdelta": int(self.risk_delta),
            "toolname": self.tool_name,
            "actiontype": self.actiontype,
            "target": self.target,
            "reasons": list(self.reasons),
            "commandpolicy": dict(self.command_policy),
            "networkpolicy": dict(self.network_policy),
            "artifactpolicies": list(self.artifact_policies),
            "matchedrules": list(self.matched_rules),
        }


@dataclass(slots=True)
class ToolCallGuard:
    command_supervisor: Any = field(default_factory=build_command_supervisor)
    network_guard: Any = field(default_factory=build_network_guard)
    file_return_guard: Any = field(default_factory=build_file_return_guard)
    high_risk_tools: set[str] = field(default_factory=lambda: set(DEFAULT_HIGH_RISK_TOOLS))
    review_threshold: int = 20
    block_threshold: int = 50
    quarantine_threshold: int = 80

    def evaluate(self, *, request: ToolCallRequest) -> ToolCallDecision:
        normalized = self._normalize_request(request)
        reasons: list[dict[str, Any]] = []
        matched_rules: list[str] = []
        risk_delta = 0

        command_policy = self._evaluate_command_policy(normalized)
        if command_policy is not None:
            reasons.extend(command_policy.reasons)
            risk_delta += int(command_policy.risk_delta)
            matched_rules.extend(getattr(command_policy, "matched_rules", []))

        network_policy = self._evaluate_network_policy(normalized)
        if network_policy is not None:
            reasons.extend(network_policy.reasons)
            risk_delta += int(network_policy.risk_delta)
            matched_rules.extend(getattr(network_policy, "matched_rules", []))

        artifact_policies = self._evaluate_artifact_policies(normalized)
        for artifact_policy in artifact_policies:
            reasons.extend(artifact_policy.reasons)
            risk_delta += int(artifact_policy.risk_delta)
            matched_rules.extend(getattr(artifact_policy, "matched_rules", []))

        tool_risk, tool_reasons, tool_rules = self._evaluate_tool_identity(normalized)
        reasons.extend(tool_reasons)
        matched_rules.extend(tool_rules)
        risk_delta += tool_risk

        normalized_risk = max(0, min(100, int(risk_delta)))

        verdict = "allow"
        allowed = True
        should_review = False
        should_block = False
        should_quarantine = False

        policies = [policy for policy in (command_policy, network_policy, *artifact_policies) if policy is not None]

        if any(getattr(policy, "should_quarantine", False) for policy in policies) or normalized_risk >= self.quarantine_threshold:
            verdict = "quarantine"
            allowed = False
            should_block = True
            should_quarantine = True
            should_review = False
            matched_rules.append("toolcallguard:quarantine")
        elif any(getattr(policy, "should_block", False) for policy in policies) or normalized_risk >= self.block_threshold:
            verdict = "block"
            allowed = False
            should_block = True
            matched_rules.append("toolcallguard:block")
        elif any(getattr(policy, "should_review", False) for policy in policies) or normalized_risk >= self.review_threshold:
            verdict = "review"
            should_review = True
            matched_rules.append("toolcallguard:review")

        reasons.insert(
            0,
            {
                "source": "toolcallguard",
                "label": "Tool call review",
                "details": (f"Tool '{normalized.tool_name}' was evaluated for action '{normalized.actiontype}' against target '{normalized.target}' with cumulative risk {normalized_risk}."),
                "score": normalized_risk,
            },
        )

        materialized_reasons = self._dedupe_reasons(reasons)
        deduped_rules = list(dict.fromkeys(rule for rule in matched_rules if rule))

        return ToolCallDecision(
            verdict=verdict,
            allowed=allowed,
            should_review=should_review,
            should_block=should_block,
            should_quarantine=should_quarantine,
            risk_delta=normalized_risk,
            tool_name=normalized.tool_name,
            actiontype=normalized.actiontype,
            target=normalized.target,
            reasons=materialized_reasons,
            command_policy=command_policy.as_dict() if command_policy is not None else {},
            network_policy=network_policy.as_dict() if network_policy is not None else {},
            artifact_policies=[policy.as_dict() for policy in artifact_policies],
            matched_rules=deduped_rules,
        )

    def allow(self, *, request: ToolCallRequest) -> bool:
        return self.evaluate(request=request).allowed

    def _normalize_request(self, request: ToolCallRequest) -> ToolCallRequest:
        return ToolCallRequest(
            tool_name=str(request.tool_name or "").strip().lower(),
            actiontype=str(request.actiontype or "toolcall").strip().lower(),
            target=str(request.target or "runtime").strip().lower(),
            command=request.command,
            network_url=str(request.network_url or "").strip() or None,
            network_method=str(request.network_method or "GET").upper(),
            artifact_paths=[str(item).strip() for item in request.artifact_paths if str(item).strip()],
            content=request.content,
            cwd=str(request.cwd).strip() if request.cwd else None,
            environment_scope=str(request.environment_scope or "sandbox").strip(),
            metadata=dict(request.metadata or {}),
        )

    def _evaluate_tool_identity(self, request: ToolCallRequest) -> tuple[int, list[dict[str, Any]], list[str]]:
        reasons: list[dict[str, Any]] = []
        matched_rules: list[str] = []
        risk_delta = 0

        if not request.tool_name:
            reasons.append(
                {
                    "source": "toolcallguard",
                    "label": "Missing tool name",
                    "details": "Tool call was denied because no tool name was provided.",
                    "score": 75,
                },
            )
            matched_rules.append("toolcallguard:missing_tool_name")
            return 75, reasons, matched_rules

        if request.tool_name in self.high_risk_tools:
            reasons.append(
                {
                    "source": "toolcallguard",
                    "label": "High-risk tool",
                    "details": f"Tool '{request.tool_name}' is classified as high risk.",
                    "score": 25,
                },
            )
            matched_rules.append(f"toolcallguard:high_risk:{request.tool_name}")
            risk_delta += 25

        if request.environment_scope.lower() != "sandbox":
            reasons.append(
                {
                    "source": "toolcallguard",
                    "label": "Non-sandbox scope",
                    "details": (f"Tool '{request.tool_name}' requested environment scope '{request.environment_scope}' outside the sandbox boundary."),
                    "score": 45,
                },
            )
            matched_rules.append("toolcallguard:non_sandbox_scope")
            risk_delta += 45

        if request.tool_name in COMMAND_TOOL_NAMES and request.command is None:
            reasons.append(
                {
                    "source": "toolcallguard",
                    "label": "Missing command payload",
                    "details": f"Command-like tool '{request.tool_name}' did not provide a command payload.",
                    "score": 40,
                },
            )
            matched_rules.append("toolcallguard:missing_command")
            risk_delta += 40

        if request.tool_name in NETWORK_TOOL_NAMES and not request.network_url:
            reasons.append(
                {
                    "source": "toolcallguard",
                    "label": "Missing network URL",
                    "details": f"Network-like tool '{request.tool_name}' did not provide a network URL.",
                    "score": 40,
                },
            )
            matched_rules.append("toolcallguard:missing_network_url")
            risk_delta += 40

        if request.tool_name in FILE_TOOL_NAMES and not request.artifact_paths:
            reasons.append(
                {
                    "source": "toolcallguard",
                    "label": "Missing artifact paths",
                    "details": f"File-like tool '{request.tool_name}' did not provide any artifact paths.",
                    "score": 30,
                },
            )
            matched_rules.append("toolcallguard:missing_artifact_paths")
            risk_delta += 30

        return risk_delta, reasons, matched_rules

    def _evaluate_command_policy(self, request: ToolCallRequest) -> CommandPolicy | None:
        if request.command is None and request.tool_name not in COMMAND_TOOL_NAMES:
            return None
        command_value = request.command if request.command is not None else request.tool_name
        return self.command_supervisor.evaluate(
            command=command_value,
            actiontype=request.actiontype,
            target=request.target or request.tool_name,
            cwd=request.cwd,
            metadata={
                **dict(request.metadata),
                "environment_scope": request.environment_scope,
                "tool_name": request.tool_name,
            },
        )

    def _evaluate_network_policy(self, request: ToolCallRequest) -> NetworkPolicy | None:
        if not request.network_url and request.tool_name not in NETWORK_TOOL_NAMES:
            return None
        if not request.network_url:
            return None
        return self.network_guard.evaluate(
            url=request.network_url,
            method=request.network_method,
            metadata={
                **dict(request.metadata),
                "direction": "egress",
                "tool_name": request.tool_name,
            },
        )

    def _evaluate_artifact_policies(self, request: ToolCallRequest) -> list[FileReturnPolicy]:
        if not request.artifact_paths and request.tool_name not in FILE_TOOL_NAMES:
            return []

        policies: list[FileReturnPolicy] = []
        for artifact_path in request.artifact_paths:
            policies.append(
                self.file_return_guard.evaluate(
                    path=artifact_path,
                    content=request.content,
                    metadata={
                        **dict(request.metadata),
                        "tool_name": request.tool_name,
                    },
                ),
            )
        return policies

    def _dedupe_reasons(self, reasons: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, int]] = set()
        for item in reasons:
            source = str(item.get("source", "toolcallguard"))
            label = str(item.get("label", "Tool call review"))
            details = str(item.get("details", ""))
            score = int(item.get("score", 0) or 0)
            key = (source, label, details, score)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(
                {
                    "source": source,
                    "label": label,
                    "details": details,
                    "score": score,
                },
            )
        return deduped[:20]


def initialize_toolcallguard(
    *,
    command_supervisor: Any | None = None,
    network_guard: Any | None = None,
    file_return_guard: Any | None = None,
    high_risk_tools: Iterable[str] | None = None,
    review_threshold: int = 20,
    block_threshold: int = 50,
    quarantine_threshold: int = 80,
) -> ToolCallGuard:
    return ToolCallGuard(
        command_supervisor=command_supervisor or build_command_supervisor(),
        network_guard=network_guard or build_network_guard(),
        file_return_guard=file_return_guard or build_file_return_guard(),
        high_risk_tools=set(high_risk_tools or DEFAULT_HIGH_RISK_TOOLS),
        review_threshold=review_threshold,
        block_threshold=block_threshold,
        quarantine_threshold=quarantine_threshold,
    )


def build_toolcallguard() -> ToolCallGuard:
    return initialize_toolcallguard()


__all__ = [
    "ToolCallDecision",
    "ToolCallGuard",
    "ToolCallRequest",
    "build_toolcallguard",
    "initialize_toolcallguard",
]
