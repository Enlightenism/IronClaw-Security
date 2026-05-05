from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Literal


PolicyMode = Literal["monitor", "enforce", "lockdown"]
PolicyDecision = Literal["allow", "warn", "quarantine", "block"]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class PolicyThresholdRecord:
    prompt_injection_score: float
    malware_score: float
    exfiltration_score: float
    tool_abuse_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class PolicySettingsRecord:
    policy_id: str
    mode: PolicyMode
    default_decision: PolicyDecision
    require_human_review_for_quarantine: bool
    sandbox_all_untrusted_content: bool
    block_high_risk_tool_calls: bool
    strict_prompt_ingress: bool
    thresholds: PolicyThresholdRecord
    updated_at: datetime
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "mode": self.mode,
            "default_decision": self.default_decision,
            "require_human_review_for_quarantine": self.require_human_review_for_quarantine,
            "sandbox_all_untrusted_content": self.sandbox_all_untrusted_content,
            "block_high_risk_tool_calls": self.block_high_risk_tool_calls,
            "strict_prompt_ingress": self.strict_prompt_ingress,
            "thresholds": self.thresholds.to_dict(),
            "updated_at": self.updated_at.isoformat().replace("+00:00", "Z"),
            "metadata": dict(self.metadata),
        }


class PolicyStore:
    def __init__(self) -> None:
        self._lock = Lock()
        self._settings = PolicySettingsRecord(
            policy_id="ironclaw-default-policy",
            mode="enforce",
            default_decision="quarantine",
            require_human_review_for_quarantine=False,
            sandbox_all_untrusted_content=True,
            block_high_risk_tool_calls=True,
            strict_prompt_ingress=True,
            thresholds=PolicyThresholdRecord(
                prompt_injection_score=0.70,
                malware_score=0.60,
                exfiltration_score=0.55,
                tool_abuse_score=0.65,
            ),
            updated_at=_utcnow(),
            metadata={
                "owner": "ironclaw",
                "profile": "maximum-protection",
            },
        )

    def get_settings(self) -> PolicySettingsRecord:
        with self._lock:
            return self._settings

    def update_settings(
        self,
        *,
        mode: PolicyMode,
        default_decision: PolicyDecision,
        require_human_review_for_quarantine: bool,
        sandbox_all_untrusted_content: bool,
        block_high_risk_tool_calls: bool,
        strict_prompt_ingress: bool,
        thresholds: PolicyThresholdRecord,
        metadata: dict[str, Any] | None = None,
    ) -> PolicySettingsRecord:
        with self._lock:
            self._settings = PolicySettingsRecord(
                policy_id=self._settings.policy_id,
                mode=mode,
                default_decision=default_decision,
                require_human_review_for_quarantine=require_human_review_for_quarantine,
                sandbox_all_untrusted_content=sandbox_all_untrusted_content,
                block_high_risk_tool_calls=block_high_risk_tool_calls,
                strict_prompt_ingress=strict_prompt_ingress,
                thresholds=thresholds,
                updated_at=_utcnow(),
                metadata=dict(metadata or {}),
            )
            return self._settings

    def reset(self) -> None:
        with self._lock:
            self.__init__()


_POLICY_STORE = PolicyStore()


def get_policy_store() -> PolicyStore:
    return _POLICY_STORE


def reset_policy_store() -> None:
    _POLICY_STORE.reset()