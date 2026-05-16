from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
from threading import Lock
from typing import Any, Final

from schemas.release_policy import ReleaseChannel

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_RESULT_FILE: Final[Path] = ROOT / ".release-policy-decisions.jsonl"
MAX_RECENT_DECISIONS: Final[int] = 200


@dataclass(frozen=True, slots=True)
class ReleasePolicyDecision:
    decision_id: str
    channel: ReleaseChannel
    allowed: bool
    requested_version: str
    minimum_upgrade_from: str
    decision_reason: str
    actor: str
    decided_at: str
    metadata: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReleasePolicyDecisionStore:
    def __init__(
        self,
        result_file: Path = DEFAULT_RESULT_FILE,
        max_recent_decisions: int = MAX_RECENT_DECISIONS,
    ) -> None:
        self._result_file = result_file
        self._max_recent_decisions = max_recent_decisions
        self._lock = Lock()
        self._recent: list[ReleasePolicyDecision] = []

    def _utcnow_iso(self) -> str:
        return datetime.now(UTC).isoformat()

    def _ensure_parent_dir(self) -> None:
        self._result_file.parent.mkdir(parents=True, exist_ok=True)

    def record_decision(
        self,
        *,
        channel: ReleaseChannel,
        allowed: bool,
        requested_version: str,
        minimum_upgrade_from: str,
        decision_reason: str,
        actor: str,
        metadata: dict[str, Any] | None = None,
    ) -> ReleasePolicyDecision:
        decided_at = self._utcnow_iso()
        decision = ReleasePolicyDecision(
            decision_id=(f"release-policy-{channel}-{decided_at.replace(':', '').replace('-', '').replace('+', '').replace('.', '')}"),
            channel=channel,
            allowed=allowed,
            requested_version=requested_version.strip(),
            minimum_upgrade_from=minimum_upgrade_from.strip(),
            decision_reason=decision_reason.strip(),
            actor=actor.strip() or "system",
            decided_at=decided_at,
            metadata=dict(metadata or {}),
        )

        payload = json.dumps(decision.to_dict(), separators=(",", ":")) + "\n"

        with self._lock:
            self._ensure_parent_dir()
            with self._result_file.open("a", encoding="utf-8") as handle:
                handle.write(payload)

            self._recent.append(decision)
            if len(self._recent) > self._max_recent_decisions:
                self._recent = self._recent[-self._max_recent_decisions :]

        return decision

    def list_recent(self, limit: int = 50) -> list[ReleasePolicyDecision]:
        bounded_limit = max(1, min(limit, self._max_recent_decisions))
        with self._lock:
            return list(self._recent[-bounded_limit:])

    def load_from_disk(self, limit: int = 200) -> list[ReleasePolicyDecision]:
        if not self._result_file.exists():
            return []

        bounded_limit = max(1, min(limit, self._max_recent_decisions))
        with self._lock:
            lines = self._result_file.read_text(encoding="utf-8").splitlines()

        decisions: list[ReleasePolicyDecision] = []
        for line in lines[-bounded_limit:]:
            stripped = line.strip()
            if not stripped:
                continue
            payload = json.loads(stripped)
            decisions.append(ReleasePolicyDecision(**payload))

        return decisions

    @property
    def result_file(self) -> Path:
        return self._result_file


release_policy_decision_store = ReleasePolicyDecisionStore()
