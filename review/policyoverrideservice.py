from __future__ import annotations

from threading import Lock
from typing import Any, Dict, List, Optional

from review.policyevaluator import PolicyOverride


class PolicyOverrideService:
    """
    In-memory override registry for policy evaluation flows.

    Goals:
    - Deterministic behavior for tests and orchestration.
    - Simple CRUD-style interface for override management.
    - Fast applicability lookup for a payload.
    - Drop-in replaceable with a persistent store later.
    """

    def __init__(self, overrides: Optional[List[PolicyOverride]] = None) -> None:
        self._lock = Lock()
        self._overrides: Dict[str, PolicyOverride] = {}
        if overrides:
            for override in overrides:
                self._overrides[override.override_id] = override

    def add_override(self, override: PolicyOverride) -> PolicyOverride:
        with self._lock:
            if override.override_id in self._overrides:
                raise ValueError(f"override already exists: {override.override_id}")
            self._overrides[override.override_id] = override
            return override

    def upsert_override(self, override: PolicyOverride) -> PolicyOverride:
        with self._lock:
            self._overrides[override.override_id] = override
            return override

    def get_override(self, override_id: str) -> Optional[PolicyOverride]:
        return self._overrides.get(override_id)

    def list_overrides(
        self,
        *,
        enabled_only: bool = False,
        target_field: Optional[str] = None,
    ) -> List[PolicyOverride]:
        overrides = list(self._overrides.values())

        if enabled_only:
            overrides = [override for override in overrides if override.enabled]

        if target_field is not None:
            overrides = [
                override
                for override in overrides
                if override.target_field == target_field
            ]

        return sorted(overrides, key=self._sort_key)

    def delete_override(self, override_id: str) -> PolicyOverride:
        with self._lock:
            override = self._require(override_id)
            del self._overrides[override_id]
            return override

    def set_enabled(self, override_id: str, enabled: bool) -> PolicyOverride:
        with self._lock:
            override = self._require(override_id)
            updated = PolicyOverride(
                override_id=override.override_id,
                target_field=override.target_field,
                target_value=override.target_value,
                force_decision=override.force_decision,
                add_reasons=list(override.add_reasons),
                metadata=dict(override.metadata),
                enabled=enabled,
            )
            self._overrides[override_id] = updated
            return updated

    def find_applicable(self, payload: Dict[str, Any]) -> List[PolicyOverride]:
        applicable: List[PolicyOverride] = []
        for override in self.list_overrides(enabled_only=True):
            if self._matches(override, payload):
                applicable.append(override)
        return applicable

    def count(self, *, enabled_only: bool = False) -> int:
        return len(self.list_overrides(enabled_only=enabled_only))

    def clear(self) -> None:
        with self._lock:
            self._overrides.clear()

    def _matches(self, override: PolicyOverride, payload: Dict[str, Any]) -> bool:
        if override.target_field is None:
            return True

        if override.target_field not in payload:
            return False

        actual = payload.get(override.target_field)

        if override.target_value is None:
            return True

        if isinstance(actual, list):
            return override.target_value in actual

        if isinstance(actual, set):
            return override.target_value in actual

        if isinstance(actual, tuple):
            return override.target_value in actual

        return actual == override.target_value

    def _require(self, override_id: str) -> PolicyOverride:
        override = self._overrides.get(override_id)
        if override is None:
            raise KeyError(f"override not found: {override_id}")
        return override

    def _sort_key(self, override: PolicyOverride) -> tuple[int, str, str]:
        return (
            0 if override.enabled else 1,
            override.target_field or "",
            override.override_id,
        )