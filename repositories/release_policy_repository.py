from __future__ import annotations

import json
from pathlib import Path
from threading import Lock
from typing import Final

from app.schemas.release_policy import ReleaseChannel, ReleasePolicyDetail

ROOT: Final[Path] = Path(__file__).resolve().parents[1]
DEFAULT_STORE_FILE: Final[Path] = ROOT / ".release-policy-catalog.json"


class ReleasePolicyRepository:
    def __init__(self, store_file: Path = DEFAULT_STORE_FILE) -> None:
        self._store_file = store_file
        self._lock = Lock()

    def _ensure_parent_dir(self) -> None:
        self._store_file.parent.mkdir(parents=True, exist_ok=True)

    def _load_payload(self) -> dict[str, object]:
        if not self._store_file.exists():
            return {"policies": {}}

        raw = self._store_file.read_text(encoding="utf-8").strip()
        if not raw:
            return {"policies": {}}

        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("release policy repository payload must be a JSON object")

        policies = payload.get("policies")
        if policies is None:
            payload["policies"] = {}
            return payload

        if not isinstance(policies, dict):
            raise ValueError("release policy repository 'policies' must be a JSON object")

        return payload

    def _write_payload(self, payload: dict[str, object]) -> None:
        self._ensure_parent_dir()
        self._store_file.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def list_policies(self) -> list[ReleasePolicyDetail]:
        with self._lock:
            payload = self._load_payload()
            raw_policies = payload.get("policies", {})

            if not isinstance(raw_policies, dict):
                raise ValueError("release policy repository 'policies' must be a JSON object")

            items = [ReleasePolicyDetail.model_validate(item) for _, item in sorted(raw_policies.items(), key=lambda entry: entry[0])]

        return items

    def get_policy(self, channel: ReleaseChannel) -> ReleasePolicyDetail | None:
        with self._lock:
            payload = self._load_payload()
            raw_policies = payload.get("policies", {})

            if not isinstance(raw_policies, dict):
                raise ValueError("release policy repository 'policies' must be a JSON object")

            item = raw_policies.get(channel)
            if item is None:
                return None

            return ReleasePolicyDetail.model_validate(item)

    def upsert_policy(self, policy: ReleasePolicyDetail) -> ReleasePolicyDetail:
        with self._lock:
            payload = self._load_payload()
            raw_policies = payload.get("policies", {})

            if not isinstance(raw_policies, dict):
                raise ValueError("release policy repository 'policies' must be a JSON object")

            raw_policies[policy.channel] = policy.model_dump(mode="json")
            payload["policies"] = raw_policies
            self._write_payload(payload)

        return policy

    def delete_policy(self, channel: ReleaseChannel) -> bool:
        with self._lock:
            payload = self._load_payload()
            raw_policies = payload.get("policies", {})

            if not isinstance(raw_policies, dict):
                raise ValueError("release policy repository 'policies' must be a JSON object")

            existed = channel in raw_policies
            if existed:
                del raw_policies[channel]
                payload["policies"] = raw_policies
                self._write_payload(payload)

        return existed

    @property
    def store_file(self) -> Path:
        return self._store_file


release_policy_repository = ReleasePolicyRepository()
