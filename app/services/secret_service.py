from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
import hashlib
import os
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _utc_now_iso() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _hash_secret(secret_value: str) -> str:
    return hashlib.sha256(secret_value.encode("utf-8")).hexdigest()


def _mask_secret(secret_value: str) -> str:
    if len(secret_value) <= 10:
        return "•" * len(secret_value)
    return f"{secret_value[:4]}…{secret_value[-4:]}"


def _normalize_secret_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _read_env_secret(*names: str) -> str:
    for name in names:
        value = _normalize_secret_value(os.environ.get(name))
        if value:
            return value
    return ""


def resolve_secret_key(
    override: str | None = None,
    *,
    env_names: tuple[str, ...] = (
        "SECRET_KEY",
        "IRONCLAW_SECRET_KEY",
        "APP_SECRET_KEY",
    ),
    config: Any = None,
) -> str:
    explicit_override = _normalize_secret_value(override)
    if explicit_override:
        return explicit_override

    if config is not None:
        if isinstance(config, dict):
            for key in ("secret_key", "SECRET_KEY", "IRONCLAW_SECRET_KEY", "APP_SECRET_KEY"):
                config_value = _normalize_secret_value(config.get(key))
                if config_value:
                    return config_value
        else:
            for attr_name in ("secret_key", "SECRET_KEY", "ironclaw_secret_key", "app_secret_key"):
                config_value = _normalize_secret_value(getattr(config, attr_name, None))
                if config_value:
                    return config_value

    return _read_env_secret(*env_names)


@dataclass(frozen=True)
class SecretRecord:
    secret_id: str
    name: str
    provider: str
    kind: str
    hashed_value: str
    masked_value: str
    created_at: datetime
    updated_at: datetime
    last_used_at: datetime | None = None
    active: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    raw_value: str | None = None


class SecretService:
    """Local-first secret registry for integration credentials and platform secrets.

    This service is intentionally in-memory for the first build phase so routes,
    UI pages, and tests can stabilize before persistence is added.
    """

    def __init__(self) -> None:
        self._records_by_id: dict[str, SecretRecord] = {}
        self._records_by_name: dict[str, str] = {}
        self._next_id = 1

    def create_secret(
        self,
        *,
        name: str,
        value: str,
        provider: str,
        kind: str = "api_key",
        metadata: dict[str, Any] | None = None,
    ) -> SecretRecord:
        normalized_name = name.strip()
        normalized_provider = provider.strip()
        normalized_kind = kind.strip()
        normalized_value = _normalize_secret_value(value)

        if not normalized_name:
            raise ValueError("Secret name is required")
        if not normalized_value:
            raise ValueError("Secret value is required")
        if not normalized_provider:
            raise ValueError("Secret provider is required")
        if not normalized_kind:
            raise ValueError("Secret kind is required")
        if normalized_name in self._records_by_name:
            raise ValueError(f"Secret '{normalized_name}' already exists")

        now = _utc_now()
        record = SecretRecord(
            secret_id=self._allocate_secret_id(),
            name=normalized_name,
            provider=normalized_provider,
            kind=normalized_kind,
            hashed_value=_hash_secret(normalized_value),
            masked_value=_mask_secret(normalized_value),
            created_at=now,
            updated_at=now,
            last_used_at=None,
            active=True,
            metadata=dict(metadata or {}),
            raw_value=normalized_value,
        )

        self._records_by_id[record.secret_id] = record
        self._records_by_name[record.name] = record.secret_id
        return record

    def get_secret(self, secret_id: str) -> SecretRecord | None:
        return self._records_by_id.get(secret_id)

    def get_secret_by_name(self, name: str) -> SecretRecord | None:
        secret_id = self._records_by_name.get(name.strip())
        if not secret_id:
            return None
        return self._records_by_id.get(secret_id)

    def list_secrets(self, *, include_inactive: bool = True) -> list[SecretRecord]:
        records = list(self._records_by_id.values())
        if include_inactive:
            return records
        return [record for record in records if record.active]

    def rotate_secret(
        self,
        secret_id: str,
        *,
        new_value: str,
        metadata: dict[str, Any] | None = None,
    ) -> SecretRecord | None:
        record = self._records_by_id.get(secret_id)
        if record is None or not record.active:
            return None

        normalized_value = _normalize_secret_value(new_value)
        if not normalized_value:
            raise ValueError("New secret value is required")

        merged_metadata = dict(record.metadata)
        if metadata:
            merged_metadata.update(metadata)
        merged_metadata["rotated_at"] = _utc_now_iso()

        updated = SecretRecord(
            secret_id=record.secret_id,
            name=record.name,
            provider=record.provider,
            kind=record.kind,
            hashed_value=_hash_secret(normalized_value),
            masked_value=_mask_secret(normalized_value),
            created_at=record.created_at,
            updated_at=_utc_now(),
            last_used_at=record.last_used_at,
            active=True,
            metadata=merged_metadata,
            raw_value=normalized_value,
        )
        self._records_by_id[secret_id] = updated
        return updated

    def revoke_secret(self, secret_id: str) -> SecretRecord | None:
        record = self._records_by_id.get(secret_id)
        if record is None:
            return None

        updated = replace(
            record,
            active=False,
            updated_at=_utc_now(),
            raw_value=None,
        )
        self._records_by_id[secret_id] = updated
        return updated

    def record_secret_use(self, secret_id: str) -> SecretRecord | None:
        record = self._records_by_id.get(secret_id)
        if record is None or not record.active:
            return None

        updated = replace(
            record,
            last_used_at=_utc_now(),
            updated_at=_utc_now(),
            raw_value=None,
        )
        self._records_by_id[secret_id] = updated
        return updated

    def verify_secret_value(self, secret_id: str, candidate_value: str) -> bool:
        record = self._records_by_id.get(secret_id)
        if record is None or not record.active:
            return False
        normalized_candidate = _normalize_secret_value(candidate_value)
        if not normalized_candidate:
            return False
        return record.hashed_value == _hash_secret(normalized_candidate)

    def resolve_secret_key(
        self,
        override: str | None = None,
        *,
        env_names: tuple[str, ...] = (
            "SECRET_KEY",
            "IRONCLAW_SECRET_KEY",
            "APP_SECRET_KEY",
        ),
        config: Any = None,
    ) -> str:
        return resolve_secret_key(override, env_names=env_names, config=config)

    def clear(self) -> None:
        self._records_by_id.clear()
        self._records_by_name.clear()
        self._next_id = 1

    def _allocate_secret_id(self) -> str:
        secret_id = f"secret_{self._next_id}"
        self._next_id += 1
        return secret_id


_secret_service = SecretService()


def get_secret_service() -> SecretService:
    return _secret_service


def create_secret_service() -> SecretService:
    return SecretService()
