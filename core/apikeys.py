from __future__ import annotations

import hashlib
import secrets
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

KeyScope = Literal["internal", "customer", "service"]
KeyStatus = Literal["active", "revoked"]


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def hash_api_key(raw_key: str) -> str:
    if not raw_key or not raw_key.strip():
        raise ValueError("raw_key is required")
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()


def mask_api_key(raw_key: str) -> str:
    if not raw_key:
        return ""
    if len(raw_key) <= 8:
        return "*" * len(raw_key)
    return f"{raw_key[:4]}...{raw_key[-4:]}"


def build_api_key(prefix: str = "ic") -> str:
    normalized_prefix = (prefix or "ic").strip().lower().replace(" ", "-")
    token = secrets.token_urlsafe(32).replace("-", "").replace("_", "")
    return f"{normalized_prefix}_{token}"


@dataclass(slots=True)
class ApiKeyRecord:
    key_id: str
    name: str
    key_prefix: str
    key_hint: str
    key_hash: str
    scope: KeyScope
    status: KeyStatus = "active"
    owner_id: str | None = None
    created_at: str = ""
    updated_at: str = ""
    last_used_at: str | None = None
    revoked_at: str | None = None

    def is_active(self) -> bool:
        return self.status == "active"


class ApiKeyRegistry:
    def __init__(self) -> None:
        self._records_by_id: dict[str, ApiKeyRecord] = {}

    def create_key(
        self,
        *,
        name: str,
        scope: KeyScope = "customer",
        owner_id: str | None = None,
        prefix: str = "ic",
    ) -> tuple[ApiKeyRecord, str]:
        normalized_name = name.strip()
        if not normalized_name:
            raise ValueError("name is required")

        raw_key = build_api_key(prefix=prefix)
        now = utc_now_iso()
        record = ApiKeyRecord(
            key_id=secrets.token_hex(12),
            name=normalized_name,
            key_prefix=raw_key.split("_", 1)[0],
            key_hint=mask_api_key(raw_key),
            key_hash=hash_api_key(raw_key),
            scope=scope,
            owner_id=owner_id,
            created_at=now,
            updated_at=now,
        )
        self._records_by_id[record.key_id] = record
        return record, raw_key

    def list_keys(
        self,
        *,
        owner_id: str | None = None,
        scope: KeyScope | None = None,
        status: KeyStatus | None = None,
    ) -> list[ApiKeyRecord]:
        records: Iterable[ApiKeyRecord] = self._records_by_id.values()

        if owner_id is not None:
            records = [r for r in records if r.owner_id == owner_id]
        if scope is not None:
            records = [r for r in records if r.scope == scope]
        if status is not None:
            records = [r for r in records if r.status == status]

        return sorted(records, key=lambda r: (r.created_at, r.key_id), reverse=True)

    def get_key(self, key_id: str) -> ApiKeyRecord | None:
        return self._records_by_id.get(key_id)

    def authenticate(self, raw_key: str) -> ApiKeyRecord | None:
        key_hash = hash_api_key(raw_key)
        for record in self._records_by_id.values():
            if record.key_hash == key_hash and record.status == "active":
                record.last_used_at = utc_now_iso()
                record.updated_at = record.last_used_at
                return record
        return None

    def revoke_key(self, key_id: str) -> ApiKeyRecord:
        record = self._records_by_id.get(key_id)
        if record is None:
            raise KeyError(f"API key not found: {key_id}")
        if record.status == "revoked":
            return record

        now = utc_now_iso()
        record.status = "revoked"
        record.revoked_at = now
        record.updated_at = now
        return record

    def rotate_key(self, key_id: str, *, prefix: str = "ic") -> tuple[ApiKeyRecord, str]:
        record = self._records_by_id.get(key_id)
        if record is None:
            raise KeyError(f"API key not found: {key_id}")
        if record.status != "active":
            raise ValueError("only active API keys can be rotated")

        raw_key = build_api_key(prefix=prefix)
        now = utc_now_iso()
        record.key_prefix = raw_key.split("_", 1)[0]
        record.key_hint = mask_api_key(raw_key)
        record.key_hash = hash_api_key(raw_key)
        record.updated_at = now
        record.last_used_at = None
        return record, raw_key


registry = ApiKeyRegistry()


def create_internal_platform_key(name: str = "IronClaw-Security") -> tuple[ApiKeyRecord, str]:
    return registry.create_key(
        name=name,
        scope="internal",
        owner_id="ironclaw-system",
        prefix="ironclaw",
    )


def create_customer_api_key(
    *,
    name: str,
    owner_id: str,
) -> tuple[ApiKeyRecord, str]:
    return registry.create_key(
        name=name,
        scope="customer",
        owner_id=owner_id,
        prefix="icpk",
    )