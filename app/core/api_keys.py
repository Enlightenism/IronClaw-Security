from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from secrets import token_urlsafe
from typing import Any, Dict, Optional


API_KEY_PREFIX = "icg1_"
API_KEY_LENGTH_BYTES = 32


@dataclass(frozen=True)
class APIKeyRecord:
    """
    In-memory API key record for a single customer or integration.

    Local-first v1 design:
    - No persistence layer required for initial build/test cycles.
    - Contract is stable enough to later back with Supabase or another DB.
    - Raw key material is only returned at creation/rotation time.
    """

    key_id: str
    display_name: str
    hashed_secret: str
    created_at: datetime
    last_used_at: Optional[datetime] = None
    active: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    raw_key: Optional[str] = None


class APIKeyRegistry:
    """
    Simple in-memory API key registry.

    Supports:
    - create/register
    - resolve/last-used tracking
    - deactivate/revoke
    - rotate
    - list/get
    """

    def __init__(self) -> None:
        self._keys_by_id: Dict[str, APIKeyRecord] = {}
        self._keys_by_secret_hash: Dict[str, str] = {}
        self._next_id = 1

    def register_key(
        self,
        display_name: str,
        raw_secret: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> APIKeyRecord:
        key_id = self._allocate_key_id()
        now = datetime.now(UTC)
        secret_hash = self._hash_secret(raw_secret)

        record = APIKeyRecord(
            key_id=key_id,
            display_name=display_name,
            hashed_secret=secret_hash,
            created_at=now,
            last_used_at=None,
            active=True,
            metadata=dict(metadata or {}),
            raw_key=raw_secret,
        )

        self._keys_by_id[key_id] = record
        self._keys_by_secret_hash[secret_hash] = key_id
        return record

    def create_key(
        self,
        display_name: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> APIKeyRecord:
        raw_secret = generate_api_key()
        return self.register_key(
            display_name=display_name,
            raw_secret=raw_secret,
            metadata=metadata,
        )

    def list_keys(self) -> Dict[str, APIKeyRecord]:
        return dict(self._keys_by_id)

    def get_key(self, key_id: str) -> Optional[APIKeyRecord]:
        return self._keys_by_id.get(key_id)

    def deactivate_key(self, key_id: str) -> Optional[APIKeyRecord]:
        record = self._keys_by_id.get(key_id)
        if not record:
            return None

        updated = replace(record, active=False, raw_key=None)
        self._keys_by_id[key_id] = updated
        self._keys_by_secret_hash.pop(record.hashed_secret, None)
        return updated

    def revoke_key(self, key_id: str) -> Optional[APIKeyRecord]:
        return self.deactivate_key(key_id)

    def rotate_key(self, key_id: str) -> Optional[APIKeyRecord]:
        record = self._keys_by_id.get(key_id)
        if not record or not record.active:
            return None

        self._keys_by_secret_hash.pop(record.hashed_secret, None)

        new_raw_key = generate_api_key()
        new_secret_hash = self._hash_secret(new_raw_key)

        updated = APIKeyRecord(
            key_id=record.key_id,
            display_name=record.display_name,
            hashed_secret=new_secret_hash,
            created_at=record.created_at,
            last_used_at=None,
            active=True,
            metadata=dict(record.metadata),
            raw_key=new_raw_key,
        )

        self._keys_by_id[key_id] = updated
        self._keys_by_secret_hash[new_secret_hash] = key_id
        return updated

    def resolve_api_key(self, raw_secret: str) -> Optional[APIKeyRecord]:
        secret_hash = self._hash_secret(raw_secret)
        key_id = self._keys_by_secret_hash.get(secret_hash)
        if not key_id:
            return None

        record = self._keys_by_id.get(key_id)
        if not record or not record.active:
            return None

        if not hmac.compare_digest(record.hashed_secret, secret_hash):
            return None

        updated = APIKeyRecord(
            key_id=record.key_id,
            display_name=record.display_name,
            hashed_secret=record.hashed_secret,
            created_at=record.created_at,
            last_used_at=datetime.now(UTC),
            active=record.active,
            metadata=dict(record.metadata),
            raw_key=None,
        )
        self._keys_by_id[key_id] = updated
        return updated

    def clear(self) -> None:
        self._keys_by_id.clear()
        self._keys_by_secret_hash.clear()
        self._next_id = 1

    def _allocate_key_id(self) -> str:
        key_id = f"key_{self._next_id}"
        self._next_id += 1
        return key_id

    @staticmethod
    def _hash_secret(raw_secret: str) -> str:
        return hashlib.sha256(raw_secret.encode("utf-8")).hexdigest()


def generate_api_key() -> str:
    random_part = token_urlsafe(API_KEY_LENGTH_BYTES)
    return f"{API_KEY_PREFIX}{random_part}"


def mask_api_key(api_key: str) -> str:
    if len(api_key) <= 12:
        return api_key
    prefix = api_key[:8]
    suffix = api_key[-4:]
    return f"{prefix}…{suffix}"


_api_key_registry = APIKeyRegistry()


def get_api_key_registry() -> APIKeyRegistry:
    return _api_key_registry


def create_api_key_registry() -> APIKeyRegistry:
    return APIKeyRegistry()