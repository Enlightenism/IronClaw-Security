from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
import hashlib
import hmac
import secrets
from threading import RLock
from typing import Any

_API_KEY_PREFIX = "ic_"
_API_KEY_SECRET_BYTES = 24
_DEFAULT_OWNER_KEY = "ironclaw-system"
_DEFAULT_SCOPES = ("system",)
_DEFAULT_RATE_PLAN = "internal"
_DEFAULT_CREATED_BY = "system"


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _normalize_metadata(metadata: dict[str, Any] | None) -> dict[str, Any]:
    return dict(metadata or {})


def _normalize_scopes(scopes: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    if not scopes:
        return _DEFAULT_SCOPES
    cleaned = tuple(scope.strip() for scope in scopes if str(scope).strip())
    return cleaned or _DEFAULT_SCOPES


def mask_api_key(api_key: str) -> str:
    if len(api_key) <= 10:
        return "*" * len(api_key)
    return f"{api_key[:6]}...{api_key[-4:]}"


def generate_api_key(prefix: str = _API_KEY_PREFIX) -> str:
    return f"{prefix}{secrets.token_urlsafe(_API_KEY_SECRET_BYTES)}"


def fingerprint_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def constant_time_api_key_match(provided_key: str, expected_key: str) -> bool:
    return hmac.compare_digest(provided_key, expected_key)


def is_api_key_expired(record: APIKeyRecord) -> bool:
    """Return True if the record is inactive (revoked). No TTL field exists yet."""
    return not record.active


@dataclass(frozen=True)
class APIKeyRecord:
    key_id: str
    api_key: str
    masked_key: str
    fingerprint: str
    display_name: str
    owner_key: str = _DEFAULT_OWNER_KEY
    scopes: tuple[str, ...] = field(default_factory=lambda: _DEFAULT_SCOPES)
    active: bool = True
    created_at: str = field(default_factory=utc_now_iso)
    created_by: str = _DEFAULT_CREATED_BY
    last_used_at: str | None = None
    revoked_at: str | None = None
    revoked_by: str | None = None
    rate_plan: str = _DEFAULT_RATE_PLAN
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self, when: str | None = None) -> APIKeyRecord:
        return replace(self, last_used_at=when or utc_now_iso())

    def revoke(self, revoked_by: str = _DEFAULT_CREATED_BY, when: str | None = None) -> APIKeyRecord:
        timestamp = when or utc_now_iso()
        return replace(
            self,
            active=False,
            revoked_at=timestamp,
            revoked_by=revoked_by,
        )

    def public_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "display_name": self.display_name,
            "masked_key": self.masked_key,
            "created_at": self.created_at,
            "last_used_at": self.last_used_at,
            "active": self.active,
            "owner_key": self.owner_key,
            "scopes": list(self.scopes),
            "rate_plan": self.rate_plan,
            "metadata": dict(self.metadata),
        }


class APIKeyRegistry:
    def __init__(self) -> None:
        self._lock = RLock()
        self._records_by_id: dict[str, APIKeyRecord] = {}
        self._key_id_by_secret: dict[str, str] = {}

    def create_key(
        self,
        display_name: str,
        *,
        owner_key: str = _DEFAULT_OWNER_KEY,
        scopes: list[str] | tuple[str, ...] | None = None,
        metadata: dict[str, Any] | None = None,
        created_by: str = _DEFAULT_CREATED_BY,
        rate_plan: str = _DEFAULT_RATE_PLAN,
        api_key: str | None = None,
        key_id: str | None = None,
    ) -> APIKeyRecord:
        issued_key = api_key or generate_api_key()
        issued_key_id = key_id or self._new_key_id()
        record = APIKeyRecord(
            key_id=issued_key_id,
            api_key=issued_key,
            masked_key=mask_api_key(issued_key),
            fingerprint=fingerprint_api_key(issued_key),
            display_name=display_name.strip(),
            owner_key=owner_key.strip() or _DEFAULT_OWNER_KEY,
            scopes=_normalize_scopes(scopes),
            created_by=created_by.strip() or _DEFAULT_CREATED_BY,
            rate_plan=rate_plan.strip() or _DEFAULT_RATE_PLAN,
            metadata=_normalize_metadata(metadata),
        )
        with self._lock:
            self._records_by_id[record.key_id] = record
            self._key_id_by_secret[record.api_key] = record.key_id
        return record

    def list_keys(self, *, active_only: bool = False) -> list[APIKeyRecord]:
        with self._lock:
            items = list(self._records_by_id.values())
        items.sort(key=lambda item: item.created_at, reverse=True)
        if active_only:
            items = [item for item in items if item.active]
        return items

    def get_by_id(self, key_id: str) -> APIKeyRecord | None:
        with self._lock:
            return self._records_by_id.get(key_id)

    def resolve_api_key(self, api_key: str) -> APIKeyRecord | None:
        with self._lock:
            key_id = self._key_id_by_secret.get(api_key)
            if not key_id:
                return None
            return self._records_by_id.get(key_id)

    def authenticate(self, api_key: str, *, touch: bool = True) -> APIKeyRecord | None:
        with self._lock:
            key_id = self._key_id_by_secret.get(api_key)
            if not key_id:
                return None
            record = self._records_by_id.get(key_id)
            if record is None or not record.active:
                return None
            if not constant_time_api_key_match(api_key, record.api_key):
                return None
            if touch:
                record = record.touch()
                self._records_by_id[key_id] = record
            return record

    def revoke_key(self, key_id: str, *, revoked_by: str = _DEFAULT_CREATED_BY) -> APIKeyRecord | None:
        with self._lock:
            record = self._records_by_id.get(key_id)
            if record is None:
                return None
            updated = record if not record.active else record.revoke(revoked_by=revoked_by)
            self._records_by_id[key_id] = updated
            return updated

    def rotate_key(
        self,
        key_id: str,
        *,
        rotated_by: str = _DEFAULT_CREATED_BY,
        metadata: dict[str, Any] | None = None,
    ) -> APIKeyRecord | None:
        with self._lock:
            record = self._records_by_id.get(key_id)
            if record is None:
                return None
            new_secret = generate_api_key()
            updated_metadata = dict(record.metadata)
            updated_metadata.update(_normalize_metadata(metadata))
            updated_metadata["rotated_by"] = rotated_by
            updated_metadata["rotated_from_fingerprint"] = record.fingerprint
            updated = replace(
                record,
                api_key=new_secret,
                masked_key=mask_api_key(new_secret),
                fingerprint=fingerprint_api_key(new_secret),
                active=True,
                revoked_at=None,
                revoked_by=None,
                metadata=updated_metadata,
            )
            self._records_by_id[key_id] = updated
            self._key_id_by_secret.pop(record.api_key, None)
            self._key_id_by_secret[updated.api_key] = key_id
            return updated

    def upsert_record(self, record: APIKeyRecord) -> APIKeyRecord:
        with self._lock:
            existing = self._records_by_id.get(record.key_id)
            if existing and existing.api_key != record.api_key:
                self._key_id_by_secret.pop(existing.api_key, None)
            self._records_by_id[record.key_id] = record
            self._key_id_by_secret[record.api_key] = record.key_id
        return record

    def ensure_default_key(self) -> APIKeyRecord:
        with self._lock:
            for record in self._records_by_id.values():
                if record.display_name == "Default System Key" and record.owner_key == _DEFAULT_OWNER_KEY:
                    return record
        return self.create_key(
            "Default System Key",
            owner_key=_DEFAULT_OWNER_KEY,
            scopes=("system", "admin"),
            metadata={"bootstrap": True},
            created_by="bootstrap",
            rate_plan="internal",
        )

    def summary(self) -> dict[str, Any]:
        with self._lock:
            records = list(self._records_by_id.values())
        active = sum(1 for record in records if record.active)
        revoked = len(records) - active
        return {
            "total": len(records),
            "active": active,
            "revoked": revoked,
        }

    @staticmethod
    def _new_key_id() -> str:
        return f"key_{secrets.token_hex(8)}"


_registry = APIKeyRegistry()


def get_api_key_registry() -> APIKeyRegistry:
    return _registry


def create_api_key(
    display_name: str,
    *,
    owner_key: str = _DEFAULT_OWNER_KEY,
    scopes: list[str] | tuple[str, ...] | None = None,
    metadata: dict[str, Any] | None = None,
    created_by: str = _DEFAULT_CREATED_BY,
    rate_plan: str = _DEFAULT_RATE_PLAN,
) -> APIKeyRecord:
    return _registry.create_key(
        display_name,
        owner_key=owner_key,
        scopes=scopes,
        metadata=metadata,
        created_by=created_by,
        rate_plan=rate_plan,
    )


def authenticate_api_key(api_key: str, *, touch: bool = True) -> APIKeyRecord | None:
    return _registry.authenticate(api_key, touch=touch)


def revoke_api_key(key_id: str, *, revoked_by: str = _DEFAULT_CREATED_BY) -> APIKeyRecord | None:
    return _registry.revoke_key(key_id, revoked_by=revoked_by)


def rotate_api_key(
    key_id: str,
    *,
    rotated_by: str = _DEFAULT_CREATED_BY,
    metadata: dict[str, Any] | None = None,
) -> APIKeyRecord | None:
    return _registry.rotate_key(key_id, rotated_by=rotated_by, metadata=metadata)
