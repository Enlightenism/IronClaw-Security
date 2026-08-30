"""System service API keys.

This registry is intentionally separate from the paid customer install-key
registry in app.core.install_keys.

It is for internal service authentication only and is not a payment-bound
install token source. Install keys are generated only by the canonical
InstallKeyRegistry after successful payment and entitlement checks.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
import hashlib
import hmac
import secrets
from threading import RLock
from typing import Any

_API_KEY_PREFIX = "ic_"
_ORG_KEY_PREFIX = "ic_org_"
_INSTALL_KEY_PREFIX = "ic_install_"
_API_KEY_SECRET_BYTES = 24
_DEFAULT_OWNER_KEY = "ironclaw-system"
_DEFAULT_SCOPES = ("system",)
_DEFAULT_RATE_PLAN = "internal"
_DEFAULT_CREATED_BY = "system"


def classify_api_key(value: str | None) -> str:
    if value is None:
        return "unknown"
    candidate = str(value).strip()
    if not candidate:
        return "unknown"
    if candidate.startswith(_INSTALL_KEY_PREFIX):
        return "install"
    if candidate.startswith(_ORG_KEY_PREFIX):
        return "org"
    if candidate.startswith(_API_KEY_PREFIX):
        return "system"
    return "unknown"


def _looks_like_install_key(value: str | None) -> bool:
    return classify_api_key(value) == "install"


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


def _assert_service_key_prefix(prefix: str) -> None:
    cleaned = str(prefix).strip()
    if classify_api_key(cleaned) == "install":
        raise ValueError(
            "System API keys are not install keys; install tokens must be issued only by app.core.install_keys after a successful paid entitlement.",
        )


def generate_api_key(prefix: str = _API_KEY_PREFIX) -> str:
    """Generate a system service key.

    This registry is not a customer install-key source. Any attempt to generate
    an install-key-style value here is rejected.
    """
    _assert_service_key_prefix(prefix)
    return f"{prefix}{secrets.token_urlsafe(_API_KEY_SECRET_BYTES)}"


def generate_org_api_key() -> str:
    """Generate a new org-scoped API key using the org prefix."""
    return generate_api_key(prefix=_ORG_KEY_PREFIX)


def fingerprint_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def constant_time_api_key_match(provided_key: str, expected_key: str) -> bool:
    return hmac.compare_digest(provided_key, expected_key)


def is_api_key_expired(record: APIKeyRecord) -> bool:
    """Return True if the record is inactive (revoked). No TTL field exists yet."""
    return not record.active


@dataclass(frozen=True)
class APIKeyRecord:
    """Internal service credential record.

    This record does not represent a customer install token, a paid entitlement,
    or a payment-bound runtime key. Install keys belong to the separate
    InstallKeyRegistry and must not be surfaced from this layer.
    """

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
    key_type: str = "personal"
    org_id: str | None = None

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
            "key_type": self.key_type,
            "org_id": self.org_id,
        }


class APIKeyRegistry:
    """Registry for system-wide internal service keys only.

    This is not a payment-bound install token source. Customer install keys are
    created and authenticated by app.core.install_keys.InstallKeyRegistry after
    successful payment and entitlement checks.
    """

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
        prefix: str = _API_KEY_PREFIX,
        key_type: str = "personal",
        org_id: str | None = None,
    ) -> APIKeyRecord:
        _assert_service_key_prefix(prefix)
        if api_key is not None:
            candidate_api_key = str(api_key).strip()
            if classify_api_key(candidate_api_key) == "install":
                raise ValueError(
                    "System API keys cannot be install keys; install keys must be generated by the paid install-key registry.",
                )
        issued_key = api_key or generate_api_key(prefix=prefix)
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
            key_type=key_type,
            org_id=org_id,
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

    def list_keys_by_org(self, org_id: str, *, active_only: bool = False) -> list[APIKeyRecord]:
        """Return all keys belonging to a given org_id."""
        with self._lock:
            items = [r for r in self._records_by_id.values() if r.org_id == org_id]
        items.sort(key=lambda item: item.created_at, reverse=True)
        if active_only:
            items = [item for item in items if item.active]
        return items

    def get_by_id(self, key_id: str) -> APIKeyRecord | None:
        with self._lock:
            return self._records_by_id.get(key_id)

    def get_by_fingerprint(self, fingerprint: str) -> APIKeyRecord | None:
        with self._lock:
            for record in self._records_by_id.values():
                if record.fingerprint == fingerprint:
                    return record
        return None

    def resolve_api_key(self, api_key: str) -> APIKeyRecord | None:
        if classify_api_key(api_key) == "install":
            return None
        with self._lock:
            key_id = self._key_id_by_secret.get(api_key)
            if not key_id:
                return None
            return self._records_by_id.get(key_id)

    def authenticate(self, api_key: str, *, touch: bool = True) -> APIKeyRecord | None:
        if classify_api_key(api_key) == "install":
            return None
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
            prefix = _ORG_KEY_PREFIX if record.key_type == "org" else _API_KEY_PREFIX
            new_secret = generate_api_key(prefix=prefix)
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
        org_keys = sum(1 for record in records if record.key_type == "org")
        return {
            "total": len(records),
            "active": active,
            "revoked": revoked,
            "org_keys": org_keys,
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


def create_org_key(
    org_id: str,
    display_name: str,
    *,
    owner_key: str = _DEFAULT_OWNER_KEY,
    scopes: list[str] | tuple[str, ...] | None = None,
    metadata: dict[str, Any] | None = None,
    created_by: str = _DEFAULT_CREATED_BY,
    rate_plan: str = _DEFAULT_RATE_PLAN,
) -> APIKeyRecord:
    """Factory for org-scoped shared API keys. Uses the ic_org_ prefix and sets key_type='org'."""
    return _registry.create_key(
        display_name,
        owner_key=owner_key,
        scopes=scopes,
        metadata=metadata,
        created_by=created_by,
        rate_plan=rate_plan,
        prefix=_ORG_KEY_PREFIX,
        key_type="org",
        org_id=org_id,
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


# Legacy-compatible aliases used by older imports and compatibility shims.
ApiKeyRecord = APIKeyRecord
ApiKeyRegistry = APIKeyRegistry
registry = _registry
