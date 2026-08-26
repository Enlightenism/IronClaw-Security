from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from threading import RLock
from typing import Any

from fastapi import APIRouter, HTTPException, Path, Query, status
from pydantic import BaseModel, ConfigDict, Field

router = APIRouter(prefix="/customer-keys", tags=["customer-keys"])

_TOKEN_LIKE_METADATA_KEYS = {"token", "raw_key", "secret", "api_key", "install_key", "key_material", "key_value"}


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


@dataclass
class CustomerKeyRecord:
    key_id: str
    customer_id: str
    owner_key: str
    org_id: str | None = None
    display_name: str = ""
    active: bool = True
    scopes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=_utc_now_iso)
    updated_at: str = field(default_factory=_utc_now_iso)

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "customer_id": self.customer_id,
            "owner_key": self.owner_key,
            "org_id": self.org_id,
            "display_name": self.display_name,
            "active": self.active,
            "scopes": list(self.scopes),
            "metadata": dict(self.metadata),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class CustomerKeyCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    customer_id: str = Field(..., min_length=1, max_length=255)
    owner_key: str = Field(..., min_length=1, max_length=512)
    org_id: str | None = Field(default=None, max_length=255)
    display_name: str = Field(default="", min_length=0, max_length=200)
    scopes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class CustomerKeyUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=0, max_length=200)
    org_id: str | None = Field(default=None, max_length=255)
    active: bool | None = None
    scopes: list[str] | None = None
    metadata: dict[str, Any] | None = None


class CustomerKeyView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    key_id: str
    customer_id: str
    owner_key: str
    org_id: str | None = None
    display_name: str
    active: bool
    scopes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class CustomerKeyCreateResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key: CustomerKeyView


class CustomerKeyListResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    total: int
    items: list[CustomerKeyView]


class CustomerKeyRevokeResponse(BaseModel):
    status: str
    service: str
    timestamp: str
    key_id: str
    active: bool


class CustomerKeyRegistry:
    """Customer/account mapping registry for identity metadata only.

    The customer-key surface is not a runtime token issuer. Actual install-key
    issuance remains the responsibility of the install-key service after a valid
    paid entitlement has been confirmed.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._records_by_id: dict[str, CustomerKeyRecord] = {}
        self._records_by_customer: dict[str, list[str]] = {}

    def _new_key_id(self) -> str:
        return f"cust_{datetime.now(UTC).strftime('%Y%m%d%H%M%S%f')}_{len(self._records_by_id) + 1:04d}"

    def create(self, payload: CustomerKeyCreateRequest) -> CustomerKeyRecord:
        cleaned_customer_id = payload.customer_id.strip()
        cleaned_owner_key = payload.owner_key.strip()
        if not cleaned_customer_id:
            raise ValueError("customer_id is required")
        if not cleaned_owner_key:
            raise ValueError("owner_key is required")

        metadata_keys = {str(key).strip().lower() for key in (payload.metadata or {}).keys()}
        if metadata_keys & _TOKEN_LIKE_METADATA_KEYS:
            raise ValueError("Customer account mappings must not include install-token or secret material")

        key_id = self._new_key_id()
        record = CustomerKeyRecord(
            key_id=key_id,
            customer_id=cleaned_customer_id,
            owner_key=cleaned_owner_key,
            org_id=payload.org_id.strip() if payload.org_id and payload.org_id.strip() else None,
            display_name=(payload.display_name or cleaned_customer_id).strip() or cleaned_customer_id,
            active=True,
            scopes=[str(scope).strip() for scope in payload.scopes if str(scope).strip()],
            metadata=dict(payload.metadata or {}),
        )
        with self._lock:
            self._records_by_id[record.key_id] = record
            self._records_by_customer.setdefault(record.customer_id, []).append(record.key_id)
        return record

    def list(
        self,
        *,
        active_only: bool = False,
        owner_key: str | None = None,
        org_id: str | None = None,
    ) -> list[CustomerKeyRecord]:
        with self._lock:
            records = list(self._records_by_id.values())
        if active_only:
            records = [r for r in records if r.active]
        if owner_key is not None:
            owner_key = owner_key.strip()
            records = [r for r in records if r.owner_key == owner_key]
        if org_id is not None:
            org_id = org_id.strip()
            records = [r for r in records if r.org_id == org_id]
        records.sort(key=lambda item: item.created_at, reverse=True)
        return records

    def get_by_id(self, key_id: str) -> CustomerKeyRecord | None:
        with self._lock:
            return self._records_by_id.get(key_id)

    def get_by_customer(self, customer_id: str) -> list[CustomerKeyRecord]:
        with self._lock:
            key_ids = self._records_by_customer.get(customer_id, [])
            return [self._records_by_id[key_id] for key_id in key_ids if key_id in self._records_by_id]

    def update(self, key_id: str, payload: CustomerKeyUpdateRequest) -> CustomerKeyRecord | None:
        with self._lock:
            record = self._records_by_id.get(key_id)
            if record is None:
                return None

            if payload.display_name is not None:
                record.display_name = payload.display_name.strip() or record.display_name
            if payload.org_id is not None:
                record.org_id = payload.org_id.strip() or None
            if payload.active is not None:
                record.active = payload.active
            if payload.scopes is not None:
                record.scopes = [str(scope).strip() for scope in payload.scopes if str(scope).strip()]
            if payload.metadata is not None:
                metadata_keys = {str(key).strip().lower() for key in payload.metadata.keys()}
                if metadata_keys & _TOKEN_LIKE_METADATA_KEYS:
                    raise ValueError("Customer account mappings must not include install-token or secret material")
                record.metadata = dict(payload.metadata)
            record.updated_at = _utc_now_iso()
            return record

    def revoke(self, key_id: str) -> CustomerKeyRecord | None:
        with self._lock:
            record = self._records_by_id.get(key_id)
            if record is None:
                return None
            record.active = False
            record.updated_at = _utc_now_iso()
            return record


_registry: CustomerKeyRegistry | None = None


def get_customer_key_registry() -> CustomerKeyRegistry:
    global _registry
    if _registry is None:
        _registry = CustomerKeyRegistry()
    return _registry


def _record_to_view(record: CustomerKeyRecord) -> CustomerKeyView:
    public = record.to_public_dict()
    return CustomerKeyView(
        key_id=public["key_id"],
        customer_id=public["customer_id"],
        owner_key=public["owner_key"],
        org_id=public["org_id"],
        display_name=public["display_name"],
        active=public["active"],
        scopes=list(public["scopes"]),
        metadata=dict(public["metadata"]),
        created_at=public["created_at"],
        updated_at=public["updated_at"],
    )


@router.post("", response_model=CustomerKeyCreateResponse, status_code=status.HTTP_201_CREATED)
def create_customer_key(payload: CustomerKeyCreateRequest) -> CustomerKeyCreateResponse:
    try:
        record = get_customer_key_registry().create(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc

    return CustomerKeyCreateResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key=_record_to_view(record),
    )


@router.get("", response_model=CustomerKeyListResponse)
def list_customer_keys(
    active_only: bool = Query(default=False, description="Only return active customer mappings"),
    owner_key: str | None = Query(default=None, description="Filter by owner_key"),
    org_id: str | None = Query(default=None, description="Filter by org_id"),
) -> CustomerKeyListResponse:
    records = get_customer_key_registry().list(active_only=active_only, owner_key=owner_key, org_id=org_id)
    return CustomerKeyListResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        total=len(records),
        items=[_record_to_view(r) for r in records],
    )


@router.get("/{key_id}", response_model=CustomerKeyView)
def get_customer_key(
    key_id: str = Path(..., min_length=1, max_length=255),
) -> CustomerKeyView:
    record = get_customer_key_registry().get_by_id(key_id.strip())
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer key mapping not found")
    return _record_to_view(record)


@router.patch("/{key_id}", response_model=CustomerKeyView)
def update_customer_key(
    payload: CustomerKeyUpdateRequest,
    key_id: str = Path(..., min_length=1, max_length=255),
) -> CustomerKeyView:
    record = get_customer_key_registry().update(key_id.strip(), payload)
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer key mapping not found")
    return _record_to_view(record)


@router.post("/{key_id}/revoke", response_model=CustomerKeyRevokeResponse)
def revoke_customer_key(
    key_id: str = Path(..., min_length=1, max_length=255),
) -> CustomerKeyRevokeResponse:
    record = get_customer_key_registry().revoke(key_id.strip())
    if record is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Customer key mapping not found")
    return CustomerKeyRevokeResponse(
        status="ok",
        service="IronClaw-Security",
        timestamp=_utc_now_iso(),
        key_id=record.key_id,
        active=record.active,
    )
