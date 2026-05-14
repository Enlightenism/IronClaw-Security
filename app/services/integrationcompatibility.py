from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Literal

CompatibilityState = Literal[
    "unknown",
    "compatible",
    "incompatible",
    "warning",
]


@dataclass(slots=True)
class IntegrationCompatibilityRecord:
    integrationid: str
    platform: str
    adapterversion: str
    state: CompatibilityState
    checkedat: str
    runtimeversion: str | None = None
    details: str | None = None


class IntegrationCompatibilityService:
    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[str, IntegrationCompatibilityRecord] = {}

    def list_records(self) -> list[IntegrationCompatibilityRecord]:
        with self._lock:
            return list(self._records.values())

    def get_record(self, integrationid: str) -> IntegrationCompatibilityRecord | None:
        with self._lock:
            return self._records.get(integrationid)

    def ensure_record(
        self,
        integrationid: str,
        platform: str,
        adapterversion: str,
        runtimeversion: str | None = None,
    ) -> IntegrationCompatibilityRecord:
        with self._lock:
            existing = self._records.get(integrationid)
            if existing is not None:
                return existing

            record = IntegrationCompatibilityRecord(
                integrationid=integrationid,
                platform=platform,
                adapterversion=adapterversion,
                state="unknown",
                checkedat=_utcnow(),
                runtimeversion=runtimeversion,
            )
            self._records[integrationid] = record
            return record

    def mark_compatible(
        self,
        integrationid: str,
        adapterversion: str | None = None,
        runtimeversion: str | None = None,
        details: str | None = None,
    ) -> IntegrationCompatibilityRecord:
        with self._lock:
            record = self._require_record(integrationid)
            record.state = "compatible"
            record.checkedat = _utcnow()
            if adapterversion is not None:
                record.adapterversion = adapterversion
            if runtimeversion is not None:
                record.runtimeversion = runtimeversion
            if details is not None:
                record.details = details
            return record

    def mark_warning(
        self,
        integrationid: str,
        details: str,
        runtimeversion: str | None = None,
    ) -> IntegrationCompatibilityRecord:
        with self._lock:
            record = self._require_record(integrationid)
            record.state = "warning"
            record.checkedat = _utcnow()
            record.details = details
            if runtimeversion is not None:
                record.runtimeversion = runtimeversion
            return record

    def mark_incompatible(
        self,
        integrationid: str,
        details: str,
        runtimeversion: str | None = None,
    ) -> IntegrationCompatibilityRecord:
        with self._lock:
            record = self._require_record(integrationid)
            record.state = "incompatible"
            record.checkedat = _utcnow()
            record.details = details
            if runtimeversion is not None:
                record.runtimeversion = runtimeversion
            return record

    def export_records(self) -> list[dict[str, object]]:
        with self._lock:
            return [asdict(record) for record in self._records.values()]

    def _require_record(self, integrationid: str) -> IntegrationCompatibilityRecord:
        record = self._records.get(integrationid)
        if record is None:
            raise KeyError(f"unknown integration compatibility record: {integrationid}")
        return record


_service: IntegrationCompatibilityService | None = None


def get_integration_compatibility_service() -> IntegrationCompatibilityService:
    global _service
    if _service is None:
        _service = IntegrationCompatibilityService()
    return _service


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()
