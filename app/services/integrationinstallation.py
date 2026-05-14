from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from threading import Lock
from typing import Literal

InstallationState = Literal[
    "not_installed",
    "installing",
    "installed",
    "upgrade_required",
    "failed",
]


@dataclass(slots=True)
class IntegrationInstallationRecord:
    integrationid: str
    platform: str
    adapterversion: str
    state: InstallationState
    installedat: str | None
    updatedat: str
    details: str | None = None


class IntegrationInstallationService:
    def __init__(self) -> None:
        self._lock = Lock()
        self._records: dict[str, IntegrationInstallationRecord] = {}

    def list_records(self) -> list[IntegrationInstallationRecord]:
        with self._lock:
            return list(self._records.values())

    def get_record(self, integrationid: str) -> IntegrationInstallationRecord | None:
        with self._lock:
            return self._records.get(integrationid)

    def begin_installation(
        self,
        integrationid: str,
        platform: str,
        adapterversion: str,
        details: str | None = None,
    ) -> IntegrationInstallationRecord:
        timestamp = _utcnow()
        record = IntegrationInstallationRecord(
            integrationid=integrationid,
            platform=platform,
            adapterversion=adapterversion,
            state="installing",
            installedat=None,
            updatedat=timestamp,
            details=details,
        )
        with self._lock:
            self._records[integrationid] = record
        return record

    def mark_installed(
        self,
        integrationid: str,
        adapterversion: str | None = None,
        details: str | None = None,
    ) -> IntegrationInstallationRecord:
        with self._lock:
            record = self._require_record(integrationid)
            timestamp = _utcnow()
            record.state = "installed"
            record.installedat = timestamp
            record.updatedat = timestamp
            if adapterversion is not None:
                record.adapterversion = adapterversion
            if details is not None:
                record.details = details
            return record

    def mark_upgrade_required(
        self,
        integrationid: str,
        details: str | None = None,
    ) -> IntegrationInstallationRecord:
        with self._lock:
            record = self._require_record(integrationid)
            record.state = "upgrade_required"
            record.updatedat = _utcnow()
            if details is not None:
                record.details = details
            return record

    def mark_failed(
        self,
        integrationid: str,
        details: str,
    ) -> IntegrationInstallationRecord:
        with self._lock:
            record = self._require_record(integrationid)
            record.state = "failed"
            record.updatedat = _utcnow()
            record.details = details
            return record

    def ensure_record(
        self,
        integrationid: str,
        platform: str,
        adapterversion: str,
    ) -> IntegrationInstallationRecord:
        with self._lock:
            existing = self._records.get(integrationid)
            if existing is not None:
                return existing

            record = IntegrationInstallationRecord(
                integrationid=integrationid,
                platform=platform,
                adapterversion=adapterversion,
                state="not_installed",
                installedat=None,
                updatedat=_utcnow(),
            )
            self._records[integrationid] = record
            return record

    def export_records(self) -> list[dict[str, object]]:
        with self._lock:
            return [asdict(record) for record in self._records.values()]

    def _require_record(self, integrationid: str) -> IntegrationInstallationRecord:
        record = self._records.get(integrationid)
        if record is None:
            raise KeyError(f"unknown integration installation record: {integrationid}")
        return record


_service: IntegrationInstallationService | None = None


def get_integration_installation_service() -> IntegrationInstallationService:
    global _service
    if _service is None:
        _service = IntegrationInstallationService()
    return _service


def _utcnow() -> str:
    return datetime.now(UTC).isoformat()
