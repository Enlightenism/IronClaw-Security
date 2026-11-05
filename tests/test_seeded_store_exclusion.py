from __future__ import annotations

from app.services.audit_store import SecurityAuditEventStore
from app.services.incident_store import IncidentStoreInMemory


def test_incident_store_excludes_seeded_records_from_production_kpis() -> None:
    store = IncidentStoreInMemory()
    store.seed_defaults()
    seeded_total = len(store.list_incidents())
    assert seeded_total > 0

    store.create_incident(
        title="Return gate block",
        summary="Blocked return content",
        severity="high",
        source="ironclaw",
        metadata={"owner_key": "owner_prod"},
    )

    production = store.list_incidents(include_seeded=False)
    assert len(production) == 1
    assert production[0].metadata.get("owner_key") == "owner_prod"
    assert all(not item.metadata.get("seeded") for item in production)

    assert store.summarize(include_seeded=False)["total"] == 1
    assert store.summarize()["total"] == seeded_total + 1


def test_audit_store_excludes_seeded_events_from_production_kpis() -> None:
    store = SecurityAuditEventStore()
    store.seed_defaults()
    seeded_total = len(store.list_events())
    assert seeded_total > 0

    store.create_event(
        event_type="return_gate.block",
        severity="high",
        summary="Return gate decision",
        verdict="block",
        metadata={"owner_key": "owner_prod"},
    )

    production = store.list_events(include_seeded=False)
    assert len(production) == 1
    assert production[0].event_type == "return_gate.block"
    assert all(not item.metadata.get("seeded") for item in production)

    assert store.summarize(include_seeded=False)["total"] == 1
    assert store.summarize()["total"] == seeded_total + 1
