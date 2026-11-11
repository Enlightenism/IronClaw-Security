from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from app.services.audit_store import AuditEventRecord, SecurityAuditEventStore
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


def test_block_events_are_written_through_to_durable_writer_only() -> None:
    written: list[str] = []
    store = SecurityAuditEventStore(durable_writer=lambda event: written.append(event.event_id))

    blocked = store.create_event(event_type="action.block", severity="high", summary="Blocked", verdict="block")
    store.create_event(event_type="action.allow", severity="low", summary="Allowed", verdict="allow")

    assert written == [blocked.event_id]


def test_durable_writer_failure_does_not_break_event_recording() -> None:
    def failing_writer(event: AuditEventRecord) -> None:
        raise RuntimeError("supabase unavailable")

    store = SecurityAuditEventStore(durable_writer=failing_writer)
    event = store.create_event(event_type="action.block", severity="high", summary="Blocked", verdict="block")

    assert store.get_event(event.event_id) is event


def test_durable_history_is_hydrated_ahead_of_live_events() -> None:
    durable = AuditEventRecord(
        event_id="audit-durable01",
        event_type="action.block",
        severity="high",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
        verdict="block",
        summary="Recorded before restart",
    )
    store = SecurityAuditEventStore(durable_loader=lambda: [durable])
    live = store.create_event(event_type="action.block", severity="high", summary="Blocked", verdict="block")

    assert [item.event_id for item in store.list_events(limit=None)] == ["audit-durable01", live.event_id]
    assert store.count() == 2


def test_hydration_skips_events_already_recorded_in_process() -> None:
    pending: list[AuditEventRecord] = []
    store = SecurityAuditEventStore(durable_loader=lambda: list(pending))
    live = store.create_event(event_type="action.block", severity="high", summary="Blocked", verdict="block")
    pending.append(live)

    assert [item.event_id for item in store.list_events(limit=None)] == [live.event_id]


def test_hydration_retries_after_loader_failure() -> None:
    durable = AuditEventRecord(
        event_id="audit-durable02",
        event_type="action.block",
        severity="high",
        created_at=datetime(2025, 1, 1, tzinfo=UTC),
        verdict="block",
        summary="Recorded before restart",
    )
    attempts = {"count": 0}

    def flaky_loader() -> list[AuditEventRecord]:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("supabase unavailable")
        return [durable]

    store = SecurityAuditEventStore(durable_loader=flaky_loader)

    assert store.list_events(limit=None) == []
    assert [item.event_id for item in store.list_events(limit=None)] == ["audit-durable02"]


class _FakeSecurityAuditQuery:
    def __init__(self, rows: list[dict[str, str]], offsets: list[tuple[int, int]]) -> None:
        self._rows = rows
        self._offsets = offsets
        self._window = (0, 0)

    def select(self, *_args: str) -> _FakeSecurityAuditQuery:
        return self

    def order(self, *_args: str, **_kwargs: bool) -> _FakeSecurityAuditQuery:
        return self

    def range(self, start: int, end: int) -> _FakeSecurityAuditQuery:
        self._window = (start, end)
        self._offsets.append((start, end))
        return self

    def execute(self) -> SimpleNamespace:
        start, end = self._window
        return SimpleNamespace(data=self._rows[start : end + 1])


class _FakeSecurityAuditClient:
    def __init__(self, rows: list[dict[str, str]]) -> None:
        self._rows = rows
        self.offsets: list[tuple[int, int]] = []

    def table(self, _name: str) -> _FakeSecurityAuditQuery:
        return _FakeSecurityAuditQuery(self._rows, self.offsets)


def test_list_security_audit_events_reads_every_page(monkeypatch) -> None:
    from app.core import supabase_persistence

    rows = [{"event_id": f"audit-{index:05d}"} for index in range(2250)]
    client = _FakeSecurityAuditClient(rows)
    monkeypatch.setattr(supabase_persistence, "get_supabase_service_client", lambda: client)

    loaded = supabase_persistence.list_security_audit_events()

    assert len(loaded) == 2250
    assert loaded[0]["event_id"] == "audit-02249"
    assert loaded[-1]["event_id"] == "audit-00000"
    assert client.offsets == [(0, 999), (1000, 1999), (2000, 2999)]
