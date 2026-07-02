from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.core.supabase_persistence import (
    PersistenceError,
    get_agent_trust_profile,
    insert_trust_event,
    list_trust_events,
    upsert_agent_trust_profile,
)

# ---------------------------------------------------------------------------
# Patch target — canonical path used by every test in this module.
# Never import get_supabase_service_client directly in tests; always patch
# at the module level where it is consumed.
# ---------------------------------------------------------------------------
_PATCH_TARGET = "app.core.supabase_persistence.get_supabase_service_client"


# ---------------------------------------------------------------------------
# Helpers — query-builder mock factory
# ---------------------------------------------------------------------------


def _make_qb(return_data: object = None, *, side_effect: BaseException | None = None) -> MagicMock:
    """Return a chainable Supabase query-builder mock.

    Every fluent method returns the same mock so chaining works regardless
    of order. ``execute`` either returns a response mock or raises
    ``side_effect`` if provided.
    """
    qb = MagicMock()
    for method in (
        "select",
        "eq",
        "in_",
        "order",
        "range",
        "maybe_single",
        "upsert",
        "insert",
    ):
        getattr(qb, method).return_value = qb

    resp = MagicMock()
    resp.data = return_data

    if side_effect is not None:
        qb.execute.side_effect = side_effect
    else:
        qb.execute.return_value = resp

    return qb


def _make_client(return_data: object = None, *, side_effect: BaseException | None = None) -> MagicMock:
    """Return a Supabase client mock whose ``.table()`` yields ``_make_qb``."""
    qb = _make_qb(return_data, side_effect=side_effect)
    client = MagicMock()
    client.table.return_value = qb
    return client


def _supabase_errors():
    from app.supabaseclient import SupabaseAPIError, SupabaseClientError  # noqa: PLC0415

    return SupabaseAPIError, SupabaseClientError


# ---------------------------------------------------------------------------
# Sample fixtures
# ---------------------------------------------------------------------------

_PROFILE_ROW: dict = {
    "agent_id": "agent-trust-001",
    "trust_score": 0.75,
    "event_count": 3,
    "last_event_type": "anomaly_detected",
    "last_event_at": "2026-06-07T10:00:00+00:00",
    "created_at": "2026-06-01T00:00:00+00:00",
    "updated_at": "2026-06-07T10:00:00+00:00",
    "is_suspended": False,
    "suspension_reason": None,
    "metadata": {},
}

_EVENT_ROW: dict = {
    "event_id": "evt-abc-001",
    "agent_id": "agent-trust-001",
    "event_type": "anomaly_detected",
    "previous_score": 0.80,
    "new_score": 0.75,
    "delta": -0.05,
    "metadata": {},
    "recorded_at": "2026-06-07T10:00:00+00:00",
}


# ===========================================================================
# get_agent_trust_profile
# ===========================================================================


class TestGetAgentTrustProfile:
    def test_found_returns_dict(self):
        client = _make_client(_PROFILE_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_agent_trust_profile("agent-trust-001")

        assert result is not None
        assert result["agent_id"] == "agent-trust-001"
        assert result["trust_score"] == 0.75

    def test_found_as_single_element_list_returns_dict(self):
        """Supabase may return a list even for maybe_single in some adapters."""
        client = _make_client([_PROFILE_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_agent_trust_profile("agent-trust-001")

        assert result is not None
        assert result["agent_id"] == "agent-trust-001"

    def test_not_found_returns_none_when_data_is_none(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = get_agent_trust_profile("agent-nonexistent")

        assert result is None

    def test_not_found_returns_none_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = get_agent_trust_profile("agent-nonexistent")

        assert result is None

    def test_not_found_returns_none_when_data_is_empty_dict(self):
        client = _make_client({})
        with patch(_PATCH_TARGET, return_value=client):
            result = get_agent_trust_profile("agent-nonexistent")

        assert result is None

    def test_empty_agent_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="agent_id is required"):
            get_agent_trust_profile("")

    def test_whitespace_agent_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="agent_id is required"):
            get_agent_trust_profile("   ")

    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("db error"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_agent_trust_profile("agent-trust-001")

        assert exc_info.value.operation == "get_agent_trust_profile"

    def test_supabase_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("conn refused"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                get_agent_trust_profile("agent-trust-001")

        assert exc_info.value.operation == "get_agent_trust_profile"

    def test_correct_table_queried(self):
        client = _make_client(_PROFILE_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            get_agent_trust_profile("agent-trust-001")

        client.table.assert_called_once_with("agent_trust_profiles")

    def test_query_filters_by_agent_id(self):
        qb = _make_qb(_PROFILE_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_agent_trust_profile("agent-trust-001")

        qb.eq.assert_called_once_with("agent_id", "agent-trust-001")

    def test_agent_id_is_stripped_before_query(self):
        qb = _make_qb(_PROFILE_ROW)
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            get_agent_trust_profile("  agent-trust-001  ")

        qb.eq.assert_called_once_with("agent_id", "agent-trust-001")


# ===========================================================================
# upsert_agent_trust_profile
# ===========================================================================


class TestUpsertAgentTrustProfile:
    def test_success_returns_row(self):
        client = _make_client([_PROFILE_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_agent_trust_profile(dict(_PROFILE_ROW))

        assert result["agent_id"] == "agent-trust-001"

    def test_success_returns_dict_response(self):
        client = _make_client(_PROFILE_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_agent_trust_profile(dict(_PROFILE_ROW))

        assert isinstance(result, dict)

    def test_missing_agent_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="agent_id"):
            upsert_agent_trust_profile({"trust_score": 0.5})

    def test_empty_agent_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="agent_id"):
            upsert_agent_trust_profile({"agent_id": "", "trust_score": 0.5})

    def test_updated_at_auto_injected_when_absent(self):
        record = {"agent_id": "agent-trust-001", "trust_score": 0.80}
        captured_records: list[dict] = []

        def _capture_upsert(*args, **kwargs):
            captured_records.append(args[0] if args else kwargs.get("json", {}))
            qb = _make_qb([{**record, "updated_at": "2026-06-07T00:00:00+00:00"}])
            return qb

        client = MagicMock()
        qb = _make_qb([{**record, "updated_at": "2026-06-07T00:00:00+00:00"}])
        client.table.return_value = qb

        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_agent_trust_profile(record)

        # The function must not mutate the caller's original dict
        assert "updated_at" not in record
        # But the result must include it (either from DB or auto-inject)
        assert result is not None

    def test_updated_at_preserved_when_caller_provides_it(self):
        ts = "2026-01-01T00:00:00+00:00"
        record = {**_PROFILE_ROW, "updated_at": ts}
        client = _make_client([record])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_agent_trust_profile(dict(record))

        assert result["updated_at"] == ts

    def test_correct_table_and_conflict_key_used(self):
        qb = _make_qb([_PROFILE_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            upsert_agent_trust_profile(dict(_PROFILE_ROW))

        client.table.assert_called_once_with("agent_trust_profiles")
        qb.upsert.assert_called_once()
        call_kwargs = qb.upsert.call_args
        assert call_kwargs.kwargs.get("on_conflict") == "agent_id"

    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("write failed"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_agent_trust_profile(dict(_PROFILE_ROW))

        assert exc_info.value.operation == "upsert_agent_trust_profile"

    def test_persistence_error_wraps_cause(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        original = SupabaseClientError("timeout")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                upsert_agent_trust_profile(dict(_PROFILE_ROW))

        assert exc_info.value.cause is original

    def test_returns_input_record_when_data_is_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = upsert_agent_trust_profile(dict(_PROFILE_ROW))

        assert result["agent_id"] == "agent-trust-001"


# ===========================================================================
# insert_trust_event
# ===========================================================================


class TestInsertTrustEvent:
    def test_with_event_id_uses_upsert(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            insert_trust_event(dict(_EVENT_ROW))

        qb.upsert.assert_called_once()
        qb.insert.assert_not_called()

    def test_with_event_id_uses_event_id_as_conflict_key(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            insert_trust_event(dict(_EVENT_ROW))

        call_kwargs = qb.upsert.call_args
        assert call_kwargs.kwargs.get("on_conflict") == "event_id"

    def test_without_event_id_uses_insert(self):
        record = {k: v for k, v in _EVENT_ROW.items() if k != "event_id"}
        qb = _make_qb([record])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            insert_trust_event(record)

        qb.insert.assert_called_once()
        qb.upsert.assert_not_called()

    def test_missing_agent_id_raises_persistence_error(self):
        record = {k: v for k, v in _EVENT_ROW.items() if k != "agent_id"}
        with pytest.raises(PersistenceError, match="agent_id"):
            insert_trust_event(record)

    def test_empty_agent_id_raises_persistence_error(self):
        record = {**_EVENT_ROW, "agent_id": ""}
        with pytest.raises(PersistenceError, match="agent_id"):
            insert_trust_event(record)

    def test_missing_event_type_raises_persistence_error(self):
        record = {k: v for k, v in _EVENT_ROW.items() if k != "event_type"}
        with pytest.raises(PersistenceError, match="event_type"):
            insert_trust_event(record)

    def test_empty_event_type_raises_persistence_error(self):
        record = {**_EVENT_ROW, "event_type": ""}
        with pytest.raises(PersistenceError, match="event_type"):
            insert_trust_event(record)

    def test_recorded_at_auto_injected_when_absent(self):
        record = {k: v for k, v in _EVENT_ROW.items() if k != "recorded_at"}
        assert "recorded_at" not in record

        qb = _make_qb([_EVENT_ROW])
        captured: list[dict] = []

        original_upsert = qb.upsert

        def _spy_upsert(payload, **kwargs):
            captured.append(payload)
            return original_upsert(payload, **kwargs)

        qb.upsert = _spy_upsert

        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            insert_trust_event(record)

        assert len(captured) == 1
        assert "recorded_at" in captured[0]

    def test_recorded_at_preserved_when_caller_provides_it(self):
        ts = "2025-01-01T00:00:00+00:00"
        record = {**_EVENT_ROW, "recorded_at": ts}
        client = _make_client([record])
        with patch(_PATCH_TARGET, return_value=client):
            result = insert_trust_event(dict(record))

        assert result["recorded_at"] == ts

    def test_correct_table_queried(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            insert_trust_event(dict(_EVENT_ROW))

        client.table.assert_called_once_with("trust_events")

    def test_returns_row_on_success(self):
        client = _make_client([_EVENT_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            result = insert_trust_event(dict(_EVENT_ROW))

        assert result["event_id"] == "evt-abc-001"

    def test_supabase_api_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("write failed"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                insert_trust_event(dict(_EVENT_ROW))

        assert exc_info.value.operation == "insert_trust_event"

    def test_supabase_client_error_raises_persistence_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("timeout"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                insert_trust_event(dict(_EVENT_ROW))

        assert exc_info.value.operation == "insert_trust_event"

    def test_persistence_error_cause_is_original_exception(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("connection lost")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                insert_trust_event(dict(_EVENT_ROW))

        assert exc_info.value.cause is original

    def test_original_record_not_mutated_when_recorded_at_injected(self):
        record = {k: v for k, v in _EVENT_ROW.items() if k != "recorded_at"}
        client = _make_client([_EVENT_ROW])
        with patch(_PATCH_TARGET, return_value=client):
            insert_trust_event(record)

        assert "recorded_at" not in record


# ===========================================================================
# list_trust_events
# ===========================================================================


class TestListTrustEventsPersistence:
    def test_returns_list_of_rows(self):
        events = [_EVENT_ROW, {**_EVENT_ROW, "event_id": "evt-abc-002"}]
        client = _make_client(events)
        with patch(_PATCH_TARGET, return_value=client):
            result = list_trust_events("agent-trust-001")

        assert isinstance(result, list)
        assert len(result) == 2
        assert result[0]["event_id"] == "evt-abc-001"

    def test_empty_result_returns_empty_list(self):
        client = _make_client([])
        with patch(_PATCH_TARGET, return_value=client):
            result = list_trust_events("agent-trust-001")

        assert result == []

    def test_none_data_returns_empty_list(self):
        client = _make_client(None)
        with patch(_PATCH_TARGET, return_value=client):
            result = list_trust_events("agent-trust-001")

        assert result == []

    def test_single_dict_response_wrapped_in_list(self):
        client = _make_client(_EVENT_ROW)
        with patch(_PATCH_TARGET, return_value=client):
            result = list_trust_events("agent-trust-001")

        assert isinstance(result, list)
        assert len(result) == 1

    def test_empty_agent_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="agent_id is required"):
            list_trust_events("")

    def test_whitespace_agent_id_raises_persistence_error(self):
        with pytest.raises(PersistenceError, match="agent_id is required"):
            list_trust_events("   ")

    def test_persistence_error_raised_on_supabase_api_error(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseAPIError("read failed"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_trust_events("agent-trust-001")

        assert exc_info.value.operation == "list_trust_events"

    def test_persistence_error_raised_on_supabase_client_error(self):
        from app.supabaseclient import SupabaseClientError  # noqa: PLC0415

        client = _make_client(side_effect=SupabaseClientError("conn reset"))
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_trust_events("agent-trust-001")

        assert exc_info.value.operation == "list_trust_events"

    def test_persistence_error_wraps_cause(self):
        from app.supabaseclient import SupabaseAPIError  # noqa: PLC0415

        original = SupabaseAPIError("disk full")
        client = _make_client(side_effect=original)
        with patch(_PATCH_TARGET, return_value=client):
            with pytest.raises(PersistenceError) as exc_info:
                list_trust_events("agent-trust-001")

        assert exc_info.value.cause is original

    def test_correct_table_queried(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_trust_events("agent-trust-001")

        client.table.assert_called_once_with("trust_events")

    def test_filters_by_agent_id(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_trust_events("agent-trust-001")

        qb.eq.assert_called_once_with("agent_id", "agent-trust-001")

    def test_agent_id_is_stripped_before_query(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_trust_events("  agent-trust-001  ")

        qb.eq.assert_called_once_with("agent_id", "agent-trust-001")

    def test_ordered_by_recorded_at_desc(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_trust_events("agent-trust-001")

        qb.order.assert_called_once_with("recorded_at", desc=True)

    def test_default_limit_50_offset_0_applied(self):
        qb = _make_qb([_EVENT_ROW])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_trust_events("agent-trust-001")

        qb.range.assert_called_once_with(0, 49)

    def test_custom_limit_and_offset_applied(self):
        qb = _make_qb([])
        client = MagicMock()
        client.table.return_value = qb
        with patch(_PATCH_TARGET, return_value=client):
            list_trust_events("agent-trust-001", limit=10, offset=20)

        qb.range.assert_called_once_with(20, 29)
