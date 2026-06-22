from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.core.supabase_persistence import (
    PersistenceError,
    get_install_key,
    increment_install_key_units,
    list_install_keys_for_owner,
    upsert_install_key,
)

_MOCK_TARGET = "app.core.supabase_persistence.get_supabase_service_client"

_VALID_RECORD: dict = {
    "install_key_id": "ik_abc123",
    "owner_id": "owner_xyz",
    "active": True,
    "units_used": 0,
}


def _make_client(*, data=None, as_list: bool = True) -> MagicMock:
    """Return a mock Supabase client whose table chain returns the given data."""
    if data is None:
        data = []
    resp = MagicMock()
    resp.data = [data] if (as_list and isinstance(data, dict)) else data

    chain = MagicMock()
    chain.execute.return_value = resp
    chain.upsert.return_value = chain
    chain.insert.return_value = chain
    chain.select.return_value = chain
    chain.eq.return_value = chain
    chain.order.return_value = chain
    chain.range.return_value = chain
    chain.maybe_single.return_value = chain
    chain.update.return_value = chain
    chain.delete.return_value = chain

    client = MagicMock()
    client.table.return_value = chain
    return client


# ---------------------------------------------------------------------------
# upsert_install_key
# ---------------------------------------------------------------------------


class TestUpsertInstallKey:
    def test_raises_persistence_error_when_install_key_id_missing(self) -> None:
        record = {"owner_id": "owner_xyz"}
        with pytest.raises(PersistenceError) as exc_info:
            upsert_install_key(record)
        assert exc_info.value.operation == "upsert_install_key"
        assert "install_key_id" in str(exc_info.value)

    def test_raises_persistence_error_when_owner_id_missing(self) -> None:
        record = {"install_key_id": "ik_abc123"}
        with pytest.raises(PersistenceError) as exc_info:
            upsert_install_key(record)
        assert exc_info.value.operation == "upsert_install_key"
        assert "owner_id" in str(exc_info.value)

    def test_raises_persistence_error_when_both_required_fields_missing(self) -> None:
        with pytest.raises(PersistenceError):
            upsert_install_key({})

    def test_happy_path_returns_persisted_record(self) -> None:
        returned = {**_VALID_RECORD, "created_at": "2026-01-01T00:00:00+00:00", "updated_at": "2026-01-01T00:00:01+00:00"}
        client = _make_client(data=returned)
        with patch(_MOCK_TARGET, return_value=client):
            result = upsert_install_key(dict(_VALID_RECORD))
        assert result["install_key_id"] == "ik_abc123"
        assert result["owner_id"] == "owner_xyz"

    def test_happy_path_injects_created_at_when_absent(self) -> None:
        captured: list[dict] = []

        def _capture_upsert(record, **kwargs):
            captured.append(record)
            chain = MagicMock()
            chain.execute.return_value = MagicMock(data=[record])
            return chain

        client = MagicMock()
        tbl = MagicMock()
        tbl.upsert.side_effect = _capture_upsert
        client.table.return_value = tbl

        with patch(_MOCK_TARGET, return_value=client):
            upsert_install_key(dict(_VALID_RECORD))

        assert captured, "upsert was not called"
        assert "created_at" in captured[0]
        assert "updated_at" in captured[0]

    def test_returns_record_as_dict_when_supabase_returns_dict(self) -> None:
        returned = {**_VALID_RECORD}
        resp = MagicMock()
        resp.data = returned
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.upsert.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = upsert_install_key(dict(_VALID_RECORD))
        assert isinstance(result, dict)
        assert result["install_key_id"] == "ik_abc123"

    def test_returns_original_record_when_supabase_returns_empty_list(self) -> None:
        resp = MagicMock()
        resp.data = []
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.upsert.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = upsert_install_key(dict(_VALID_RECORD))
        assert result["install_key_id"] == "ik_abc123"


# ---------------------------------------------------------------------------
# get_install_key
# ---------------------------------------------------------------------------


class TestGetInstallKey:
    def test_raises_persistence_error_on_empty_string(self) -> None:
        with pytest.raises(PersistenceError) as exc_info:
            get_install_key("")
        assert exc_info.value.operation == "get_install_key"

    def test_raises_persistence_error_on_whitespace_only(self) -> None:
        with pytest.raises(PersistenceError):
            get_install_key("   ")

    def test_returns_none_on_cache_miss_when_data_is_none(self) -> None:
        resp = MagicMock()
        resp.data = None
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.maybe_single.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = get_install_key("ik_missing")
        assert result is None

    def test_returns_none_on_cache_miss_when_data_is_empty_list(self) -> None:
        resp = MagicMock()
        resp.data = []
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.maybe_single.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = get_install_key("ik_missing")
        assert result is None

    def test_returns_dict_on_cache_hit(self) -> None:
        row = {**_VALID_RECORD}
        resp = MagicMock()
        resp.data = row
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.maybe_single.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = get_install_key("ik_abc123")
        assert isinstance(result, dict)
        assert result["install_key_id"] == "ik_abc123"

    def test_returns_first_element_when_data_is_list(self) -> None:
        row = {**_VALID_RECORD}
        resp = MagicMock()
        resp.data = [row]
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.maybe_single.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = get_install_key("ik_abc123")
        assert result is not None
        assert result["install_key_id"] == "ik_abc123"

    def test_strips_whitespace_from_id_before_query(self) -> None:
        eq_calls: list[tuple] = []
        resp = MagicMock()
        resp.data = {**_VALID_RECORD}

        def _capture_eq(col, val):
            eq_calls.append((col, val))
            chain = MagicMock()
            chain.execute.return_value = resp
            chain.maybe_single.return_value = chain
            chain.eq.return_value = chain
            return chain

        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.side_effect = _capture_eq
        chain.maybe_single.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            get_install_key("  ik_abc123  ")
        assert any(val == "ik_abc123" for _, val in eq_calls)


# ---------------------------------------------------------------------------
# list_install_keys_for_owner
# ---------------------------------------------------------------------------


class TestListInstallKeysForOwner:
    def test_raises_persistence_error_on_empty_owner_id(self) -> None:
        with pytest.raises(PersistenceError) as exc_info:
            list_install_keys_for_owner("")
        assert exc_info.value.operation == "list_install_keys_for_owner"

    def test_raises_persistence_error_on_whitespace_owner_id(self) -> None:
        with pytest.raises(PersistenceError):
            list_install_keys_for_owner("   ")

    def test_active_only_filter_is_applied_when_true(self) -> None:
        eq_calls: list[tuple] = []
        resp = MagicMock()
        resp.data = []

        def _capture_eq(col, val):
            eq_calls.append((col, val))
            m = MagicMock()
            m.execute.return_value = resp
            m.eq.side_effect = _capture_eq
            m.order.return_value = m
            m.range.return_value = m
            return m

        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.side_effect = _capture_eq
        chain.order.return_value = chain
        chain.range.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            list_install_keys_for_owner("owner_xyz", active_only=True)
        assert any(col == "active" and val is True for col, val in eq_calls)

    def test_active_only_filter_is_not_applied_when_false(self) -> None:
        eq_calls: list[tuple] = []
        resp = MagicMock()
        resp.data = []

        def _capture_eq(col, val):
            eq_calls.append((col, val))
            m = MagicMock()
            m.execute.return_value = resp
            m.eq.side_effect = _capture_eq
            m.order.return_value = m
            m.range.return_value = m
            return m

        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.side_effect = _capture_eq
        chain.order.return_value = chain
        chain.range.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            list_install_keys_for_owner("owner_xyz", active_only=False)
        assert not any(col == "active" for col, _ in eq_calls)

    def test_pagination_range_is_correct(self) -> None:
        range_calls: list[tuple] = []
        resp = MagicMock()
        resp.data = []

        def _capture_range(start, end):
            range_calls.append((start, end))
            m = MagicMock()
            m.execute.return_value = resp
            return m

        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.order.return_value = chain
        chain.range.side_effect = _capture_range
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            list_install_keys_for_owner("owner_xyz", limit=25, offset=50)
        assert range_calls, "range() was not called"
        start, end = range_calls[0]
        assert start == 50
        assert end == 74

    def test_returns_list_on_success(self) -> None:
        rows = [_VALID_RECORD, {**_VALID_RECORD, "install_key_id": "ik_def456"}]
        resp = MagicMock()
        resp.data = rows
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.order.return_value = chain
        chain.range.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = list_install_keys_for_owner("owner_xyz")
        assert isinstance(result, list)
        assert len(result) == 2

    def test_returns_empty_list_when_no_rows(self) -> None:
        resp = MagicMock()
        resp.data = []
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.order.return_value = chain
        chain.range.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = list_install_keys_for_owner("owner_xyz")
        assert result == []


# ---------------------------------------------------------------------------
# increment_install_key_units
# ---------------------------------------------------------------------------


class TestIncrementInstallKeyUnits:
    def test_raises_persistence_error_when_install_key_id_empty(self) -> None:
        with pytest.raises(PersistenceError) as exc_info:
            increment_install_key_units("", delta=1)
        assert exc_info.value.operation == "increment_install_key_units"

    def test_raises_persistence_error_when_install_key_id_whitespace(self) -> None:
        with pytest.raises(PersistenceError):
            increment_install_key_units("   ", delta=1)

    def test_raises_persistence_error_when_delta_is_zero(self) -> None:
        with pytest.raises(PersistenceError) as exc_info:
            increment_install_key_units("ik_abc123", delta=0)
        assert exc_info.value.operation == "increment_install_key_units"
        assert "delta" in str(exc_info.value)

    def test_raises_persistence_error_when_delta_is_negative(self) -> None:
        with pytest.raises(PersistenceError) as exc_info:
            increment_install_key_units("ik_abc123", delta=-5)
        assert exc_info.value.operation == "increment_install_key_units"

    def test_returns_none_when_key_does_not_exist(self) -> None:
        resp = MagicMock()
        resp.data = None
        chain = MagicMock()
        chain.execute.return_value = resp
        chain.select.return_value = chain
        chain.eq.return_value = chain
        chain.maybe_single.return_value = chain
        client = MagicMock()
        client.table.return_value = chain
        with patch(_MOCK_TARGET, return_value=client):
            result = increment_install_key_units("ik_missing", delta=1)
        assert result is None

    def test_correct_arithmetic_on_units_used(self) -> None:
        existing_row = {**_VALID_RECORD, "units_used": 10}
        upserted_rows: list[dict] = []

        get_resp = MagicMock()
        get_resp.data = existing_row

        upsert_resp = MagicMock()

        def _build_upsert_chain(record, **kwargs):
            upserted_rows.append(dict(record))
            upsert_resp.data = [record]
            m = MagicMock()
            m.execute.return_value = upsert_resp
            return m

        def _table(name: str):
            tbl = MagicMock()
            sel_chain = MagicMock()
            sel_chain.execute.return_value = get_resp
            sel_chain.eq.return_value = sel_chain
            sel_chain.maybe_single.return_value = sel_chain
            tbl.select.return_value = sel_chain
            tbl.upsert.side_effect = _build_upsert_chain
            return tbl

        client = MagicMock()
        client.table.side_effect = _table
        with patch(_MOCK_TARGET, return_value=client):
            increment_install_key_units("ik_abc123", delta=5)

        assert upserted_rows, "upsert was not called"
        assert upserted_rows[0]["units_used"] == 15

    def test_default_delta_is_one(self) -> None:
        existing_row = {**_VALID_RECORD, "units_used": 3}
        upserted_rows: list[dict] = []

        get_resp = MagicMock()
        get_resp.data = existing_row
        upsert_resp_obj = MagicMock()

        def _build_upsert_chain(record, **kwargs):
            upserted_rows.append(dict(record))
            upsert_resp_obj.data = [record]
            m = MagicMock()
            m.execute.return_value = upsert_resp_obj
            return m

        def _table(name: str):
            tbl = MagicMock()
            sel_chain = MagicMock()
            sel_chain.execute.return_value = get_resp
            sel_chain.eq.return_value = sel_chain
            sel_chain.maybe_single.return_value = sel_chain
            tbl.select.return_value = sel_chain
            tbl.upsert.side_effect = _build_upsert_chain
            return tbl

        client = MagicMock()
        client.table.side_effect = _table
        with patch(_MOCK_TARGET, return_value=client):
            increment_install_key_units("ik_abc123")

        assert upserted_rows[0]["units_used"] == 4

    def test_updated_at_is_set_on_incremented_record(self) -> None:
        existing_row = {**_VALID_RECORD, "units_used": 0}
        upserted_rows: list[dict] = []

        get_resp = MagicMock()
        get_resp.data = existing_row
        upsert_resp_obj = MagicMock()

        def _build_upsert_chain(record, **kwargs):
            upserted_rows.append(dict(record))
            upsert_resp_obj.data = [record]
            m = MagicMock()
            m.execute.return_value = upsert_resp_obj
            return m

        def _table(name: str):
            tbl = MagicMock()
            sel_chain = MagicMock()
            sel_chain.execute.return_value = get_resp
            sel_chain.eq.return_value = sel_chain
            sel_chain.maybe_single.return_value = sel_chain
            tbl.select.return_value = sel_chain
            tbl.upsert.side_effect = _build_upsert_chain
            return tbl

        client = MagicMock()
        client.table.side_effect = _table
        with patch(_MOCK_TARGET, return_value=client):
            increment_install_key_units("ik_abc123", delta=2)

        assert "updated_at" in upserted_rows[0]
