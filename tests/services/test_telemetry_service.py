from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from unittest.mock import patch

import pytest

from app.schemas.telemetry import TelemetryEventType
import app.services.telemetry as _tel_module
from app.services.telemetry import (
    DEFAULT_READ_LIMIT,
    KNOWN_EVENT_TYPES,
    MAX_READ_LIMIT,
    TELEMETRY_SCHEMA_VERSION,
    _build_event_record,
    _coerce_json_safe,
    _normalize_event,
    _parse_iso_timestamp,
    _resolve_event_type,
    _safe_limit,
    append_telemetry_event,
    clear_telemetry_events,
    get_events_by_agent,
    get_telemetry_path,
    is_known_event_type,
    read_telemetry_events,
    summarize_telemetry_events,
    telemetry_file_exists,
)

_MODULE_PATH = "app.services.telemetry.TELEMETRY_PATH"


def _iso_offset(seconds: int = 0) -> str:
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


@pytest.fixture(autouse=True)
def _patch_telemetry_path(tmp_path: Path):
    fake_path = tmp_path / "telemetry_events.jsonl"
    with patch.object(_tel_module, "TELEMETRY_PATH", fake_path):
        yield fake_path


class TestKnownEventTypes:
    def test_is_frozenset(self):
        assert isinstance(KNOWN_EVENT_TYPES, frozenset)

    def test_contains_all_enum_values(self):
        for member in TelemetryEventType:
            assert member.value in KNOWN_EVENT_TYPES

    def test_no_extra_values(self):
        enum_values = frozenset(e.value for e in TelemetryEventType)
        assert KNOWN_EVENT_TYPES == enum_values

    def test_unknown_fallback_present(self):
        assert TelemetryEventType.UNKNOWN.value in KNOWN_EVENT_TYPES

    def test_does_not_contain_old_literal_strings(self):
        assert "scan_completed" not in KNOWN_EVENT_TYPES
        assert "action_guard_decision" not in KNOWN_EVENT_TYPES
        assert "quarantine_created" not in KNOWN_EVENT_TYPES
        assert "trust_score_updated" not in KNOWN_EVENT_TYPES
        assert "behavioral_drift_detected" not in KNOWN_EVENT_TYPES


class TestIsKnownEventType:
    def test_known_enum_value_returns_true(self):
        assert is_known_event_type(TelemetryEventType.PROMPT_SCANNED.value) is True

    def test_unknown_string_returns_false(self):
        assert is_known_event_type("not_a_real_event") is False

    def test_unknown_enum_value_returns_true(self):
        assert is_known_event_type(TelemetryEventType.UNKNOWN.value) is True

    def test_empty_string_returns_false(self):
        assert is_known_event_type("") is False


class TestResolveEventType:
    def test_enum_returns_value(self):
        assert _resolve_event_type(TelemetryEventType.PROMPT_SCANNED) == "prompt.scanned"

    def test_raw_string_passthrough(self):
        assert _resolve_event_type("prompt.scanned") == "prompt.scanned"

    def test_empty_string_falls_back_to_unknown(self):
        assert _resolve_event_type("") == TelemetryEventType.UNKNOWN.value

    def test_whitespace_only_falls_back_to_unknown(self):
        assert _resolve_event_type("   ") == TelemetryEventType.UNKNOWN.value

    def test_unknown_enum_member(self):
        assert _resolve_event_type(TelemetryEventType.UNKNOWN) == "unknown"

    def test_all_enum_members_resolve_to_their_value(self):
        for member in TelemetryEventType:
            assert _resolve_event_type(member) == member.value


class TestBuildEventRecord:
    def test_returns_dict_with_required_keys(self):
        record = _build_event_record(TelemetryEventType.SYSTEM_STARTUP, None)
        assert set(record.keys()) == {"event_id", "schema_version", "timestamp", "event_type", "payload"}

    def test_event_type_from_enum(self):
        record = _build_event_record(TelemetryEventType.PROMPT_BLOCKED, None)
        assert record["event_type"] == "prompt.blocked"

    def test_event_type_from_string(self):
        record = _build_event_record("prompt.blocked", None)
        assert record["event_type"] == "prompt.blocked"

    def test_payload_defaults_to_empty_dict(self):
        record = _build_event_record(TelemetryEventType.SYSTEM_STARTUP, None)
        assert record["payload"] == {}

    def test_payload_dict_preserved(self):
        record = _build_event_record(TelemetryEventType.SYSTEM_STARTUP, {"key": "val"})
        assert record["payload"] == {"key": "val"}

    def test_schema_version_correct(self):
        record = _build_event_record(TelemetryEventType.SYSTEM_STARTUP, None)
        assert record["schema_version"] == TELEMETRY_SCHEMA_VERSION

    def test_event_id_starts_with_telem(self):
        record = _build_event_record(TelemetryEventType.SYSTEM_STARTUP, None)
        assert record["event_id"].startswith("telem_")

    def test_timestamp_is_iso_string(self):
        record = _build_event_record(TelemetryEventType.SYSTEM_STARTUP, None)
        ts = record["timestamp"]
        assert isinstance(ts, str)
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        assert parsed.tzinfo is not None


class TestNormalizeEvent:
    def test_valid_dict_returned(self):
        raw = {
            "event_id": "telem_123",
            "schema_version": 1,
            "timestamp": "2024-01-01T00:00:00Z",
            "event_type": "prompt.scanned",
            "payload": {"foo": "bar"},
        }
        result = _normalize_event(raw)
        assert result is not None
        assert result["event_type"] == "prompt.scanned"

    def test_non_dict_returns_none(self):
        assert _normalize_event("not a dict") is None
        assert _normalize_event(None) is None
        assert _normalize_event(42) is None

    def test_missing_event_type_falls_back_to_unknown(self):
        result = _normalize_event({"event_type": None, "schema_version": 1})
        assert result["event_type"] == TelemetryEventType.UNKNOWN.value

    def test_empty_event_type_falls_back_to_unknown(self):
        result = _normalize_event({"event_type": "", "schema_version": 1})
        assert result["event_type"] == TelemetryEventType.UNKNOWN.value

    def test_payload_non_dict_wrapped(self):
        result = _normalize_event({"event_type": "prompt.scanned", "payload": "raw_string"})
        assert isinstance(result["payload"], dict)
        assert result["payload"] == {"value": "raw_string"}


class TestSafeLimit:
    def test_default_used_when_none(self):
        assert _safe_limit(None) == DEFAULT_READ_LIMIT

    def test_explicit_value_returned(self):
        assert _safe_limit(10) == 10

    def test_floor_is_1(self):
        assert _safe_limit(0) == 1
        assert _safe_limit(-5) == 1

    def test_ceiling_is_max_read_limit(self):
        assert _safe_limit(MAX_READ_LIMIT + 1000) == MAX_READ_LIMIT

    def test_string_int_coerced(self):
        assert _safe_limit("25") == 25

    def test_invalid_string_falls_back_to_default(self):
        assert _safe_limit("abc") == DEFAULT_READ_LIMIT


class TestParseIsoTimestamp:
    def test_valid_z_suffix(self):
        result = _parse_iso_timestamp("2024-06-01T12:00:00Z")
        assert isinstance(result, datetime)
        assert result.tzinfo is not None

    def test_valid_offset(self):
        result = _parse_iso_timestamp("2024-06-01T12:00:00+00:00")
        assert isinstance(result, datetime)

    def test_none_returns_none(self):
        assert _parse_iso_timestamp(None) is None

    def test_empty_string_returns_none(self):
        assert _parse_iso_timestamp("") is None

    def test_invalid_string_returns_none(self):
        assert _parse_iso_timestamp("not-a-date") is None


class TestCoerceJsonSafe:
    def test_primitives_passthrough(self):
        assert _coerce_json_safe(None) is None
        assert _coerce_json_safe(True) is True
        assert _coerce_json_safe(42) == 42
        assert _coerce_json_safe(3.14) == 3.14
        assert _coerce_json_safe("hello") == "hello"

    def test_datetime_to_iso_string(self):
        dt = datetime(2024, 1, 1, tzinfo=UTC)
        result = _coerce_json_safe(dt)
        assert isinstance(result, str)
        assert "2024" in result

    def test_path_to_string(self):
        result = _coerce_json_safe(Path("/tmp/test"))
        assert result == str(PurePosixPath(Path("/tmp/test")))

    def test_dict_recursed(self):
        result = _coerce_json_safe({"k": datetime(2024, 1, 1, tzinfo=UTC)})
        assert isinstance(result["k"], str)

    def test_list_recursed(self):
        result = _coerce_json_safe([1, "two", None])
        assert result == [1, "two", None]

    def test_set_to_list(self):
        result = _coerce_json_safe({1, 2})
        assert isinstance(result, list)

    def test_depth_guard_returns_str(self):
        nested: dict = {}
        cursor = nested
        for _ in range(35):
            cursor["x"] = {}
            cursor = cursor["x"]
        result = _coerce_json_safe(nested)
        assert result is not None


class TestAppendTelemetryEvent:
    def test_appends_with_raw_string(self, _patch_telemetry_path: Path):
        record = append_telemetry_event("prompt.scanned", {"agent": "a1"})
        assert _patch_telemetry_path.exists()
        assert record["event_type"] == "prompt.scanned"

    def test_appends_with_enum(self, _patch_telemetry_path: Path):
        record = append_telemetry_event(TelemetryEventType.PROMPT_SCANNED, {"agent": "a1"})
        assert record["event_type"] == "prompt.scanned"

    def test_file_grows_on_multiple_appends(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        append_telemetry_event(TelemetryEventType.SYSTEM_SHUTDOWN)
        lines = [ln for ln in _patch_telemetry_path.read_text().splitlines() if ln.strip()]
        assert len(lines) == 2

    def test_return_shape(self, _patch_telemetry_path: Path):
        record = append_telemetry_event(TelemetryEventType.POLICY_VIOLATION, {"reason": "test"})
        assert "event_id" in record
        assert "timestamp" in record
        assert "schema_version" in record
        assert record["payload"] == {"reason": "test"}

    def test_none_payload_stored_as_empty_dict(self, _patch_telemetry_path: Path):
        record = append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        assert record["payload"] == {}


class TestReadTelemetryEvents:
    def test_returns_empty_when_no_file(self, _patch_telemetry_path: Path):
        result = read_telemetry_events()
        assert result == []

    def test_returns_events_in_reverse_order(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        append_telemetry_event(TelemetryEventType.SYSTEM_SHUTDOWN)
        events = read_telemetry_events(limit=10)
        assert events[0]["event_type"] == "system.shutdown"
        assert events[1]["event_type"] == "system.startup"

    def test_limit_respected(self, _patch_telemetry_path: Path):
        for _ in range(5):
            append_telemetry_event(TelemetryEventType.AUDIT_LOG_WRITTEN)
        events = read_telemetry_events(limit=3)
        assert len(events) == 3

    def test_filter_by_raw_string(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        append_telemetry_event(TelemetryEventType.POLICY_VIOLATION)
        events = read_telemetry_events(event_type="system.startup")
        assert all(e["event_type"] == "system.startup" for e in events)
        assert len(events) == 1

    def test_filter_by_enum(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        append_telemetry_event(TelemetryEventType.POLICY_VIOLATION)
        events = read_telemetry_events(event_type=TelemetryEventType.POLICY_VIOLATION)
        assert all(e["event_type"] == "policy.violation" for e in events)
        assert len(events) == 1

    def test_filter_by_agent_id(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-A"})
        append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-B"})
        events = read_telemetry_events(agent_id="agent-A")
        assert len(events) == 1
        assert events[0]["payload"]["agent_id"] == "agent-A"

    def test_malformed_lines_skipped(self, _patch_telemetry_path: Path):
        _patch_telemetry_path.write_text("not json\n" '{"event_type":"system.startup","schema_version":1,"timestamp":"2024-01-01T00:00:00Z","event_id":"telem_1","payload":{}}\n')
        events = read_telemetry_events(limit=10)
        assert len(events) == 1
        assert events[0]["event_type"] == "system.startup"

    def test_empty_lines_skipped(self, _patch_telemetry_path: Path):
        _patch_telemetry_path.write_text("\n\n\n")
        events = read_telemetry_events()
        assert events == []


class TestTimestampRangeFilters:
    def test_since_filters_out_older_events(self, _patch_telemetry_path: Path):
        import json

        past = (datetime.now(UTC) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        _patch_telemetry_path.write_text(json.dumps({"event_id": "t1", "schema_version": 1, "timestamp": past, "event_type": "system.startup", "payload": {}}) + "\n" + json.dumps({"event_id": "t2", "schema_version": 1, "timestamp": future, "event_type": "system.shutdown", "payload": {}}) + "\n")
        cutoff = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        events = read_telemetry_events(since=cutoff)
        assert all(e["event_type"] == "system.shutdown" for e in events)

    def test_until_filters_out_newer_events(self, _patch_telemetry_path: Path):
        import json

        past = (datetime.now(UTC) - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        future = (datetime.now(UTC) + timedelta(hours=1)).isoformat().replace("+00:00", "Z")
        _patch_telemetry_path.write_text(json.dumps({"event_id": "t1", "schema_version": 1, "timestamp": past, "event_type": "system.startup", "payload": {}}) + "\n" + json.dumps({"event_id": "t2", "schema_version": 1, "timestamp": future, "event_type": "system.shutdown", "payload": {}}) + "\n")
        cutoff = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        events = read_telemetry_events(until=cutoff)
        assert all(e["event_type"] == "system.startup" for e in events)

    def test_since_as_datetime_object(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        cutoff = datetime.now(UTC) + timedelta(hours=1)
        events = read_telemetry_events(since=cutoff)
        assert events == []

    def test_until_as_datetime_object(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        cutoff = datetime.now(UTC) - timedelta(hours=1)
        events = read_telemetry_events(until=cutoff)
        assert events == []


class TestGetEventsByAgent:
    def test_returns_only_matching_agent(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-X"})
        append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-Y"})
        events = get_events_by_agent("agent-X")
        assert len(events) == 1
        assert events[0]["payload"]["agent_id"] == "agent-X"

    def test_returns_empty_for_unknown_agent(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-X"})
        events = get_events_by_agent("no-such-agent")
        assert events == []

    def test_event_type_filter_combined_with_agent(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-X"})
        append_telemetry_event(TelemetryEventType.POLICY_VIOLATION, {"agent_id": "agent-X"})
        events = get_events_by_agent("agent-X", event_type=TelemetryEventType.POLICY_VIOLATION)
        assert len(events) == 1
        assert events[0]["event_type"] == "policy.violation"

    def test_since_filter_respected(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-X"})
        future_cutoff = datetime.now(UTC) + timedelta(hours=1)
        events = get_events_by_agent("agent-X", since=future_cutoff)
        assert events == []

    def test_limit_respected(self, _patch_telemetry_path: Path):
        for _ in range(5):
            append_telemetry_event(TelemetryEventType.AGENT_PROFILE_UPDATED, {"agent_id": "agent-X"})
        events = get_events_by_agent("agent-X", limit=2)
        assert len(events) == 2


class TestSummarizeTelemetryEvents:
    def test_empty_file_returns_zero_count(self, _patch_telemetry_path: Path):
        summary = summarize_telemetry_events()
        assert summary["event_count"] == 0
        assert summary["event_type_counts"] == {}
        assert summary["latest_timestamp"] is None

    def test_counts_by_event_type(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        append_telemetry_event(TelemetryEventType.POLICY_VIOLATION)
        summary = summarize_telemetry_events()
        assert summary["event_type_counts"]["system.startup"] == 2
        assert summary["event_type_counts"]["policy.violation"] == 1

    def test_known_types_produce_no_unknown(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        summary = summarize_telemetry_events()
        assert summary["unknown_event_types"] == []

    def test_unknown_type_detected(self, _patch_telemetry_path: Path):
        import json

        _patch_telemetry_path.write_text(json.dumps({"event_id": "t1", "schema_version": 1, "timestamp": "2024-01-01T00:00:00Z", "event_type": "scan_completed", "payload": {}}) + "\n")
        summary = summarize_telemetry_events()
        assert "scan_completed" in summary["unknown_event_types"]

    def test_schema_version_present(self, _patch_telemetry_path: Path):
        summary = summarize_telemetry_events()
        assert summary["schema_version"] == TELEMETRY_SCHEMA_VERSION

    def test_latest_timestamp_is_most_recent(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        append_telemetry_event(TelemetryEventType.SYSTEM_SHUTDOWN)
        summary = summarize_telemetry_events()
        assert summary["latest_timestamp"] is not None

    def test_path_present_in_summary(self, _patch_telemetry_path: Path):
        summary = summarize_telemetry_events()
        assert "path" in summary


class TestClearAndExists:
    def test_file_does_not_exist_before_append(self, _patch_telemetry_path: Path):
        assert telemetry_file_exists() is False

    def test_file_exists_after_append(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        assert telemetry_file_exists() is True

    def test_clear_empties_file(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        clear_telemetry_events()
        events = read_telemetry_events()
        assert events == []

    def test_clear_file_still_exists_after_clear(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        clear_telemetry_events()
        assert telemetry_file_exists() is True

    def test_append_after_clear_works(self, _patch_telemetry_path: Path):
        append_telemetry_event(TelemetryEventType.SYSTEM_STARTUP)
        clear_telemetry_events()
        append_telemetry_event(TelemetryEventType.SYSTEM_SHUTDOWN)
        events = read_telemetry_events()
        assert len(events) == 1
        assert events[0]["event_type"] == "system.shutdown"


class TestGetTelemetryPath:
    def test_returns_string(self):
        result = get_telemetry_path()
        assert isinstance(result, str)

    def test_ends_with_jsonl(self):
        result = get_telemetry_path()
        assert result.endswith(".jsonl")
