from __future__ import annotations

from typing import Any

import pytest

from app.history import build_history


def _payload_of(result: Any) -> dict[str, Any]:
    if isinstance(result, dict):
        return result
    if hasattr(result, "as_dict") and callable(result.as_dict):
        payload = result.as_dict()
        assert isinstance(payload, dict)
        return payload
    payload: dict[str, Any] = {}
    for name in dir(result):
        if name.startswith("_"):
            continue
        value = getattr(result, name)
        if callable(value):
            continue
        if isinstance(value, (str, int, float, bool, list, dict, type(None))):
            payload[name] = value
    return payload


def _text(payload: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        if key in payload and payload[key] is not None:
            return str(payload[key])
    return None


def _value(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in payload:
            return payload[key]
    return None


def _call_method_if_present(target: Any, names: tuple[str, ...], *args: Any, **kwargs: Any) -> Any:
    for name in names:
        if hasattr(target, name):
            method = getattr(target, name)
            if callable(method):
                return method(*args, **kwargs)
    raise AssertionError(f"missing expected method from candidates: {names}")


def test_build_history_returns_object() -> None:
    history = build_history()

    assert history is not None


def test_history_is_serializable_to_dictionary_shape() -> None:
    payload = _payload_of(build_history())

    assert isinstance(payload, dict)
    assert payload


def test_history_contains_core_fields_when_present() -> None:
    payload = _payload_of(build_history())

    expected_candidates = {
        "historyid",
        "sessionid",
        "entries",
        "events",
        "items",
        "status",
        "generatedat",
        "createdat",
    }
    assert set(payload.keys()).intersection(expected_candidates)


def test_history_identifiers_are_non_empty_when_present() -> None:
    payload = _payload_of(build_history())

    for value in (
        _text(payload, "historyid", "history_id", "id"),
        _text(payload, "sessionid", "session_id", "runtime_session_id"),
        _text(payload, "status", "state"),
    ):
        if value is not None:
            assert value.strip()


def test_history_collections_have_expected_types_when_present() -> None:
    payload = _payload_of(build_history())

    entries = _value(payload, "entries", "events", "items", "records")

    if entries is not None:
        assert isinstance(entries, (list, dict))


def test_history_supports_session_bound_build_when_available() -> None:
    try:
        history = build_history(session_id="session-001")
    except TypeError:
        history = build_history()

    payload = _payload_of(history)
    session_id = _text(payload, "sessionid", "session_id", "runtime_session_id")
    if session_id is not None:
        assert session_id.strip()


def test_history_append_event_flow_when_supported() -> None:
    history = build_history()

    append_methods = ("append_event", "add_event", "record_event", "push_event")
    if not any(hasattr(history, name) and callable(getattr(history, name)) for name in append_methods):
        pytest.skip("history append method not implemented")

    try:
        result = _call_method_if_present(
            history,
            append_methods,
            event_type="scan.completed",
            message="scan complete",
            status="ok",
        )
    except TypeError:
        result = _call_method_if_present(
            history,
            append_methods,
            "scan.completed",
            "scan complete",
            "ok",
        )

    if result is not None:
        payload = _payload_of(result)
        event_type = _text(payload, "eventtype", "event_type", "type")
        if event_type is not None:
            assert event_type.strip()


def test_history_rejects_blank_event_type_when_supported() -> None:
    history = build_history()

    append_methods = ("append_event", "add_event", "record_event", "push_event")
    if not any(hasattr(history, name) and callable(getattr(history, name)) for name in append_methods):
        pytest.skip("history append method not implemented")

    with pytest.raises((TypeError, ValueError, AssertionError)):
        try:
            _call_method_if_present(
                history,
                append_methods,
                event_type="",
                message="scan complete",
                status="ok",
            )
        except TypeError:
            _call_method_if_present(history, append_methods, "", "scan complete", "ok")


def test_history_entries_have_stable_shape_when_present() -> None:
    payload = _payload_of(build_history())
    entries = _value(payload, "entries", "events", "items", "records")

    if entries is None:
        pytest.skip("history does not expose entries collection")

    if isinstance(entries, dict):
        iterable = list(entries.values())
    else:
        iterable = list(entries)

    for entry in iterable:
        assert isinstance(entry, dict)
        assert any(
            key in entry
            for key in (
                "eventtype",
                "event_type",
                "message",
                "status",
                "timestamp",
                "createdat",
                "created_at",
            )
        )


def test_history_multiple_builds_have_stable_key_sets() -> None:
    first = _payload_of(build_history())
    second = _payload_of(build_history())

    assert set(first.keys()) == set(second.keys())


def test_history_payload_uses_json_friendly_values() -> None:
    payload = _payload_of(build_history())

    for key, value in payload.items():
        assert isinstance(key, str)
        assert value is None or isinstance(value, (str, int, float, bool, list, dict))
