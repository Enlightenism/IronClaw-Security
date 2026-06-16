from __future__ import annotations

from datetime import UTC, datetime
import re
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.services.telemetry_service import (
    MAX_BATCH_SIZE,
    TelemetryBatchResult,
    TelemetryEventInput,
    TelemetryIngestResponse,
    build_agent_event,
    build_event_key,
    post_telemetry_batch,
    post_telemetry_batch_async,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


_MODULE = "app.services.telemetry_service"


def _make_event(
    source: str = "ironclaw.test",
    metric_name: str = "test.metric",
    metric_type: str = "event",
) -> TelemetryEventInput:
    return build_agent_event(
        source=source,
        metric_name=metric_name,
        metric_type=metric_type,  # type: ignore[arg-type]
    )


def _mock_ok_response(n: int = 1) -> MagicMock:
    resp = MagicMock()
    resp.json.return_value = {
        "ok": True,
        "received": n,
        "valid": n,
        "inserted": n,
        "duplicates": 0,
        "validation_errors": [],
        "error": None,
    }
    resp.raise_for_status = MagicMock()
    return resp


# ─── __all__ / re-export bridge ───────────────────────────────────────────────


class TestReExport:
    def test_TelemetryIngestResponse_importable_from_service_module(self):
        import app.services.telemetry_service as svc

        assert hasattr(svc, "TelemetryIngestResponse")

    def test_re_exported_class_is_same_object(self):
        from app.schemas.telemetry import TelemetryIngestResponse as SchemaResp
        from app.services.telemetry_service import TelemetryIngestResponse as SvcResp

        assert SvcResp is SchemaResp

    def test_all_contains_TelemetryIngestResponse(self):
        import app.services.telemetry_service as svc

        assert "TelemetryIngestResponse" in svc.__all__

    def test_all_contains_core_symbols(self):
        import app.services.telemetry_service as svc

        for name in (
            "TelemetryEventInput",
            "TelemetryBatchResult",
            "build_event_key",
            "build_agent_event",
            "post_telemetry_batch",
            "post_telemetry_batch_async",
        ):
            assert name in svc.__all__, f"Missing from __all__: {name}"


# ─── build_event_key ──────────────────────────────────────────────────────────


class TestBuildEventKey:
    def test_returns_uuid_format(self):
        key = build_event_key(
            source="ironclaw",
            metric_name="prompt.scanned",
            captured_at="2024-01-01T00:00:00Z",
        )
        assert _UUID_RE.match(key), f"Not UUID format: {key}"

    def test_deterministic_same_inputs(self):
        kwargs = dict(
            source="ironclaw",
            metric_name="prompt.scanned",
            captured_at="2024-01-01T00:00:00Z",
            org_id="org-1",
        )
        assert build_event_key(**kwargs) == build_event_key(**kwargs)

    def test_different_source_produces_different_key(self):
        base = dict(metric_name="m", captured_at="2024-01-01T00:00:00Z")
        k1 = build_event_key(source="a", **base)
        k2 = build_event_key(source="b", **base)
        assert k1 != k2

    def test_different_metric_name_produces_different_key(self):
        base = dict(source="s", captured_at="2024-01-01T00:00:00Z")
        k1 = build_event_key(metric_name="x", **base)
        k2 = build_event_key(metric_name="y", **base)
        assert k1 != k2

    def test_different_captured_at_produces_different_key(self):
        base = dict(source="s", metric_name="m")
        k1 = build_event_key(captured_at="2024-01-01T00:00:00Z", **base)
        k2 = build_event_key(captured_at="2024-01-02T00:00:00Z", **base)
        assert k1 != k2

    def test_different_org_id_produces_different_key(self):
        base = dict(source="s", metric_name="m", captured_at="2024-01-01T00:00:00Z")
        k1 = build_event_key(org_id="org-A", **base)
        k2 = build_event_key(org_id="org-B", **base)
        assert k1 != k2

    def test_none_org_id_consistent_with_omitted(self):
        base = dict(source="s", metric_name="m", captured_at="2024-01-01T00:00:00Z")
        k1 = build_event_key(**base)
        k2 = build_event_key(org_id=None, **base)
        assert k1 == k2

    def test_extra_seed_changes_key(self):
        base = dict(source="s", metric_name="m", captured_at="2024-01-01T00:00:00Z")
        k1 = build_event_key(extra="", **base)
        k2 = build_event_key(extra="retry-1", **base)
        assert k1 != k2

    def test_key_lowercase_hex(self):
        key = build_event_key(source="s", metric_name="m", captured_at="2024-01-01T00:00:00Z")
        assert key == key.lower()


# ─── build_agent_event ────────────────────────────────────────────────────────


class TestBuildAgentEvent:
    def test_returns_TelemetryEventInput(self):
        event = _make_event()
        assert isinstance(event, TelemetryEventInput)

    def test_event_key_is_uuid_format(self):
        event = _make_event()
        assert _UUID_RE.match(event.event_key)

    def test_metric_name_set(self):
        event = _make_event(metric_name="policy.violation")
        assert event.metric_name == "policy.violation"

    def test_source_set(self):
        event = _make_event(source="ironclaw.guard")
        assert event.source == "ironclaw.guard"

    def test_metric_type_set(self):
        event = build_agent_event(source="s", metric_name="m", metric_type="counter")
        assert event.metric_type == "counter"

    def test_org_id_none_by_default(self):
        event = _make_event()
        assert event.org_id is None

    def test_org_id_propagated(self):
        event = build_agent_event(source="s", metric_name="m", org_id="org-X")
        assert event.org_id == "org-X"

    def test_value_numeric_propagated(self):
        event = build_agent_event(source="s", metric_name="m", value_numeric=3.14)
        assert event.value_numeric == 3.14

    def test_value_text_propagated(self):
        event = build_agent_event(source="s", metric_name="m", value_text="blocked")
        assert event.value_text == "blocked"

    def test_unit_propagated(self):
        event = build_agent_event(source="s", metric_name="m", unit="ms")
        assert event.unit == "ms"

    def test_dimensions_propagated(self):
        dims = {"region": "us-east-1"}
        event = build_agent_event(source="s", metric_name="m", dimensions=dims)
        assert event.dimensions == dims

    def test_captured_at_defaults_to_now_utc(self):
        before = datetime.now(UTC)
        event = _make_event()
        after = datetime.now(UTC)
        ts = datetime.fromisoformat(event.captured_at.replace("Z", "+00:00"))
        assert before <= ts <= after

    def test_captured_at_datetime_coerced_to_iso_z(self):
        dt = datetime(2025, 6, 1, 12, 0, 0, tzinfo=UTC)
        event = build_agent_event(source="s", metric_name="m", captured_at=dt)
        assert event.captured_at == "2025-06-01T12:00:00Z"

    def test_captured_at_string_passthrough(self):
        ts = "2025-06-01T12:00:00Z"
        event = build_agent_event(source="s", metric_name="m", captured_at=ts)
        assert event.captured_at == ts

    def test_event_key_deterministic_across_calls(self):
        ts = "2025-06-01T12:00:00Z"
        e1 = build_agent_event(source="s", metric_name="m", captured_at=ts)
        e2 = build_agent_event(source="s", metric_name="m", captured_at=ts)
        assert e1.event_key == e2.event_key

    def test_different_captured_at_different_key(self):
        e1 = build_agent_event(source="s", metric_name="m", captured_at="2025-06-01T12:00:00Z")
        e2 = build_agent_event(source="s", metric_name="m", captured_at="2025-06-02T12:00:00Z")
        assert e1.event_key != e2.event_key

    def test_retention_until_propagated(self):
        ts = "2026-01-01T00:00:00Z"
        event = build_agent_event(source="s", metric_name="m", retention_until=ts)
        assert event.retention_until == ts

    def test_empty_dimensions_default(self):
        event = build_agent_event(source="s", metric_name="m")
        assert event.dimensions == {}


# ─── TelemetryBatchResult.to_ingest_response ──────────────────────────────────


class TestToIngestResponse:
    def test_returns_TelemetryIngestResponse(self):
        result = TelemetryBatchResult(ok=True, received=5, inserted=5, duplicates=0)
        resp = result.to_ingest_response()
        assert isinstance(resp, TelemetryIngestResponse)

    def test_ok_propagated(self):
        resp = TelemetryBatchResult(ok=False, error="oops").to_ingest_response()
        assert resp.ok is False

    def test_received_propagated(self):
        resp = TelemetryBatchResult(ok=True, received=10).to_ingest_response()
        assert resp.received == 10

    def test_inserted_propagated(self):
        resp = TelemetryBatchResult(ok=True, inserted=7).to_ingest_response()
        assert resp.inserted == 7

    def test_duplicates_propagated(self):
        resp = TelemetryBatchResult(ok=True, duplicates=3).to_ingest_response()
        assert resp.duplicates == 3

    def test_error_propagated(self):
        resp = TelemetryBatchResult(ok=False, error="HTTP 500: bad gateway").to_ingest_response()
        assert resp.error == "HTTP 500: bad gateway"

    def test_validation_errors_propagated(self):
        errs = [{"field": "metric_name", "msg": "too short"}]
        resp = TelemetryBatchResult(ok=False, validation_errors=errs).to_ingest_response()
        assert resp.validation_errors == errs

    def test_valid_field_not_leaked(self):
        resp = TelemetryBatchResult(ok=True, valid=9).to_ingest_response()
        assert not hasattr(resp, "valid")

    def test_none_error_preserved(self):
        resp = TelemetryBatchResult(ok=True).to_ingest_response()
        assert resp.error is None


# ─── post_telemetry_batch (sync) ──────────────────────────────────────────────


class TestPostTelemetryBatchSync:
    def test_empty_list_returns_ok_zero(self):
        result = post_telemetry_batch([])
        assert result.ok is True
        assert result.received == 0
        assert result.inserted == 0

    def test_unconfigured_returns_not_ok(self):
        events = [_make_event()]
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value=None),
            patch(f"{_MODULE}._get_ingest_token", return_value=None),
        ):
            result = post_telemetry_batch(events)
        assert result.ok is False
        assert "not configured" in (result.error or "").lower()
        assert result.received == 1

    def test_unconfigured_missing_url_only(self):
        events = [_make_event()]
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value=None),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
        ):
            result = post_telemetry_batch(events)
        assert result.ok is False

    def test_unconfigured_missing_token_only(self):
        events = [_make_event()]
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com"),
            patch(f"{_MODULE}._get_ingest_token", return_value=None),
        ):
            result = post_telemetry_batch(events)
        assert result.ok is False

    def test_success_response_parsed(self):
        events = [_make_event()]
        mock_resp = _mock_ok_response(1)
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.post", return_value=mock_resp),
        ):
            result = post_telemetry_batch(events)
        assert result.ok is True
        assert result.inserted == 1

    def test_http_status_error_returns_not_ok(self):
        events = [_make_event()]
        exc_resp = MagicMock()
        exc_resp.status_code = 503
        exc_resp.text = "service unavailable"
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch(
                "httpx.post",
                side_effect=httpx.HTTPStatusError("err", request=MagicMock(), response=exc_resp),
            ),
        ):
            result = post_telemetry_batch(events)
        assert result.ok is False
        assert "503" in (result.error or "")
        assert result.received == 1

    def test_timeout_exception_returns_not_ok(self):
        events = [_make_event()]
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.post", side_effect=httpx.TimeoutException("timed out")),
        ):
            result = post_telemetry_batch(events)
        assert result.ok is False
        assert "timed out" in (result.error or "").lower()
        assert result.received == 1

    def test_generic_exception_returns_not_ok(self):
        events = [_make_event()]
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.post", side_effect=RuntimeError("boom")),
        ):
            result = post_telemetry_batch(events)
        assert result.ok is False
        assert "boom" in (result.error or "")

    def test_batch_truncated_at_max(self):
        events = [_make_event() for _ in range(MAX_BATCH_SIZE + 10)]
        mock_resp = _mock_ok_response(MAX_BATCH_SIZE)
        captured: list[list] = []

        def fake_post(url, json, headers, timeout):
            captured.append(json)
            return mock_resp

        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.post", side_effect=fake_post),
        ):
            post_telemetry_batch(events)

        assert len(captured[0]) == MAX_BATCH_SIZE

    def test_result_is_TelemetryBatchResult(self):
        events = [_make_event()]
        mock_resp = _mock_ok_response(1)
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.post", return_value=mock_resp),
        ):
            result = post_telemetry_batch(events)
        assert isinstance(result, TelemetryBatchResult)

    def test_to_ingest_response_from_sync_result(self):
        events = [_make_event()]
        mock_resp = _mock_ok_response(1)
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.post", return_value=mock_resp),
        ):
            result = post_telemetry_batch(events)
        api_resp = result.to_ingest_response()
        assert isinstance(api_resp, TelemetryIngestResponse)
        assert api_resp.ok is True


# ─── post_telemetry_batch_async ───────────────────────────────────────────────


class TestPostTelemetryBatchAsync:
    @pytest.mark.asyncio
    async def test_empty_list_returns_ok_zero(self):
        result = await post_telemetry_batch_async([])
        assert result.ok is True
        assert result.received == 0

    @pytest.mark.asyncio
    async def test_unconfigured_returns_not_ok(self):
        events = [_make_event()]
        with (
            patch(f"{_MODULE}._get_ingest_url", return_value=None),
            patch(f"{_MODULE}._get_ingest_token", return_value=None),
        ):
            result = await post_telemetry_batch_async(events)
        assert result.ok is False
        assert result.received == 1

    @pytest.mark.asyncio
    async def test_success_response_parsed(self):
        events = [_make_event()]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "ok": True,
            "received": 1,
            "valid": 1,
            "inserted": 1,
            "duplicates": 0,
            "validation_errors": [],
            "error": None,
        }
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            result = await post_telemetry_batch_async(events)
        assert result.ok is True
        assert result.inserted == 1

    @pytest.mark.asyncio
    async def test_http_status_error_returns_not_ok(self):
        events = [_make_event()]
        exc_resp = MagicMock()
        exc_resp.status_code = 429
        exc_resp.text = "rate limited"

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.HTTPStatusError("err", request=MagicMock(), response=exc_resp))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            result = await post_telemetry_batch_async(events)
        assert result.ok is False
        assert "429" in (result.error or "")

    @pytest.mark.asyncio
    async def test_timeout_returns_not_ok(self):
        events = [_make_event()]
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("async timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            result = await post_telemetry_batch_async(events)
        assert result.ok is False
        assert "timed out" in (result.error or "").lower()

    @pytest.mark.asyncio
    async def test_generic_exception_returns_not_ok(self):
        events = [_make_event()]
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=ValueError("unexpected"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            result = await post_telemetry_batch_async(events)
        assert result.ok is False
        assert "unexpected" in (result.error or "")

    @pytest.mark.asyncio
    async def test_batch_truncated_at_max(self):
        events = [_make_event() for _ in range(MAX_BATCH_SIZE + 5)]
        captured: list[list] = []

        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "ok": True,
            "received": MAX_BATCH_SIZE,
            "valid": MAX_BATCH_SIZE,
            "inserted": MAX_BATCH_SIZE,
            "duplicates": 0,
            "validation_errors": [],
            "error": None,
        }
        mock_resp.raise_for_status = MagicMock()

        async def fake_post(url, json, headers):
            captured.append(json)
            return mock_resp

        mock_client = AsyncMock()
        mock_client.post = fake_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            await post_telemetry_batch_async(events)

        assert len(captured[0]) == MAX_BATCH_SIZE

    @pytest.mark.asyncio
    async def test_to_ingest_response_from_async_result(self):
        events = [_make_event()]
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "ok": True,
            "received": 1,
            "valid": 1,
            "inserted": 1,
            "duplicates": 0,
            "validation_errors": [],
            "error": None,
        }
        mock_resp.raise_for_status = MagicMock()

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(f"{_MODULE}._get_ingest_url", return_value="https://example.com/ingest"),
            patch(f"{_MODULE}._get_ingest_token", return_value="tok"),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            result = await post_telemetry_batch_async(events)
        api_resp = result.to_ingest_response()
        assert isinstance(api_resp, TelemetryIngestResponse)
        assert api_resp.ok is True
