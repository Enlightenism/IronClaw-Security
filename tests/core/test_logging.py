from __future__ import annotations

import json
import logging
import sys

import anyio
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.types import Message

from app.core.logging import (
    JsonFormatter,
    RequestContextFilter,
    RequestContextMiddleware,
    _extract_extra_fields,
    _truncate_value,
    bind_security_event,
    configure_logging,
    get_logger,
    get_request_id,
    request_id_context,
)
from app.core.requestid import REQUEST_ID_HEADER_NAME
from app.core.settings import Settings


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestContextMiddleware)

    @app.get("/ok")
    async def ok() -> JSONResponse:
        return JSONResponse(
            content={"request_id": get_request_id()},
        )

    @app.get("/preset-header")
    async def preset_header() -> JSONResponse:
        return JSONResponse(
            content={"request_id": get_request_id()},
            headers={REQUEST_ID_HEADER_NAME: "route-header-request-id"},
        )

    @app.get("/boom")
    async def boom() -> None:
        raise RuntimeError("boom")

    @app.options("/ok")
    async def ok_options() -> JSONResponse:
        return JSONResponse(
            content={"request_id": get_request_id()},
        )

    return app


def test_get_request_id_returns_current_context_value() -> None:
    token = request_id_context.set("ctx-123")
    try:
        assert get_request_id() == "ctx-123"
    finally:
        request_id_context.reset(token)


def test_request_context_filter_sets_request_id_on_record() -> None:
    token = request_id_context.set("filter-request-id")
    try:
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="hello",
            args=(),
            exc_info=None,
        )
        result = RequestContextFilter().filter(record)

        assert result is True
        assert record.request_id == "filter-request-id"
    finally:
        request_id_context.reset(token)


def test_request_context_filter_sets_none_when_context_empty() -> None:
    token = request_id_context.set("")
    try:
        record = logging.LogRecord(
            name="test.logger",
            level=logging.INFO,
            pathname=__file__,
            lineno=10,
            msg="hello",
            args=(),
            exc_info=None,
        )
        result = RequestContextFilter().filter(record)

        assert result is True
        assert record.request_id is None
    finally:
        request_id_context.reset(token)


def test_extract_extra_fields_returns_only_non_standard_fields() -> None:
    record = logging.LogRecord(
        name="test.logger",
        level=logging.INFO,
        pathname=__file__,
        lineno=20,
        msg="message",
        args=(),
        exc_info=None,
    )
    record.custom_field = "custom-value"
    record.another_field = 123
    record._private_field = "ignore-me"
    record.request_id = "req-1"

    extracted = _extract_extra_fields(record)

    assert extracted["custom_field"] == "custom-value"
    assert extracted["another_field"] == 123
    assert "_private_field" not in extracted
    assert "request_id" not in extracted
    assert "name" not in extracted
    assert "msg" not in extracted


def test_json_formatter_includes_core_fields_and_extra_fields() -> None:
    token = request_id_context.set("json-request-id")
    try:
        record = logging.LogRecord(
            name="test.logger",
            level=logging.WARNING,
            pathname=__file__,
            lineno=30,
            msg="structured message",
            args=(),
            exc_info=None,
        )
        record.request_id = "json-request-id"
        record.event = "request_completed"
        record.status_code = 200

        formatted = JsonFormatter().format(record)
        payload = json.loads(formatted)

        assert payload["level"] == "WARNING"
        assert payload["logger"] == "test.logger"
        assert payload["message"] == "structured message"
        assert payload["request_id"] == "json-request-id"
        assert payload["event"] == "request_completed"
        assert payload["status_code"] == 200
        assert "timestamp" in payload
    finally:
        request_id_context.reset(token)


def test_json_formatter_includes_exception_text_when_present() -> None:
    try:
        raise ValueError("bad-value")
    except ValueError:
        exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="test.logger",
            level=logging.ERROR,
            pathname=__file__,
            lineno=40,
            msg="failed",
            args=(),
            exc_info=exc_info,
        )
        formatted = JsonFormatter().format(record)
        payload = json.loads(formatted)

    assert payload["message"] == "failed"
    assert payload["level"] == "ERROR"
    assert "exception" in payload
    assert "ValueError" in payload["exception"]


def test_configure_logging_sets_json_formatter_when_structured_enabled() -> None:
    settings = Settings(LOG_LEVEL="DEBUG", STRUCTURED_LOGGING_ENABLED=True)

    configure_logging(settings)

    root_logger = logging.getLogger()
    assert len(root_logger.handlers) == 1
    handler = root_logger.handlers[0]
    assert isinstance(handler.formatter, JsonFormatter)
    assert root_logger.level == logging.DEBUG


def test_configure_logging_sets_plain_formatter_when_structured_disabled() -> None:
    settings = Settings(LOG_LEVEL="INFO", STRUCTURED_LOGGING_ENABLED=False)

    configure_logging(settings)

    root_logger = logging.getLogger()
    assert len(root_logger.handlers) == 1
    handler = root_logger.handlers[0]
    assert isinstance(handler.formatter, logging.Formatter)
    assert not isinstance(handler.formatter, JsonFormatter)
    assert root_logger.level == logging.INFO


def test_get_logger_returns_named_logger() -> None:
    logger = get_logger("ironclaw.test.logger")
    assert logger.name == "ironclaw.test.logger"


def test_request_context_middleware_uses_unknown_request_id_when_missing() -> None:
    client = TestClient(_build_app())

    response = client.get("/ok")

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER_NAME] == "unknown-request-id"
    assert response.json()["request_id"] == "unknown-request-id"
    assert get_request_id() == ""


def test_request_context_middleware_preserves_incoming_request_id() -> None:
    client = TestClient(_build_app())

    response = client.get(
        "/ok",
        headers={REQUEST_ID_HEADER_NAME: "incoming-request-id"},
    )

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER_NAME] == "incoming-request-id"
    assert response.json()["request_id"] == "incoming-request-id"
    assert get_request_id() == ""


def test_request_context_middleware_preserves_request_id_on_options() -> None:
    client = TestClient(_build_app())

    response = client.options(
        "/ok",
        headers={
            "Origin": "https://moving-forward.ca",
            "Access-Control-Request-Method": "GET",
            REQUEST_ID_HEADER_NAME: "options-request-id",
        },
    )

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER_NAME] == "options-request-id"
    assert response.json()["request_id"] == "options-request-id"
    assert get_request_id() == ""


def test_request_context_middleware_does_not_overwrite_existing_response_header() -> None:
    client = TestClient(_build_app())

    response = client.get(
        "/preset-header",
        headers={REQUEST_ID_HEADER_NAME: "incoming-request-id"},
    )

    assert response.status_code == 200
    assert response.headers[REQUEST_ID_HEADER_NAME] == "route-header-request-id"
    assert response.json()["request_id"] == "incoming-request-id"
    assert get_request_id() == ""


def test_request_context_middleware_clears_context_after_exception() -> None:
    client = TestClient(_build_app())

    try:
        client.get(
            "/boom",
            headers={REQUEST_ID_HEADER_NAME: "boom-request-id"},
        )
    except RuntimeError as exc:
        assert str(exc) == "boom"
    else:
        raise AssertionError("expected RuntimeError to be raised")

    assert get_request_id() == ""


def test_request_context_middleware_non_http_scope_passes_through_unchanged() -> None:
    events: list[dict[str, object]] = []

    async def app(scope, receive, send) -> None:
        events.append(
            {
                "scope_type": scope["type"],
                "request_id_context": get_request_id(),
            }
        )
        await send({"type": "lifespan.startup.complete"})

    middleware = RequestContextMiddleware(app)

    async def receive() -> Message:
        return {"type": "lifespan.startup"}

    async def send(message: Message) -> None:
        events.append(
            {
                "message_type": message["type"],
                "request_id_context": get_request_id(),
            }
        )

    anyio.run(
        middleware,
        {"type": "lifespan", "state": {}},
        receive,
        send,
    )

    assert events[0]["scope_type"] == "lifespan"
    assert events[0]["request_id_context"] == ""
    assert events[1]["message_type"] == "lifespan.startup.complete"
    assert events[1]["request_id_context"] == ""
    assert get_request_id() == ""


def test_bind_security_event_logs_expected_payload_fields(caplog) -> None:
    logger = logging.getLogger("ironclaw.security.test")

    with caplog.at_level(logging.INFO, logger="ironclaw.security.test"):
        bind_security_event(
            logger,
            "security_event",
            scan_id="scan-123",
            verdict="block",
            risk_score=91,
            target_type="url",
            target_value="https://example.com/path",
            action_type="deny",
            review_status="pending",
            matched_patterns=["prompt-injection", "exfiltration"],
            extra_metadata={"source": "unit-test"},
        )

    record = caplog.records[-1]
    assert record.msg == "security_event"
    assert record.scan_id == "scan-123"
    assert record.verdict == "block"
    assert record.risk_score == 91
    assert record.target_type == "url"
    assert record.target_value == "https://example.com/path"
    assert record.action_type == "deny"
    assert record.review_status == "pending"
    assert record.matched_patterns == ["prompt-injection", "exfiltration"]
    assert record.source == "unit-test"


def test_truncate_value_returns_none_for_none() -> None:
    assert _truncate_value(None) is None


def test_truncate_value_returns_original_when_under_limit() -> None:
    assert _truncate_value("short", limit=10) == "short"


def test_truncate_value_truncates_when_over_limit() -> None:
    value = "x" * 20
    truncated = _truncate_value(value, limit=10)

    assert truncated == ("x" * 10) + "...[truncated]"
