from __future__ import annotations

from unittest.mock import MagicMock, patch

from fastapi import HTTPException, Request
from fastapi.exceptions import RequestValidationError
import pytest

from app.core.errors import (
    AppError,
    ConflictError,
    ErrorResponse,
    GuardRejectedError,
    NotFoundError,
    _is_value_error,
    _sanitize_validation_errors,
    app_error_handler,
    build_error_response,
    http_exception_handler,
    insufficient_units_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.core.unit_wallet import TOKEN_CHUNK_SIZE, InsufficientUnitsError

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_request(path: str = "/test", request_id: str | None = None) -> Request:
    scope = {
        "type": "http",
        "method": "GET",
        "path": path,
        "query_string": b"",
        "headers": [],
    }
    request = Request(scope)
    if request_id:
        request.state.request_id = request_id
    return request


def _make_validation_error(errors: list[dict]) -> RequestValidationError:
    exc = MagicMock(spec=RequestValidationError)
    exc.errors.return_value = errors
    return exc


# ---------------------------------------------------------------------------
# unhandled_exception_handler
# ---------------------------------------------------------------------------


class TestUnhandledExceptionHandler:
    @pytest.mark.asyncio
    async def test_bare_exception_returns_500_internal_error_shape(self):
        request = _make_request(request_id="req-bare-001")
        exc = RuntimeError("something exploded")

        with patch("app.core.errors.get_logger"):
            resp = await unhandled_exception_handler(request, exc)

        assert resp.status_code == 500
        body = resp.body
        import json

        data = json.loads(body)
        assert data["error"] == "internal_error"
        assert data["message"] == "Internal server error"
        assert "request_id" in data

    @pytest.mark.asyncio
    async def test_http_exception_401_delegates_not_500(self):
        request = _make_request(request_id="req-401-001")
        exc = HTTPException(status_code=401, detail="Unauthorized")

        with patch("app.core.errors.get_logger"):
            resp = await unhandled_exception_handler(request, exc)

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_http_exception_401_does_not_return_500(self):
        request = _make_request()
        exc = HTTPException(status_code=401, detail="Unauthorized")

        with patch("app.core.errors.get_logger"):
            resp = await unhandled_exception_handler(request, exc)

        assert resp.status_code != 500

    @pytest.mark.asyncio
    async def test_http_exception_403_returns_403_not_500(self):
        request = _make_request(request_id="req-403-001")
        exc = HTTPException(status_code=403, detail="Forbidden")

        with patch("app.core.errors.get_logger"):
            resp = await unhandled_exception_handler(request, exc)

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_http_exception_403_does_not_return_500(self):
        request = _make_request()
        exc = HTTPException(status_code=403, detail="Forbidden")

        with patch("app.core.errors.get_logger"):
            resp = await unhandled_exception_handler(request, exc)

        assert resp.status_code != 500

    @pytest.mark.asyncio
    async def test_bare_exception_body_has_no_detail_key(self):
        request = _make_request()
        exc = ValueError("bad value")

        with patch("app.core.errors.get_logger"):
            resp = await unhandled_exception_handler(request, exc)

        import json

        data = json.loads(resp.body)
        assert "error" in data
        assert "message" in data


# ---------------------------------------------------------------------------
# app_error_handler
# ---------------------------------------------------------------------------


class TestAppErrorHandler:
    @pytest.mark.asyncio
    async def test_app_error_base_400(self):
        request = _make_request(request_id="req-app-001")
        exc = AppError(error="test_error", message="test message")

        with patch("app.core.errors.get_logger"):
            resp = await app_error_handler(request, exc)

        import json

        assert resp.status_code == 400
        data = json.loads(resp.body)
        assert data["error"] == "test_error"
        assert data["message"] == "test message"

    @pytest.mark.asyncio
    async def test_not_found_error_returns_404(self):
        request = _make_request(request_id="req-nf-001")
        exc = NotFoundError("Policy not found")

        with patch("app.core.errors.get_logger"):
            resp = await app_error_handler(request, exc)

        import json

        assert resp.status_code == 404
        data = json.loads(resp.body)
        assert data["error"] == "not_found"
        assert data["message"] == "Policy not found"

    @pytest.mark.asyncio
    async def test_conflict_error_returns_409(self):
        request = _make_request(request_id="req-conflict-001")
        exc = ConflictError("Key already exists")

        with patch("app.core.errors.get_logger"):
            resp = await app_error_handler(request, exc)

        import json

        assert resp.status_code == 409
        data = json.loads(resp.body)
        assert data["error"] == "conflict"
        assert data["message"] == "Key already exists"

    @pytest.mark.asyncio
    async def test_guard_rejected_error_returns_403(self):
        request = _make_request(request_id="req-guard-001")
        exc = GuardRejectedError(
            "Prompt injection detected",
            details={"pattern": "ignore previous instructions"},
        )

        with patch("app.core.errors.get_logger"):
            resp = await app_error_handler(request, exc)

        import json

        assert resp.status_code == 403
        data = json.loads(resp.body)
        assert data["error"] == "guard_rejected"
        assert data["message"] == "Prompt injection detected"
        assert data["details"]["pattern"] == "ignore previous instructions"

    @pytest.mark.asyncio
    async def test_app_error_details_passthrough(self):
        request = _make_request(request_id="req-detail-001")
        exc = AppError(
            error="custom_error",
            message="custom message",
            details={"key": "value", "count": 3},
        )

        with patch("app.core.errors.get_logger"):
            resp = await app_error_handler(request, exc)

        import json

        data = json.loads(resp.body)
        assert data["details"]["key"] == "value"
        assert data["details"]["count"] == 3

    @pytest.mark.asyncio
    async def test_app_error_request_id_in_response(self):
        request = _make_request(request_id="req-id-check")
        exc = NotFoundError()

        with patch("app.core.errors.get_logger"):
            resp = await app_error_handler(request, exc)

        import json

        data = json.loads(resp.body)
        assert data["request_id"] == "req-id-check"


# ---------------------------------------------------------------------------
# validation_exception_handler
# ---------------------------------------------------------------------------


class TestValidationExceptionHandler:
    @pytest.mark.asyncio
    async def test_type_error_returns_422(self):
        request = _make_request(request_id="req-val-001")
        errors = [{"type": "string_type", "loc": ["body", "name"], "msg": "string required", "input": 123, "url": "https://errors.pydantic.dev/2/v/string_type"}]
        exc = _make_validation_error(errors)

        with patch("app.core.errors.get_logger"):
            resp = await validation_exception_handler(request, exc)

        import json

        assert resp.status_code == 422
        data = json.loads(resp.body)
        assert data["error"] == "validation_error"

    @pytest.mark.asyncio
    async def test_value_error_returns_400(self):
        request = _make_request(request_id="req-val-002")
        errors = [{"type": "value_error", "loc": ["body"], "msg": "Value error, passwords do not match", "input": {}}]
        exc = _make_validation_error(errors)

        with patch("app.core.errors.get_logger"):
            resp = await validation_exception_handler(request, exc)

        import json

        assert resp.status_code == 400
        data = json.loads(resp.body)
        assert data["error"] == "bad_request"

    @pytest.mark.asyncio
    async def test_mixed_errors_returns_422(self):
        request = _make_request()
        errors = [
            {"type": "value_error", "loc": ["body"], "msg": "bad value", "input": {}},
            {"type": "string_type", "loc": ["body", "name"], "msg": "required", "input": None},
        ]
        exc = _make_validation_error(errors)

        with patch("app.core.errors.get_logger"):
            resp = await validation_exception_handler(request, exc)

        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_details_errors_field_present(self):
        request = _make_request()
        errors = [{"type": "string_type", "loc": ["body", "x"], "msg": "required", "input": None}]
        exc = _make_validation_error(errors)

        with patch("app.core.errors.get_logger"):
            resp = await validation_exception_handler(request, exc)

        import json

        data = json.loads(resp.body)
        assert "errors" in data["details"]
        assert isinstance(data["details"]["errors"], list)


# ---------------------------------------------------------------------------
# http_exception_handler
# ---------------------------------------------------------------------------


class TestHttpExceptionHandler:
    @pytest.mark.asyncio
    async def test_str_detail_preserved(self):
        request = _make_request(request_id="req-http-001")
        exc = HTTPException(status_code=404, detail="Not found here")

        with patch("app.core.errors.get_logger"):
            resp = await http_exception_handler(request, exc)

        import json

        assert resp.status_code == 404
        data = json.loads(resp.body)
        assert data["detail"] == "Not found here"

    @pytest.mark.asyncio
    async def test_mapping_detail_preserved(self):
        request = _make_request(request_id="req-http-002")
        detail_map = {"message": "Quota exceeded", "code": "quota_exceeded"}
        exc = HTTPException(status_code=429, detail=detail_map)

        with patch("app.core.errors.get_logger"):
            resp = await http_exception_handler(request, exc)

        import json

        assert resp.status_code == 429
        data = json.loads(resp.body)
        assert data["detail"]["message"] == "Quota exceeded"
        assert data["detail"]["code"] == "quota_exceeded"

    @pytest.mark.asyncio
    async def test_401_status_code_preserved(self):
        request = _make_request()
        exc = HTTPException(status_code=401, detail="Invalid API key")

        with patch("app.core.errors.get_logger"):
            resp = await http_exception_handler(request, exc)

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_403_status_code_preserved(self):
        request = _make_request()
        exc = HTTPException(status_code=403, detail="Access denied")

        with patch("app.core.errors.get_logger"):
            resp = await http_exception_handler(request, exc)

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_detail_key_always_present(self):
        request = _make_request()
        exc = HTTPException(status_code=400, detail="bad input")

        with patch("app.core.errors.get_logger"):
            resp = await http_exception_handler(request, exc)

        import json

        data = json.loads(resp.body)
        assert "detail" in data


# ---------------------------------------------------------------------------
# insufficient_units_handler
# ---------------------------------------------------------------------------


class TestInsufficientUnitsHandler:
    @pytest.mark.asyncio
    async def test_returns_402(self):
        request = _make_request(request_id="req-units-001")
        exc = InsufficientUnitsError(owner_key="user_abc", have=2, need=5)

        with patch("app.core.errors.get_logger"):
            resp = await insufficient_units_handler(request, exc)

        assert resp.status_code == 402

    @pytest.mark.asyncio
    async def test_detail_shape(self):
        request = _make_request(request_id="req-units-002")
        exc = InsufficientUnitsError(owner_key="user_abc", have=2, need=5)

        with patch("app.core.errors.get_logger"):
            resp = await insufficient_units_handler(request, exc)

        import json

        data = json.loads(resp.body)
        assert "detail" in data
        detail = data["detail"]
        assert detail["status"] == "insufficient_units"
        assert detail["owner_key"] == "user_abc"
        assert detail["have"] == 2
        assert detail["need"] == 5
        assert detail["tokens_per_unit"] == TOKEN_CHUNK_SIZE

    @pytest.mark.asyncio
    async def test_detail_is_dict_not_string(self):
        request = _make_request()
        exc = InsufficientUnitsError(owner_key="key_x", have=0, need=10)

        with patch("app.core.errors.get_logger"):
            resp = await insufficient_units_handler(request, exc)

        import json

        data = json.loads(resp.body)
        assert isinstance(data["detail"], dict)


# ---------------------------------------------------------------------------
# build_error_response
# ---------------------------------------------------------------------------


class TestBuildErrorResponse:
    def test_request_id_passthrough(self):
        result = build_error_response(
            error="test_err",
            message="test msg",
            request_id="req-build-001",
        )
        assert isinstance(result, ErrorResponse)
        assert result.request_id == "req-build-001"
        assert result.error == "test_err"
        assert result.message == "test msg"

    def test_details_field_populated(self):
        result = build_error_response(
            error="some_error",
            message="some message",
            details={"foo": "bar", "count": 99},
        )
        assert result.details["foo"] == "bar"
        assert result.details["count"] == 99

    def test_details_defaults_to_empty_dict(self):
        result = build_error_response(error="e", message="m")
        assert result.details == {}

    def test_request_id_none_when_not_provided_and_no_context(self):
        with patch("app.core.errors.get_request_id", return_value=None):
            result = build_error_response(error="e", message="m")
        assert result.request_id is None

    def test_falls_back_to_get_request_id(self):
        with patch("app.core.errors.get_request_id", return_value="ctx-req-id"):
            result = build_error_response(error="e", message="m")
        assert result.request_id == "ctx-req-id"


# ---------------------------------------------------------------------------
# _sanitize_validation_errors
# ---------------------------------------------------------------------------


class TestSanitizeValidationErrors:
    def test_exception_in_ctx_is_stringified(self):
        err = ValueError("bad val")
        errors = [{"type": "value_error", "loc": ["body"], "msg": "fail", "ctx": {"error": err}}]
        result = _sanitize_validation_errors(errors)
        assert result[0]["ctx"]["error"] == "bad val"

    def test_exception_as_top_level_value_stringified(self):
        err = TypeError("type mismatch")
        errors = [{"type": "type_error", "loc": ["body", "x"], "msg": str(err), "input": err}]
        result = _sanitize_validation_errors(errors)
        assert isinstance(result[0]["input"], str)

    def test_non_dict_error_wrapped_in_msg(self):
        errors = ["raw string error"]
        result = _sanitize_validation_errors(errors)
        assert result == [{"msg": "raw string error"}]

    def test_passthrough_normal_dict(self):
        errors = [{"type": "string_type", "loc": ["x"], "msg": "required", "input": None}]
        result = _sanitize_validation_errors(errors)
        assert result[0]["type"] == "string_type"
        assert result[0]["msg"] == "required"

    def test_empty_list_returns_empty(self):
        assert _sanitize_validation_errors([]) == []

    def test_ctx_non_exception_values_preserved(self):
        errors = [{"type": "value_error", "ctx": {"min_length": 3, "actual": 1}}]
        result = _sanitize_validation_errors(errors)
        assert result[0]["ctx"]["min_length"] == 3
        assert result[0]["ctx"]["actual"] == 1


# ---------------------------------------------------------------------------
# _is_value_error
# ---------------------------------------------------------------------------


class TestIsValueError:
    def test_empty_list_returns_false(self):
        assert _is_value_error([]) is False

    def test_all_value_error_returns_true(self):
        errors = [
            {"type": "value_error", "loc": ["body"], "msg": "fail"},
            {"type": "value_error", "loc": ["body"], "msg": "fail2"},
        ]
        assert _is_value_error(errors) is True

    def test_mixed_types_returns_false(self):
        errors = [
            {"type": "value_error", "loc": ["body"], "msg": "fail"},
            {"type": "string_type", "loc": ["body", "x"], "msg": "required"},
        ]
        assert _is_value_error(errors) is False

    def test_single_non_value_error_returns_false(self):
        errors = [{"type": "missing", "loc": ["body", "name"], "msg": "field required"}]
        assert _is_value_error(errors) is False

    def test_non_dict_entry_returns_false(self):
        errors = ["value_error"]
        assert _is_value_error(errors) is False

    def test_dict_missing_type_key_returns_false(self):
        errors = [{"loc": ["body"], "msg": "fail"}]
        assert _is_value_error(errors) is False

    def test_single_value_error_returns_true(self):
        errors = [{"type": "value_error", "loc": ["body"], "msg": "fail"}]
        assert _is_value_error(errors) is True
