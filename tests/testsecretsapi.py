from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

import app.api.secrets as secrets_api


class _Result:
    def __init__(
        self,
        *,
        verdict: str = "allow",
        blocked: bool = False,
        reasons: list[dict[str, Any]] | None = None,
        redacted_text: str | None = None,
    ) -> None:
        self.verdict = verdict
        self.blocked = blocked
        self.reasons = reasons if reasons is not None else [{"label": verdict}]
        self.redacted_text = redacted_text if redacted_text is not None else ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "blocked": self.blocked,
            "reasons": list(self.reasons),
            "redacted_text": self.redacted_text,
        }


class _SecretServiceStub:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def inspect_text(
        self,
        text: str,
        *,
        context: str | None = None,
        metadata: dict[str, Any] | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> _Result:
        self.calls.append(
            {
                "method": "inspect_text",
                "text": text,
                "context": context,
                "metadata": metadata if metadata is not None else {},
                "redact_secrets": redact_secrets,
                "block_unsafe_commands": block_unsafe_commands,
            },
        )
        return _Result(
            verdict="allow",
            blocked=False,
            reasons=[{"label": "text-ok"}],
            redacted_text="[redacted]" if redact_secrets else text,
        )

    def inspect_arguments(
        self,
        arguments: dict[str, Any],
        *,
        context: str | None = None,
        metadata: dict[str, Any] | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> _Result:
        self.calls.append(
            {
                "method": "inspect_arguments",
                "arguments": arguments,
                "context": context,
                "metadata": metadata if metadata is not None else {},
                "redact_secrets": redact_secrets,
                "block_unsafe_commands": block_unsafe_commands,
            },
        )
        return _Result(
            verdict="review",
            blocked=False,
            reasons=[{"label": "arguments-scanned"}],
            redacted_text="arguments-redacted",
        )

    def inspect_metadata(
        self,
        metadata: dict[str, Any],
        *,
        context: str | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> _Result:
        self.calls.append(
            {
                "method": "inspect_metadata",
                "metadata": metadata,
                "context": context,
                "redact_secrets": redact_secrets,
                "block_unsafe_commands": block_unsafe_commands,
            },
        )
        return _Result(
            verdict="allow",
            blocked=False,
            reasons=[{"label": "metadata-scanned"}],
            redacted_text="metadata-redacted",
        )

    def inspect_payload(
        self,
        *,
        tool_name: str | None = None,
        arguments: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        content: Any | None = None,
        context: str | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> _Result:
        self.calls.append(
            {
                "method": "inspect_payload",
                "tool_name": tool_name,
                "arguments": arguments if arguments is not None else {},
                "metadata": metadata if metadata is not None else {},
                "content": content,
                "context": context,
                "redact_secrets": redact_secrets,
                "block_unsafe_commands": block_unsafe_commands,
            },
        )
        return _Result(
            verdict="block",
            blocked=True,
            reasons=[{"label": "payload-blocked"}],
            redacted_text="payload-redacted",
        )


def _build_client(monkeypatch) -> tuple[TestClient, _SecretServiceStub]:
    service = _SecretServiceStub()
    monkeypatch.setattr(secrets_api, "build_secret_service", lambda: service)

    app = FastAPI()
    app.include_router(secrets_api.router)
    return TestClient(app), service


def test_secrets_api_overview(monkeypatch) -> None:
    client, _ = _build_client(monkeypatch)

    response = client.get("/api/secrets")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["name"] == "IronClaw secrets api"
    assert "/api/secrets/inspect" in body["routes"]
    assert "/api/secrets/health" in body["routes"]


def test_secrets_api_health(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.get("/api/secrets/health")

    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["service"] == "secrets"
    assert body["verdict"] == "allow"
    assert body["blocked"] is False
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_text"
    assert service.calls[0]["text"] == "health probe"


def test_secrets_api_inspect_routes_text_requests_to_text_scanner(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect",
        json={
            "text": "token=abc123",
            "metadata": {"trace_id": "trace-1"},
            "context": "prompt",
            "redact_secrets": True,
            "block_unsafe_commands": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "allow"
    assert body["blocked"] is False
    assert body["redacted_text"] == "[redacted]"
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_text"
    assert service.calls[0]["text"] == "token=abc123"
    assert service.calls[0]["metadata"]["trace_id"] == "trace-1"


def test_secrets_api_inspect_routes_arguments_requests_to_arguments_scanner(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect",
        json={
            "arguments": {"api_key": "secret-value"},
            "metadata": {"trace_id": "trace-2"},
            "context": "tool_call",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "review"
    assert body["blocked"] is False
    assert body["redacted_text"] == "arguments-redacted"
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_arguments"
    assert service.calls[0]["arguments"]["api_key"] == "secret-value"


def test_secrets_api_inspect_routes_metadata_only_requests_to_metadata_scanner(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect",
        json={
            "metadata": {"authorization": "Bearer top-secret"},
            "context": "headers",
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "allow"
    assert body["blocked"] is False
    assert body["redacted_text"] == "metadata-redacted"
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_metadata"
    assert service.calls[0]["metadata"]["authorization"] == "Bearer top-secret"


def test_secrets_api_inspect_routes_payload_requests_to_payload_scanner(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect",
        json={
            "tool_name": "bash",
            "arguments": {"command": "printenv"},
            "metadata": {"contains_secrets": True},
            "content": {"stream": "env dump"},
            "context": "execution",
            "redact_secrets": True,
            "block_unsafe_commands": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "block"
    assert body["blocked"] is True
    assert body["redacted_text"] == "payload-redacted"
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_payload"
    assert service.calls[0]["tool_name"] == "bash"
    assert service.calls[0]["content"] == {"stream": "env dump"}


def test_secrets_api_inspect_text_endpoint(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect/text",
        json={
            "text": "password=hunter2",
            "metadata": {"trace_id": "trace-3"},
            "context": "body",
            "redact_secrets": False,
            "block_unsafe_commands": False,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "allow"
    assert body["blocked"] is False
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_text"
    assert service.calls[0]["redact_secrets"] is False
    assert service.calls[0]["block_unsafe_commands"] is False


def test_secrets_api_inspect_arguments_endpoint(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect/arguments",
        json={
            "arguments": {"token": "abc"},
            "context": "tool_args",
            "metadata": {"trace_id": "trace-4"},
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "review"
    assert body["blocked"] is False
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_arguments"
    assert service.calls[0]["context"] == "tool_args"


def test_secrets_api_inspect_metadata_endpoint(monkeypatch) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect/metadata",
        json={
            "metadata": {"x-api-key": "abc123"},
            "context": "headers",
            "redact_secrets": True,
            "block_unsafe_commands": True,
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["verdict"] == "allow"
    assert body["blocked"] is False
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_metadata"
    assert service.calls[0]["context"] == "headers"


def test_secrets_api_inspect_text_endpoint_defaults_missing_text_to_empty_string(
    monkeypatch,
) -> None:
    client, service = _build_client(monkeypatch)

    response = client.post(
        "/api/secrets/inspect/text",
        json={},
    )

    assert response.status_code == 200
    assert len(service.calls) == 1
    assert service.calls[0]["method"] == "inspect_text"
    assert service.calls[0]["text"] == ""
