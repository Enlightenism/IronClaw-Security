from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from app.runtime import return_gate
from app.runtime.return_gate import (
    STAGE_INPROCESS,
    STAGE_SANDBOX,
    STAGE_SCAN_ERROR,
    new_sandbox_id,
    run_return_gate,
)
from app.runtime.return_scanner import ReturnScanResult
from app.schemas.telemetry import TelemetryEventType
from app.services.audit_store import get_security_audit_store
from app.services.sandbox_broker_client import SandboxBrokerClient

_ALLOW_BROKER = {"verdict": "allow", "status": "completed", "executor": "docker"}
_BLOCK_BROKER = {"verdict": "block", "status": "blocked", "executor": "docker", "reason": "pattern_match"}
_REAL_METERING_BLOCK = return_gate._metering_block


class _FakeBroker:
    def __init__(self, response: dict[str, Any] | Exception) -> None:
        self._response = response
        self.calls: list[dict[str, Any]] = []

    def run(
        self,
        action_type: str,
        target: str,
        payload: dict[str, Any],
        *,
        timeout_seconds: float,
        read_only_fs: bool = True,
        network_enabled: bool = False,
    ) -> dict[str, Any]:
        self.calls.append({"action_type": action_type, "target": target, "payload": payload, "timeout_seconds": timeout_seconds})
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


@pytest.fixture
def telemetry(monkeypatch: pytest.MonkeyPatch) -> list[tuple[Any, Any]]:
    events: list[tuple[Any, Any]] = []
    monkeypatch.setattr(return_gate, "append_telemetry_event", lambda event_type, payload=None: events.append((event_type, payload)))
    return events


@pytest.fixture(autouse=True)
def _bypass_metering(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(return_gate, "_metering_block", lambda *args, **kwargs: None)


class _FakeActionService:
    def __init__(self, *, executed: bool | None = None, error: Exception | None = None) -> None:
        self._executed = executed
        self._error = error
        self.requests: list[Any] = []

    def execute(self, request: Any) -> Any:
        self.requests.append(request)
        if self._error is not None:
            raise self._error
        return SimpleNamespace(executed=self._executed)


def test_metering_blocks_without_owner_key() -> None:
    decision = _REAL_METERING_BLOCK("sandbox-meter-1", owner_key=None, units=1, install_key_id=None, program=None)

    assert decision is not None
    assert decision.stage == return_gate.STAGE_METERING
    assert decision.reasons == ["billing_owner_unresolved"]


def test_metering_blocks_when_units_not_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeActionService(executed=False)
    monkeypatch.setattr(return_gate, "get_action_execute_service", lambda: service)

    decision = _REAL_METERING_BLOCK("sandbox-meter-2", owner_key="owner-meter", units=3, install_key_id=None, program=None)

    assert decision is not None
    assert decision.stage == return_gate.STAGE_METERING
    assert decision.reasons == ["protection_units_unavailable"]
    assert service.requests[0].requested_units == 3


def test_metering_blocks_when_service_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeActionService(error=RuntimeError("ledger down"))
    monkeypatch.setattr(return_gate, "get_action_execute_service", lambda: service)

    decision = _REAL_METERING_BLOCK("sandbox-meter-3", owner_key="owner-meter", units=1, install_key_id=None, program=None)

    assert decision is not None
    assert decision.reasons == ["usage_metering_unavailable"]


def test_metering_allows_when_units_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    service = _FakeActionService(executed=True)
    monkeypatch.setattr(return_gate, "get_action_execute_service", lambda: service)

    assert _REAL_METERING_BLOCK("sandbox-meter-4", owner_key="owner-meter", units=1, install_key_id=None, program=None) is None


def _set_scan(monkeypatch: pytest.MonkeyPatch, result: ReturnScanResult | Exception) -> None:
    def _scan(*args: Any, **kwargs: Any) -> ReturnScanResult:
        if isinstance(result, Exception):
            raise result
        return result

    monkeypatch.setattr(return_gate, "scan_return", _scan)


def _allow_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_scan(monkeypatch, ReturnScanResult(verdict="allow", risk_score=0))


def _block_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    _set_scan(monkeypatch, ReturnScanResult(verdict="block", risk_score=90, reasons=["text_classifier"]))


def _run(broker: Any) -> return_gate.ReturnGateDecision:
    return run_return_gate(platform="claude_code", payload={"stdout": "ok"}, content="hello", broker_client=broker)


def _gate_records(owner_key: str) -> list[Any]:
    return [event for event in get_security_audit_store().list_events(limit=10000, include_seeded=False) if event.metadata.get("owner_key") == owner_key]


def test_block_is_audited_without_incident(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _block_scan(monkeypatch)
    owner_key = "owner-return-gate-block"

    decision = run_return_gate(
        platform="claude_code",
        payload={"stdout": "secret"},
        content="secret",
        broker_client=_FakeBroker(_ALLOW_BROKER),
        owner_key=owner_key,
    )

    events = _gate_records(owner_key)
    assert len(events) == 1
    assert events[0].event_type == "return_gate_decision"
    assert events[0].verdict == "block"
    assert events[0].severity == "high"
    assert events[0].metadata["decision_id"] == decision.sandbox_id
    assert events[0].metadata["reason_codes"] == ["text_classifier"]
    assert "secret" not in str(events[0].metadata)


def test_allow_is_audited_without_incident(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)
    owner_key = "owner-return-gate-allow"

    run_return_gate(platform="claude_code", payload={"stdout": "ok"}, content="hello", broker_client=_FakeBroker(_ALLOW_BROKER), owner_key=owner_key)

    events = _gate_records(owner_key)
    assert len(events) == 1
    assert events[0].verdict == "allow"
    assert events[0].severity == "low"


def test_block_audit_records_install_key_id(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _block_scan(monkeypatch)
    owner_key = "owner-return-gate-key"

    run_return_gate(
        platform="claude_code",
        payload={"stdout": "secret"},
        content="secret",
        broker_client=_FakeBroker(_ALLOW_BROKER),
        owner_key=owner_key,
        install_key_id="ik_claude_code_test",
    )

    events = _gate_records(owner_key)
    assert len(events) == 1
    assert events[0].metadata["install_key_id"] == "ik_claude_code_test"


def test_allow_when_in_process_and_sandbox_both_allow(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)
    broker = _FakeBroker(_ALLOW_BROKER)

    decision = _run(broker)

    assert decision.verdict == "allow"
    assert decision.blocked is False
    assert decision.stage == STAGE_SANDBOX
    assert decision.reasons == []
    assert len(broker.calls) == 1


def test_in_process_block_skips_broker(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _block_scan(monkeypatch)
    broker = _FakeBroker(_ALLOW_BROKER)

    decision = _run(broker)

    assert decision.verdict == "block"
    assert decision.blocked is True
    assert decision.stage == STAGE_INPROCESS
    assert decision.reasons == ["text_classifier"]
    assert broker.calls == []


def test_sandbox_block_blocks(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)

    decision = _run(_FakeBroker(_BLOCK_BROKER))

    assert decision.verdict == "block"
    assert decision.stage == STAGE_SANDBOX
    assert decision.reasons == ["pattern_match"]


def test_allow_without_completed_status_blocks(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)

    decision = _run(_FakeBroker({"verdict": "allow", "status": "unavailable", "executor": "docker"}))

    assert decision.verdict == "block"
    assert decision.stage == STAGE_SANDBOX


def test_allow_marked_untrusted_blocks(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)

    decision = _run(_FakeBroker({"verdict": "allow", "status": "completed", "untrusted": True}))

    assert decision.verdict == "block"


def test_scan_exception_blocks_and_skips_broker(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _set_scan(monkeypatch, RuntimeError("guard crashed"))
    broker = _FakeBroker(_ALLOW_BROKER)

    decision = _run(broker)

    assert decision.verdict == "block"
    assert decision.stage == STAGE_SCAN_ERROR
    assert decision.reasons == ["return_scan_error"]
    assert broker.calls == []


def test_broker_timeout_blocks(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)

    def _timeout(*args: Any, **kwargs: Any) -> None:
        raise httpx.ReadTimeout("timed out")

    monkeypatch.setattr(httpx, "post", _timeout)
    client = SandboxBrokerClient(broker_url="http://broker.test", broker_token="test-token")

    decision = _run(client)

    assert decision.verdict == "block"
    assert decision.stage == STAGE_SANDBOX
    assert decision.reasons == ["broker_unreachable"]


def test_broker_down_blocks(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)

    def _refused(*args: Any, **kwargs: Any) -> None:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "post", _refused)
    client = SandboxBrokerClient(broker_url="http://broker.test", broker_token="test-token")

    decision = _run(client)

    assert decision.verdict == "block"
    assert decision.reasons == ["broker_unreachable"]


def test_broker_exception_blocks(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)

    decision = _run(_FakeBroker(RuntimeError("unexpected")))

    assert decision.verdict == "block"
    assert decision.reasons == ["broker_error"]


def test_broker_health_reports_reachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *_args, **_kwargs: httpx.Response(200, json={"status": "ok"}))
    client = SandboxBrokerClient(broker_url="http://broker.test", broker_token="test-token")

    assert client.health() == {"reachable": True, "reason": None}


def test_broker_health_reports_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refused(*_args: Any, **_kwargs: Any) -> None:
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", _refused)
    client = SandboxBrokerClient(broker_url="http://broker.test", broker_token="test-token")

    assert client.health() == {"reachable": False, "reason": "broker_unreachable"}


def test_broker_health_reports_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", lambda *_args, **_kwargs: httpx.Response(503))
    client = SandboxBrokerClient(broker_url="http://broker.test", broker_token="test-token")

    assert client.health() == {"reachable": False, "reason": "broker_error"}


def test_broker_health_unconfigured_without_token() -> None:
    client = SandboxBrokerClient(broker_url="http://broker.test", broker_token="")

    assert client.health() == {"reachable": False, "reason": "broker_unconfigured"}


def test_each_return_gets_unique_sandbox_id(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _allow_scan(monkeypatch)
    broker = _FakeBroker(_ALLOW_BROKER)

    first = _run(broker)
    second = _run(broker)

    assert first.sandbox_id.startswith("return-")
    assert first.sandbox_id != second.sandbox_id
    assert broker.calls[0]["payload"]["sandbox_id"] == first.sandbox_id


def test_new_sandbox_id_is_prefixed() -> None:
    assert new_sandbox_id().startswith("return-")


def test_decision_is_recorded_in_telemetry(monkeypatch: pytest.MonkeyPatch, telemetry: list[tuple[Any, Any]]) -> None:
    _block_scan(monkeypatch)

    decision = _run(_FakeBroker(_ALLOW_BROKER))

    assert len(telemetry) == 1
    event_type, payload = telemetry[0]
    assert event_type == TelemetryEventType.RETURN_GATE_DECISION
    assert payload["sandbox_id"] == decision.sandbox_id
    assert payload["verdict"] == "block"
    assert payload["platform"] == "claude_code"


def test_telemetry_failure_does_not_change_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    _allow_scan(monkeypatch)

    def _broken(*args: Any, **kwargs: Any) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(return_gate, "append_telemetry_event", _broken)

    decision = _run(_FakeBroker(_ALLOW_BROKER))

    assert decision.verdict == "allow"
