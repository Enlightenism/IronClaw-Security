from __future__ import annotations

import json
from typing import Any

import pytest

import ironclaw_sdk.hermes_plugin as hermes_plugin
from ironclaw_sdk.hermes_plugin import BLOCKED_REPLACEMENT_TEXT
import ironclaw_sdk.runtime_hooks as runtime_hooks
from ironclaw_sdk.runtime_hooks import GENERIC_BLOCK_REASON


class _GateRecorder:
    def __init__(self) -> None:
        self.response: Any = {"verdict": "allow", "reasons": []}
        self.error: Exception | None = None
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def __call__(self, route: str, program: str, body: dict[str, Any], config_file: Any = None, timeout: float | None = None) -> Any:
        self.calls.append((route, program, body))
        if self.error is not None:
            raise self.error
        return self.response


class _Context:
    def __init__(self) -> None:
        self.hooks: dict[str, Any] = {}

    def register_hook(self, name: str, callback: Any) -> None:
        self.hooks[name] = callback


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> _GateRecorder:
    recorder = _GateRecorder()
    monkeypatch.setattr(runtime_hooks, "post_gate", recorder)
    monkeypatch.setattr(hermes_plugin, "post_gate", recorder)
    return recorder


def test_register_adds_two_hooks() -> None:
    ctx = _Context()

    hermes_plugin.register(ctx)

    assert ctx.hooks == {
        "pre_tool_call": hermes_plugin.pre_tool_call,
        "transform_tool_result": hermes_plugin.transform_tool_result,
    }


def test_pre_tool_call_ignores_non_install_calls(gate: _GateRecorder) -> None:
    assert hermes_plugin.pre_tool_call(tool_name="read_file", args={"path": "README.md"}) is None
    assert gate.calls == []


def test_pre_tool_call_allows_pinned_install(gate: _GateRecorder) -> None:
    assert hermes_plugin.pre_tool_call(tool_name="bash", args={"command": "pip install ironclaw-sdk==1.1.0"}) is None

    route, program, body = gate.calls[0]
    assert route == "/install-gate/evaluate"
    assert program == "hermes"
    assert body["platform"] == "hermes"
    assert "pip install" in body["command"]


def test_pre_tool_call_blocks_unpinned_install(gate: _GateRecorder) -> None:
    gate.response = {"verdict": "block", "reasons": ["not_pinned"]}

    result = hermes_plugin.pre_tool_call(tool_name="bash", args={"command": "npm install evil-pkg"})

    assert result is not None
    assert result["action"] == "block"
    assert "not_pinned" in result["message"]


def test_pre_tool_call_blocks_when_gate_unreachable(gate: _GateRecorder) -> None:
    gate.error = OSError("gate unreachable")

    result = hermes_plugin.pre_tool_call(tool_name="bash", args={"command": "npm install evil-pkg"})

    assert result == {"action": "block", "message": GENERIC_BLOCK_REASON}


def test_pre_tool_call_blocks_when_classifier_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    def _broken(tool_name: str, params: Any) -> str | None:
        raise RuntimeError("classifier failure")

    monkeypatch.setattr(hermes_plugin, "install_command_text", _broken)

    result = hermes_plugin.pre_tool_call(tool_name="bash", args={"command": "ls"})

    assert result == {"action": "block", "message": GENERIC_BLOCK_REASON}


def test_transform_allow_returns_none(gate: _GateRecorder) -> None:
    gate.response = {"verdict": "allow", "replacement": None, "reasons": []}

    assert hermes_plugin.transform_tool_result(tool_name="web_fetch", result="clean output") is None

    route, program, body = gate.calls[0]
    assert route == "/return-gate/transform"
    assert program == "hermes"
    assert body["platform"] == "hermes"
    assert body["content"] == "clean output"


def test_transform_block_returns_replacement(gate: _GateRecorder) -> None:
    gate.response = {"verdict": "block", "replacement": "[safe replacement]", "reasons": ["injection"]}

    assert hermes_plugin.transform_tool_result(tool_name="web_fetch", result="bad output") == "[safe replacement]"


@pytest.mark.parametrize(
    "response",
    [
        {"verdict": "block", "replacement": None, "reasons": ["injection"]},
        {"verdict": "unknown"},
        [],
        None,
    ],
)
def test_transform_unexpected_shape_returns_blocked_text(gate: _GateRecorder, response: Any) -> None:
    gate.response = response

    assert hermes_plugin.transform_tool_result(tool_name="web_fetch", result="output") == BLOCKED_REPLACEMENT_TEXT


def test_transform_outage_returns_blocked_text(gate: _GateRecorder) -> None:
    gate.error = OSError("gate unreachable")

    assert hermes_plugin.transform_tool_result(tool_name="web_fetch", result="output") == BLOCKED_REPLACEMENT_TEXT


def test_transform_serializes_structured_results(gate: _GateRecorder) -> None:
    hermes_plugin.transform_tool_result(tool_name="web_fetch", result={"a": 1})

    assert gate.calls[0][2]["content"] == json.dumps({"a": 1}, default=str, ensure_ascii=False)


def test_large_content_is_forwarded_in_full(gate: _GateRecorder) -> None:
    large = "x" * 1_000_001

    assert hermes_plugin.transform_tool_result(tool_name="web_fetch", result=large) is None

    assert gate.calls[0][2]["content"] == large


def test_return_body_carries_url_command_and_file_path_for_parity(gate: _GateRecorder) -> None:
    hermes_plugin.transform_tool_result(
        tool_name="web_fetch",
        result="output",
        args={
            "url": "https://example.com/page",
            "command": "curl https://example.com/page",
            "file_path": "notes/readme.md",
        },
    )

    body = gate.calls[0][2]
    assert body["payload"]["tool_name"] == "web_fetch"
    assert body["payload"]["url"] == "https://example.com/page"
    assert body["payload"]["command"] == "curl https://example.com/page"
    assert body["payload"]["file_path"] == "notes/readme.md"


def test_each_tool_result_triggers_one_gate_call(gate: _GateRecorder) -> None:
    hermes_plugin.transform_tool_result(tool_name="web_fetch", result="output")

    assert [route for route, _, _ in gate.calls] == ["/return-gate/transform"]
