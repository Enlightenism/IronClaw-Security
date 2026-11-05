from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

import ironclaw_sdk.goose_hooks as goose_hooks
import ironclaw_sdk.runtime_hooks as runtime_hooks
from ironclaw_sdk.runtime_hooks import GENERIC_BLOCK_REASON, UNIDENTIFIED_TOOL_REASON


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


@pytest.fixture
def gate(monkeypatch: pytest.MonkeyPatch) -> _GateRecorder:
    recorder = _GateRecorder()
    monkeypatch.setattr(runtime_hooks, "post_gate", recorder)
    return recorder


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path


def _hooks_path(home: Path) -> Path:
    return goose_hooks.goose_plugin_dir(home) / "hooks" / "hooks.json"


def _event(tool_name: str, tool_input: dict[str, Any]) -> str:
    return json.dumps({"tool_name": tool_name, "tool_input": tool_input})


def test_merged_config_blocks_on_failure_in_pre_tool_use_only() -> None:
    config = goose_hooks.merge_goose_hooks({})

    assert list(config["hooks"]) == ["PreToolUse"]
    entry = config["hooks"]["PreToolUse"][0]["hooks"][0]
    assert entry["on_failure"] == "block"
    assert entry["type"] == "command"
    assert entry["timeout"] == goose_hooks.HOOK_TIMEOUT_SECONDS
    assert goose_hooks.HOOK_MARKER in entry["command"]


def test_merge_is_idempotent() -> None:
    once = goose_hooks.merge_goose_hooks({})
    twice = goose_hooks.merge_goose_hooks(once)

    assert twice == once
    assert len(twice["hooks"]["PreToolUse"]) == 1


def test_merge_keeps_unrelated_entries() -> None:
    existing = {"hooks": {"PreToolUse": [{"matcher": "x", "hooks": [{"type": "command", "command": "other-tool"}]}]}}

    config = goose_hooks.merge_goose_hooks(existing)

    commands = [hook["command"] for entry in config["hooks"]["PreToolUse"] for hook in entry["hooks"]]
    assert "other-tool" in commands
    assert any(goose_hooks.HOOK_MARKER in command for command in commands)


def test_merge_rejects_non_object_hooks() -> None:
    with pytest.raises(ValueError):
        goose_hooks.merge_goose_hooks({"hooks": []})


def test_write_creates_manifest_and_hooks(home: Path) -> None:
    written = goose_hooks.write_goose_hook(home)

    assert written == [goose_hooks.goose_plugin_dir(home) / "plugin.json", _hooks_path(home)]
    assert json.loads(written[0].read_text(encoding="utf-8"))["name"] == goose_hooks.PLUGIN_NAME
    assert json.loads(_hooks_path(home).read_text(encoding="utf-8"))["hooks"]["PreToolUse"][0]["hooks"][0]["on_failure"] == "block"


def test_invalid_existing_hooks_fail_before_any_write(home: Path) -> None:
    hooks_path = _hooks_path(home)
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text("{not json", encoding="utf-8")

    with pytest.raises(ValueError):
        goose_hooks.write_goose_hook(home)

    assert not (goose_hooks.goose_plugin_dir(home) / "plugin.json").exists()
    assert hooks_path.read_text(encoding="utf-8") == "{not json"


def test_pre_tool_allows_non_install_calls(gate: _GateRecorder) -> None:
    assert goose_hooks.evaluate_pre_tool(_event("read_file", {"path": "README.md"}), None) is None
    assert gate.calls == []


def test_pre_tool_allows_pinned_install(gate: _GateRecorder) -> None:
    assert goose_hooks.evaluate_pre_tool(_event("bash", {"command": "npm install ironclaw@1.0.0"}), None) is None

    route, program, body = gate.calls[0]
    assert route == "/install-gate/evaluate"
    assert program == "goose"
    assert body["platform"] == "goose"


def test_pre_tool_blocks_unpinned_install(gate: _GateRecorder) -> None:
    gate.response = {"verdict": "block", "reasons": ["not_pinned"]}

    reason = goose_hooks.evaluate_pre_tool(_event("bash", {"command": "pip install evil-pkg"}), None)

    assert reason is not None
    assert "not_pinned" in reason


def test_pre_tool_blocks_when_gate_unreachable(gate: _GateRecorder) -> None:
    gate.error = OSError("gate unreachable")

    assert goose_hooks.evaluate_pre_tool(_event("bash", {"command": "pip install evil-pkg"}), None) == GENERIC_BLOCK_REASON


@pytest.mark.parametrize("raw_event", ["", "{not json", "[]", json.dumps({"tool_input": {"command": "pip install x"}})])
def test_pre_tool_blocks_malformed_input(gate: _GateRecorder, raw_event: str) -> None:
    assert goose_hooks.evaluate_pre_tool(raw_event, None) == UNIDENTIFIED_TOOL_REASON
    assert gate.calls == []


def test_main_blocks_with_exit_code_two(gate: _GateRecorder, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    gate.response = {"verdict": "block", "reasons": ["not_pinned"]}
    monkeypatch.setattr("sys.stdin", io.StringIO(_event("bash", {"command": "pip install evil-pkg"})))

    assert goose_hooks.main([]) == 2
    assert "not_pinned" in capsys.readouterr().err


def test_main_allows_with_exit_code_zero(gate: _GateRecorder, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(_event("read_file", {"path": "README.md"})))

    assert goose_hooks.main([]) == 0


def test_main_install_writes_config(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert goose_hooks.main(["--install"]) == 0
    assert str(_hooks_path(home)) in capsys.readouterr().out
    assert _hooks_path(home).exists()


def test_main_install_reports_invalid_existing_hooks(home: Path, capsys: pytest.CaptureFixture[str]) -> None:
    hooks_path = _hooks_path(home)
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text(json.dumps({"hooks": []}), encoding="utf-8")

    assert goose_hooks.main(["--install"]) == 1
    assert "not a JSON object" in capsys.readouterr().err
