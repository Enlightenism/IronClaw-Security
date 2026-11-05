"""Writes and runs the Goose PreToolUse install gate.

Goose has no return-path enforcement, so only PreToolUse is installed. The hook
uses ``on_failure: "block"``, so a crash or timeout also denies the tool call.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from ironclaw_sdk.runtime_hooks import (
    UNIDENTIFIED_TOOL_REASON,
    authorize_install,
    install_command_text,
    load_hook_config,
    write_runtime_hook,
)

GOOSE_PROGRAM = "goose"
PLUGIN_NAME = "ironclaw-security"
PLUGIN_VERSION = "1.0.0"
HOOK_MARKER = "ironclaw_sdk.goose_hooks"
HOOK_TIMEOUT_SECONDS = 30


def goose_plugin_dir(home: Path | None = None) -> Path:
    return (home or Path.home()) / ".agents" / "plugins" / PLUGIN_NAME


def plugin_manifest() -> dict[str, str]:
    return {"name": PLUGIN_NAME, "version": PLUGIN_VERSION, "description": "IronClaw install gate for Goose."}


def hook_command() -> str:
    return f"python -m {HOOK_MARKER}"


def merge_goose_hooks(existing: dict[str, Any]) -> dict[str, Any]:
    config = dict(existing)
    hooks = config.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("Existing hooks configuration is not a JSON object.")
    entries = hooks.get("PreToolUse", [])
    if not isinstance(entries, list):
        raise ValueError("Existing PreToolUse hooks configuration is not a JSON array.")
    kept = [entry for entry in entries if HOOK_MARKER not in json.dumps(entry)]
    kept.append({"matcher": ".*", "hooks": [{"type": "command", "command": hook_command(), "timeout": HOOK_TIMEOUT_SECONDS, "on_failure": "block"}]})
    hooks["PreToolUse"] = kept
    config["hooks"] = hooks
    return config


def plan_goose_hook(home: Path | None = None) -> list[tuple[Path, dict[str, Any]]]:
    """Return every target and merged config without writing, so invalid existing JSON fails before any write."""
    root = goose_plugin_dir(home)
    hooks_path = root / "hooks" / "hooks.json"
    return [
        (root / "plugin.json", plugin_manifest()),
        (hooks_path, merge_goose_hooks(load_hook_config(hooks_path))),
    ]


def write_goose_hook(home: Path | None = None) -> list[Path]:
    return [write_runtime_hook(target, config) for target, config in plan_goose_hook(home)]


def evaluate_pre_tool(raw_event: str, config_file: Path | None) -> str | None:
    """Return None to allow the Goose tool call, or a block reason."""
    try:
        event = json.loads(raw_event)
        tool_name = event.get("tool_name") if isinstance(event, dict) else None
        if not isinstance(tool_name, str) or not tool_name.strip():
            return UNIDENTIFIED_TOOL_REASON
        command = install_command_text(tool_name, event.get("tool_input"))
    except Exception:
        return UNIDENTIFIED_TOOL_REASON
    if command is None:
        return None
    return authorize_install(command, GOOSE_PROGRAM, config_file)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ironclaw_sdk.goose_hooks",
        description="IronClaw install gate for Goose PreToolUse hooks.",
    )
    parser.add_argument("--install", action="store_true", help="Write the Goose plugin files instead of evaluating a tool call.")
    parser.add_argument("--config-file", type=Path, default=None, help="Defaults to ~/.ironclaw/config.json.")
    args = parser.parse_args(argv)
    if args.install:
        try:
            written = write_goose_hook()
        except ValueError as error:
            sys.stderr.write(f"{error}\n")
            return 1
        for path in written:
            sys.stdout.write(f"{path}\n")
        return 0
    try:
        raw_event = sys.stdin.read()
    except (OSError, UnicodeDecodeError):
        raw_event = ""
    reason = evaluate_pre_tool(raw_event, args.config_file)
    if reason is None:
        return 0
    sys.stderr.write(reason + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
