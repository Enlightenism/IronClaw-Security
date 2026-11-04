"""Fail-closed IronClaw enforcement gate for non-OpenClaw agent runtime hooks.

Reads one tool-call event from stdin, asks IronClaw ``/action/execute`` for a
decision, and reports it in the format the calling runtime expects. Any failure
blocks the tool call.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from typing import Any
import urllib.error
from urllib.parse import urlsplit
import urllib.request
import uuid

REQUEST_TIMEOUT_SECONDS = 12
MAX_RESPONSE_BYTES = 64 * 1024
MAX_REASON_CHARS = 240
REDACTED = "[REDACTED]"
DEFAULT_CONFIG_PARTS = (".ironclaw", "config.json")
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
SUPPORTED_PROGRAMS = frozenset({"claude_code", "gemini_cli", "cursor", "copilot"})
JSON_DECISION_PROGRAMS = frozenset({"copilot"})

UNIDENTIFIED_TOOL_REASON = "IronClaw could not identify this tool call; the action was blocked."
CONFIG_UNAVAILABLE_REASON = "IronClaw configuration is missing or unsafe for this runtime; the action was blocked."
UNSAFE_BASE_URL_REASON = "IronClaw base URL is not safe for install-key authentication; the action was blocked."
GENERIC_BLOCK_REASON = "IronClaw could not verify this action; the action was blocked."

_SENSITIVE_FIELD_PATTERN = re.compile(
    r"password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key",
    re.IGNORECASE,
)
_REDACTION_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE), "******"),
    (re.compile(r"\b(?:ic_install|ic_claim)_[A-Za-z0-9_-]+\b", re.IGNORECASE), REDACTED),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b", re.IGNORECASE), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", re.IGNORECASE), REDACTED),
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b", re.IGNORECASE), REDACTED),
    (re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b", re.IGNORECASE), REDACTED),
    (
        re.compile(
            r"(api[_-]?key|access[_-]?token|refresh[_-]?token|password|passwd|secret"
            r"|authorization|cookie|credential|private[_-]?key)\s*[:=]\s*[\"']?([^\"'\s&,;]+)",
            re.IGNORECASE,
        ),
        r"\1=[REDACTED]",
    ),
)
_ACTION_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("command", re.compile(r"(^|_)(exec|shell|command|bash|terminal)(_|$)")),
    ("filewrite", re.compile(r"(^|_)(write|edit|patch|delete|move|copy|mkdir|touch)(_|$)")),
    ("browseropen", re.compile(r"(^|_)(browser|navigate|browse|open_url)(_|$)")),
    ("httpfetch", re.compile(r"(^|_)(http|fetch|web_search)(_|$)")),
    ("fileread", re.compile(r"(^|_)(read|list|search|glob)(_|$)")),
)


class HookError(Exception):
    """Raised for expected failures whose message is safe to show the user."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def redact_text(value: str) -> str:
    for pattern, replacement in _REDACTION_RULES:
        value = pattern.sub(replacement, value)
    return value


def _redact_value(key: str | None, value: Any) -> Any:
    if key is not None and _SENSITIVE_FIELD_PATTERN.search(key):
        return REDACTED
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {str(child_key): _redact_value(str(child_key), child) for child_key, child in value.items()}
    if isinstance(value, list):
        return [_redact_value(None, item) for item in value]
    return value


def serialize_tool_params(params: Any) -> str:
    redacted = _redact_value(None, params if params is not None else {})
    return json.dumps(redacted, separators=(",", ":"), ensure_ascii=False)


def action_type_for_tool(tool_name: str) -> str:
    name = re.sub(r"[^a-z0-9]+", "_", tool_name.lower())
    for action, pattern in _ACTION_RULES:
        if pattern.search(name):
            return action
    return "toolcall"


def action_endpoint(base_url: str) -> str:
    parsed = urlsplit(base_url)
    hostname = (parsed.hostname or "").lower()
    is_loopback = hostname in LOOPBACK_HOSTS
    if not hostname or (parsed.scheme != "https" and not (parsed.scheme == "http" and is_loopback)) or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HookError(UNSAFE_BASE_URL_REASON)
    return f"{base_url.rstrip('/')}/action/execute"


def _first_string(event: dict[str, Any], *keys: str) -> str | None:
    for key in keys:
        value = event.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def build_payload(raw_event: str, program: str) -> dict[str, Any]:
    event = json.loads(raw_event)
    if not isinstance(event, dict):
        raise HookError(UNIDENTIFIED_TOOL_REASON)
    tool_name = _first_string(event, "tool_name", "toolName")
    if tool_name is None:
        raise HookError(UNIDENTIFIED_TOOL_REASON)
    params = event["tool_input"] if "tool_input" in event else event.get("toolArgs")
    session_id = _first_string(event, "session_id", "sessionId") or str(uuid.uuid4())
    return {
        "actiontype": action_type_for_tool(tool_name),
        "target": tool_name,
        "content": serialize_tool_params(params),
        "clientid": program,
        "sessionid": session_id,
        "eventid": str(uuid.uuid4()),
        "metadata": {"runtime": program},
    }


def load_runtime_config(config_file: Path, program: str) -> tuple[str, str]:
    if config_file.is_symlink() or not config_file.is_file():
        raise HookError(CONFIG_UNAVAILABLE_REASON)
    parsed = json.loads(config_file.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise HookError(CONFIG_UNAVAILABLE_REASON)
    install_keys = parsed.get("install_keys")
    install_key = install_keys.get(program) if isinstance(install_keys, dict) else None
    if not isinstance(install_key, str) or not install_key.strip():
        raise HookError(CONFIG_UNAVAILABLE_REASON)
    base_url = parsed.get("base_url")
    if not isinstance(base_url, str) or not base_url.strip():
        raise HookError(CONFIG_UNAVAILABLE_REASON)
    return install_key.strip(), action_endpoint(base_url.strip())


def request_decision(endpoint: str, install_key: str, payload: dict[str, Any]) -> Any:
    request = urllib.request.Request(
        endpoint,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Install-Key": install_key,
        },
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise HookError(f"IronClaw enforcement failed with HTTP {error.code}; the action was blocked.") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise HookError(GENERIC_BLOCK_REASON)
    return json.loads(raw.decode("utf-8"))


def is_allowed(decision: Any) -> bool:
    if not isinstance(decision, dict):
        return False
    usage = decision.get("usage")
    return decision.get("status") == "allowed" and decision.get("executionallowed") is True and isinstance(usage, dict) and usage.get("executed") is True and usage.get("applied") is True


def _decision_block_reason(decision: Any) -> str:
    message = decision.get("message") if isinstance(decision, dict) else None
    if isinstance(message, str) and message.strip():
        safe_message = redact_text(message.strip())[:MAX_REASON_CHARS]
        return f"{safe_message} The action was blocked."
    return "IronClaw did not authorize this action. The action was blocked."


def authorize(raw_event: str, program: str, config_file: Path | None) -> str | None:
    """Return None to allow the tool call, or a block reason to deny it."""
    try:
        path = config_file or Path.home().joinpath(*DEFAULT_CONFIG_PARTS)
        payload = build_payload(raw_event, program)
        install_key, endpoint = load_runtime_config(path, program)
        decision = request_decision(endpoint, install_key, payload)
    except HookError as error:
        return str(error)
    except Exception as error:
        print(
            f"[ironclaw-security] Authorization failed ({type(error).__name__}); the tool call was blocked.",
            file=sys.stderr,
        )
        return GENERIC_BLOCK_REASON
    if is_allowed(decision):
        return None
    return _decision_block_reason(decision)


HOOK_MARKER = "ironclaw_sdk.runtime_hooks"
_HOOK_EVENTS: dict[str, str] = {
    "claude_code": "PreToolUse",
    "gemini_cli": "BeforeTool",
    "cursor": "preToolUse",
    "copilot": "preToolUse",
}


def hook_command(program: str) -> str:
    return f"python -m {HOOK_MARKER} --program {program}"


def runtime_hook_config_path(program: str, home: Path | None = None) -> Path:
    base = home or Path.home()
    if program == "claude_code":
        return base / ".claude" / "settings.json"
    if program == "gemini_cli":
        return base / ".gemini" / "settings.json"
    if program == "cursor":
        return base / ".cursor" / "hooks.json"
    if program == "copilot":
        return base / ".copilot" / "hooks" / "ironclaw-security.json"
    raise ValueError(f"Unsupported runtime hook program: {program}")


def _hook_entry(program: str) -> dict[str, Any]:
    command = hook_command(program)
    if program == "claude_code":
        return {"matcher": "", "hooks": [{"type": "command", "command": command}]}
    if program == "gemini_cli":
        return {"matcher": ".*", "hooks": [{"type": "command", "command": command}]}
    if program == "cursor":
        return {"command": command}
    return {"type": "command", "command": command, "timeoutSec": 30}


def merge_hook_config(program: str, existing: dict[str, Any]) -> dict[str, Any]:
    config = dict(existing)
    if program in ("cursor", "copilot"):
        config.setdefault("version", 1)
    hooks = config.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("Existing hooks configuration is not a JSON object.")
    event = _HOOK_EVENTS[program]
    entries = hooks.get(event, [])
    if not isinstance(entries, list):
        raise ValueError(f"Existing {event} hooks configuration is not a JSON array.")
    kept = [entry for entry in entries if HOOK_MARKER not in json.dumps(entry)]
    kept.append(_hook_entry(program))
    hooks[event] = kept
    config["hooks"] = hooks
    return config


def load_hook_config(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path} must be a regular, non-symlink file.")
    parsed = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(parsed, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return parsed


def plan_runtime_hook(program: str, home: Path | None = None) -> tuple[Path, dict[str, Any]] | None:
    """Return the hook target and merged config without writing anything.

    Invalid existing JSON raises here, so callers can fail before consuming a claim.
    """
    if program not in _HOOK_EVENTS:
        return None
    target = runtime_hook_config_path(program, home)
    return target, merge_hook_config(program, load_hook_config(target))


def write_runtime_hook(target: Path, config: dict[str, Any]) -> Path:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f"{target.name}.tmp")
    temporary.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, target)
    return target


def _emit(program: str, reason: str | None) -> int:
    if program in JSON_DECISION_PROGRAMS:
        output: dict[str, str] = {"permissionDecision": "allow" if reason is None else "deny"}
        if reason is not None:
            output["permissionDecisionReason"] = reason
        sys.stdout.write(json.dumps(output) + "\n")
        return 0
    if reason is None:
        return 0
    sys.stderr.write(reason + "\n")
    return 2


def _read_stdin() -> str:
    try:
        return sys.stdin.read()
    except (OSError, UnicodeDecodeError):
        return ""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m ironclaw_sdk.runtime_hooks",
        description="IronClaw fail-closed tool-call gate for agent runtime hooks.",
    )
    parser.add_argument("--program", required=True, choices=sorted(SUPPORTED_PROGRAMS))
    parser.add_argument(
        "--config-file",
        type=Path,
        default=None,
        help="Defaults to ~/.ironclaw/config.json.",
    )
    args = parser.parse_args(argv)
    reason = authorize(_read_stdin(), args.program, args.config_file)
    return _emit(args.program, reason)


if __name__ == "__main__":
    raise SystemExit(main())
