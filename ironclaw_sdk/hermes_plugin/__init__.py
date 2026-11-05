"""Hermes Agent plugin for IronClaw install gating and return-path enforcement.

Hermes treats hook exceptions as fail-open, so every callback catches its own
errors and returns the blocking result itself.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from ironclaw_sdk.runtime_hooks import (
    GENERIC_BLOCK_REASON,
    RETURN_REQUEST_TIMEOUT_SECONDS,
    action_fields,
    authorize_install,
    install_command_text,
    post_gate,
)

PROGRAM = "hermes"
BLOCKED_REPLACEMENT_TEXT = "[BLOCKED BY IRONCLAW RETURN GATE] The original tool output was withheld because it failed the return-gate scan."

logger = logging.getLogger(__name__)


def _return_body(tool_name: str, args: Any, result: Any) -> dict[str, Any]:
    content = result if isinstance(result, str) else json.dumps(result, default=str, ensure_ascii=False)
    payload: dict[str, Any] = {"tool_name": tool_name, **action_fields(args, result)}
    return {"platform": PROGRAM, "content": content, "payload": payload, "client_id": PROGRAM}


def pre_tool_call(tool_name: str = "", args: Any = None, **kwargs: Any) -> dict[str, str] | None:
    try:
        command = install_command_text(tool_name, args)
        if command is None:
            return None
        reason = authorize_install(command, PROGRAM, None)
    except Exception:
        logger.warning("IronClaw install gate failed; the tool call was blocked.")
        reason = GENERIC_BLOCK_REASON
    if reason is None:
        return None
    return {"action": "block", "message": reason}


def transform_tool_result(tool_name: str = "", result: Any = None, args: Any = None, **kwargs: Any) -> str | None:
    try:
        body = _return_body(tool_name, args, result)
        decision = post_gate("/return-gate/transform", PROGRAM, body, None, RETURN_REQUEST_TIMEOUT_SECONDS)
    except Exception:
        logger.warning("IronClaw return gate failed; the tool result was withheld.")
        return BLOCKED_REPLACEMENT_TEXT
    if not isinstance(decision, dict):
        return BLOCKED_REPLACEMENT_TEXT
    verdict = decision.get("verdict")
    if verdict == "allow":
        return None
    replacement = decision.get("replacement")
    if verdict == "block" and isinstance(replacement, str) and replacement:
        return replacement
    return BLOCKED_REPLACEMENT_TEXT


def register(ctx: Any) -> None:
    ctx.register_hook("pre_tool_call", pre_tool_call)
    ctx.register_hook("transform_tool_result", transform_tool_result)
