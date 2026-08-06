# Claude Code ↔ IronClaw Guard Client
#
# This document describes how to wire Claude Code (or any Claude-based
# proxy/tooling) through IronClaw-Security as a front‑line security guard.

## 1. Prerequisites

Before wiring Claude Code to IronClaw, you need:

- A running IronClaw-Security deployment, reachable from your Claude Code proxy.
- An IronClaw API key with permission to call guard and policy routes.
- The `claude_bootstrap` API enabled (mounted under `/claude/bootstrap`).
- The Python client available in your proxy/tooling environment:
  - `app/clients/claude_guard_client.py`
  - `httpx` installed (`pip install httpx`)

## 2. Generate one‑command config from IronClaw

Use the Claude bootstrap endpoint to generate Claude‑specific guard config
and a ready‑to‑paste shell snippet.

### Request

```bash
curl -X POST "$IRONCLAW_BASE_URL/claude/bootstrap" \
  -H "X-API-Key: $IRONCLAW_OPERATOR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "platform": "claude-code",
    "display_name": "My Claude Workspace",
    "base_guard_url": "'"$IRONCLAW_BASE_URL"'",
    "guard_mode": "enforce",
    "default_timeout_ms": 8000,
    "max_payload_kb": 256
  }'
```

### Response (shape)

```json
{
  "generated_at": "2026-04-21T18:50:00.000000+00:00",
  "platform": "claude-code",
  "workspace_name": "My Claude Workspace",
  "client_config": {
    "guard_base_url": "https://ironclaw.company.com",
    "api_key": "******",
    "guard_mode": "enforce",
    "default_timeout_ms": 8000,
    "max_payload_kb": 256,
    "use_bundle_guard": true,
    "use_guard_execute": true
  },
  "one_command_snippet": "export IRONCLAW_GUARD_BASE_URL=...\n...",
  "notes": [
    "Configure Claude Code's proxy to send all external tool calls through /guard/execute.",
    "Send combined prompt/context/model output bundles to /policy/guard-bundle before showing them to the user.",
    "Always include X-API-Key using the value from IRONCLAW_GUARD_API_KEY.",
    "Use IRONCLAW_GUARD_MODE to decide whether to enforce blocks or only warn in the UI."
  ]
}
```

### Apply the one‑command snippet

Copy `one_command_snippet` and run it in the environment where your
Claude Code proxy/tooling process runs, for example:

```bash
# Example (do not paste literally; use the snippet from the API)
export IRONCLAW_GUARD_BASE_URL="https://ironclaw.company.com"
export IRONCLAW_GUARD_API_KEY="your-ironclaw-api-key"
export IRONCLAW_GUARD_MODE="enforce"
export IRONCLAW_GUARD_TIMEOUT_MS="8000"
export IRONCLAW_GUARD_MAX_PAYLOAD_KB="256"
export IRONCLAW_WORKSPACE_NAME="My Claude Workspace"
```

## 3. Initialize the guard client in your proxy

In the process that proxies Claude Code’s network/tool calls, create
a `ClaudeGuardClient` from environment variables:

```python
# app/proxy/guard_integration.py

from app.clients.claude_guard_client import ClaudeGuardClient, ClaudeGuardClientConfig

_guard_client: ClaudeGuardClient | None = None


def get_guard_client() -> ClaudeGuardClient:
    global _guard_client
    if _guard_client is None:
        config = ClaudeGuardClientConfig.from_env()
        _guard_client = ClaudeGuardClient(config=config)
    return _guard_client
```

Ensure this module is imported once at proxy startup so the client is ready.

## 4. Guarding tool / action executions

Wrap external actions (HTTP calls, shell tools, DB queries, etc.) that
Claude Code wants to perform with `guard_execute`.

### Example: guarding a tool call

```python
from typing import Any, Dict

from app.proxy.guard_integration import get_guard_client


def execute_tool_with_guard(tool_name: str, args: Dict[str, Any]) -> Any:
    guard = get_guard_client()

    # Build an ExecuteRequest-style payload compatible with /guard/execute.
    guard_payload = {
        "action_type": "toolcall",
        "target": tool_name,
        "content": args,
        "client_id": args.get("client_id"),
        "session_id": args.get("session_id"),
    }

    verdict = guard.guard_execute(guard_payload)

    # Expected high-level shape:
    # {
    #   "policy_verdict": "allow" | "review" | "block",
    #   "should_execute": true/false,
    #   "halted_by_boundary": true/false,
    #   "reason": "..."
    # }

    if not verdict.get("should_execute", False):
        # Blocked or queued for review – DO NOT execute the tool.
        # Surface a safe message back into Claude Code instead.
        raise RuntimeError(f"Guard blocked tool '{tool_name}': {verdict.get('reason', 'no reason provided')}")

    # Safe to execute – run the actual tool now.
    return perform_tool_call(tool_name, args)
```

`perform_tool_call` is your existing implementation that actually
invokes the tool. IronClaw never runs the tool itself; it only decides.

## 5. Guarding prompt/output bundles before user display

Before showing any combined AI output to the user, send a bundle to
`/policy/guard-bundle` via `guard_bundle`.

### Example: guarding a response bundle

```python
from typing import Any, Dict

from app.proxy.guard_integration import get_guard_client


def guard_and_render_response(
    user_prompt: str,
    retrieved_docs: list[str] | None,
    tool_outputs: list[Dict[str, Any]] | None,
    model_output: str,
) -> str:
    guard = get_guard_client()

    bundle = {
        "userprompt": user_prompt,
        "retrieveddoc": "\n\n".join(retrieved_docs or []),
        "tooloutput": tool_outputs or [],
        "modeloutput": model_output,
    }

    verdict = guard.guard_bundle(bundle)

    # Expected high-level shape:
    # {
    #   "bundle_verdict": "allow" | "warn" | "quarantine" | "block",
    #   "reason": "..."
    # }

    bundle_verdict = verdict.get("bundle_verdict", "allow")
    reason = verdict.get("reason", "")

    if bundle_verdict in {"block", "quarantine"}:
        # Replace unsafe content with a safe explanation.
        return f"⚠️ Response blocked by IronClaw security guard.\n\nReason: {reason or 'high-risk content detected.'}"

    if bundle_verdict == "warn":
        # Optionally annotate the response with a warning banner.
        return "⚠️ IronClaw detected potentially risky content. Review carefully.\n\n" + model_output

    # bundle_verdict == "allow"
    return model_output
```

Claude Code never sees the raw model output until IronClaw approves or
annotates it, which helps block prompt injections and unsafe content
before it reaches the user.

## 6. Mapping guard modes in Claude Code

Respect `IRONCLAW_GUARD_MODE` in your proxy logic:

- `enforce`:
  - Block / quarantine results as shown above.
  - Throw errors or surface warnings in the editor when an action is blocked.
- `assist`:
  - Always return content but annotate warnings instead of hard blocking.
  - Useful during rollout or for less trusted projects.
- `dryrun`:
  - Call the guard endpoints and log results.
  - Never block; use this mode for evaluation in non‑prod environments.

### Example mode-sensitive handling

```python
import os

from app.proxy.guard_integration import get_guard_client

GUARD_MODE = os.environ.get("IRONCLAW_GUARD_MODE", "enforce").lower()


def guard_and_maybe_block(model_output: str, bundle: dict) -> str:
    guard = get_guard_client()
    verdict = guard.guard_bundle(bundle)
    bundle_verdict = verdict.get("bundle_verdict", "allow")
    reason = verdict.get("reason", "")

    if GUARD_MODE == "dryrun":
        # Log only; never block.
        log_guard_verdict(bundle_verdict, reason)
        return model_output

    if GUARD_MODE == "assist":
        if bundle_verdict in {"block", "quarantine", "warn"}:
            log_guard_verdict(bundle_verdict, reason)
            return f"⚠️ IronClaw flagged this response as potentially unsafe.\n\nReason: {reason or 'review recommended.'}\n\n" + model_output
        return model_output

    # GUARD_MODE == "enforce"
    if bundle_verdict in {"block", "quarantine"}:
        log_guard_verdict(bundle_verdict, reason)
        return f"⚠️ Response blocked by IronClaw security guard.\n\nReason: {reason or 'high-risk content detected.'}"

    if bundle_verdict == "warn":
        log_guard_verdict(bundle_verdict, reason)
        return "⚠️ IronClaw warns this response may be unsafe.\n\n" + model_output

    return model_output
```

## 7. Shutdown handling

If your proxy process manages its own lifecycle, close the guard client
gracefully on shutdown:

```python
from app.proxy.guard_integration import _guard_client  # or expose a getter/closer


def on_shutdown() -> None:
    if _guard_client is not None:
        _guard_client.close()
```

## 8. Summary

- Use `/claude/bootstrap` once to generate env + config for a Claude Code workspace.
- Export the env vars (`IRONCLAW_GUARD_*`) into your Claude proxy environment.
- Initialize `ClaudeGuardClientConfig.from_env()` and `ClaudeGuardClient`.
- Guard external actions via `guard_execute`.
- Guard combined prompt/output bundles via `guard_bundle` before displaying
  anything to the user.
- Respect `IRONCLAW_GUARD_MODE` to control enforce/assist/dryrun behavior.

This keeps Claude Code flexible while ensuring IronClaw remains the
front‑line security boundary for all agent actions and outputs.