# IronClaw + MCP Toolchain — Integration Guide

This guide covers integrating IronClaw-Security as the enforcement layer for MCP-style (Model Context Protocol) toolchains — systems where an LLM dispatches tool calls dynamically via a tool registry.

---

## Pattern

In an MCP-style system, the agent selects and calls tools at runtime. IronClaw gates every tool invocation:

Agent selects tool
│
▼
IronClaw /scan/ ← inspect tool name + args before dispatch
│
├── block/quarantine → tool call rejected
│
▼
Tool executes
│
▼
IronClaw /scan/ ← inspect tool output before returning to agent
│
├── block/quarantine → output withheld
│
▼
Result returned to agent


---

## Setup

```bash
pip install -e .
```

```python
from ironclaw_sdk import IronclawClient

guard = IronclawClient(base_url="http://localhost:8000", api_key="your-ironclaw-api-key")
```

---

## Tool Call Interception

Wrap your MCP tool dispatcher with IronClaw inspection:

```python
def guarded_tool_call(tool_name: str, tool_args: dict, agent_id: str) -> dict:
    # Inspect before dispatch
    pre_result = guard.scan(content=f"{tool_name}({tool_args})", context="tool_call", agent_id=agent_id, tool_name=tool_name, tool_args=tool_args)

    if pre_result.verdict == "block":
        raise PermissionError(f"Tool call blocked: {pre_result.reason}")

    if pre_result.verdict == "quarantine":
        # Submit to review queue — do not execute yet
        raise PermissionError(f"Tool call quarantined — pending review: {pre_result.scan_id}")

    # Execute tool
    tool_output = mcp_dispatch(tool_name, tool_args)

    # Inspect output
    post_result = guard.scan(content=str(tool_output), context="agent_output", agent_id=agent_id, tool_name=tool_name)

    if post_result.verdict in ("block", "quarantine"):
        raise PermissionError(f"Tool output blocked: {post_result.reason}")

    return tool_output
```

---

## Registering an Allowed Tool List

Use a policy rule to define which tools are permitted for a given agent:

```python
# Example: retrieve the guard bundle and check tool allowlist locally
bundle = guard.get_guard_bundle()

ALLOWED_TOOLS = {rule["tool_name"] for rule in bundle.rules if rule.get("type") == "tool_allowlist"}


def is_tool_allowed(tool_name: str) -> bool:
    return tool_name in ALLOWED_TOOLS
```

---

## Batch Tool Pre-Screening

When an agent plans multiple tool calls in one step, batch-scan them before any are dispatched:

```python
planned_calls = [
    {"tool_name": "read_file", "args": {"path": "/data/report.csv"}},
    {"tool_name": "send_email", "args": {"to": "user@example.com", "body": "..."}},
]

scan_items = [{"content": f"{c['tool_name']}({c['args']})", "context": "tool_call", "tool_name": c["tool_name"], "tool_args": c["args"], "agent_id": "mcp-agent"} for c in planned_calls]

results = guard.scan_batch(scan_items)

for i, result in enumerate(results):
    if result.verdict in ("block", "quarantine"):
        raise PermissionError(f"Planned tool call [{planned_calls[i]['tool_name']}] blocked: {result.reason}")

# All cleared — dispatch in order
for call in planned_calls:
    mcp_dispatch(call["tool_name"], call["args"])
```

---

## Quarantine Handling with Review Queue

When a tool call is quarantined, surface the review ID to your operator interface:

```python
try:
    result = guarded_tool_call("delete_record", {"id": "user-123"}, "mcp-agent")
except PermissionError as e:
    print(f"Quarantined: {e}")
    # The scan_id is in the error message — operators can approve or reject via /review/
```

Approve via SDK:
```python
guard.approve_review("review-uuid")
```

Reject via SDK:
```python
guard.reject_review("review-uuid")
```