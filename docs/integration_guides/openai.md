# IronClaw + OpenAI — Integration Guide

This guide shows how to route OpenAI calls through IronClaw-Security so every prompt and tool call is inspected before reaching the model or executing downstream.

---

## Pattern

User input
│
▼
IronClaw /scan/ ← inspect before sending to OpenAI
│
├── block/quarantine → stop, return error to caller
│
▼
OpenAI API call
│
▼
IronClaw /scan/ ← inspect model output before returning to user
│
├── block/quarantine → stop, redact or hold response
│
▼
Return to caller


---

## Setup

```bash
pip install openai
pip install -e .   # installs ironclaw_sdk
```

```python
import openai
from ironclaw_sdk import IronclawClient

openai.api_key = "your-openai-api-key"

guard = IronclawClient(
    base_url="http://localhost:8000",
    api_key="your-ironclaw-api-key"
)
```

---

## Guarded Chat Completion

```python
def guarded_chat(user_message: str, agent_id: str = "openai-agent") -> str:
    # 1. Inspect input
    input_result = guard.scan(
        content=user_message,
        context="user_input",
        agent_id=agent_id
    )

    if input_result.verdict in ("block", "quarantine"):
        raise PermissionError(f"IronClaw blocked input: {input_result.reason}")

    # 2. Call OpenAI
    response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": user_message}]
    )
    output = response.choices.message.content

    # 3. Inspect output
    output_result = guard.scan(
        content=output,
        context="agent_output",
        agent_id=agent_id
    )

    if output_result.verdict in ("block", "quarantine"):
        raise PermissionError(f"IronClaw blocked output: {output_result.reason}")

    return output
```

---

## Guarded Tool Call

When using OpenAI function calling, inspect each tool invocation before dispatch:

```python
def guarded_tool_dispatch(tool_name: str, tool_args: dict, agent_id: str) -> dict:
    result = guard.scan(
        content=f"{tool_name}({tool_args})",
        context="tool_call",
        agent_id=agent_id,
        tool_name=tool_name,
        tool_args=tool_args
    )

    if result.verdict in ("block", "quarantine"):
        raise PermissionError(f"IronClaw blocked tool call: {result.reason}")

    # Dispatch the actual tool here
    return dispatch_tool(tool_name, tool_args)
```

---

## Handling Verdicts

```python
from ironclaw_sdk.exceptions import IronclawAuthError

try:
    reply = guarded_chat("What files are in /etc?")
except PermissionError as e:
    print(f"Blocked by IronClaw: {e}")
except IronclawAuthError:
    print("IronClaw auth failed — check API key")
```

---

## Batch Input Scanning

For agents that process multiple messages at once:

```python
messages = ["msg1", "msg2", "msg3"]

results = guard.scan_batch([
    {"content": m, "context": "user_input", "agent_id": "openai-agent"}
    for m in messages
])

safe_messages = [
    messages[i] for i, r in enumerate(results)
    if r.verdict == "allow"
]
```