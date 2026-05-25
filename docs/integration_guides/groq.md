# IronClaw + Groq — Integration Guide

This guide shows how to route Groq inference calls through IronClaw-Security for input inspection, output scanning, and tool call guarding.

---

## Pattern

User input
│
▼
IronClaw /scan/ ← inspect before sending to Groq
│
├── block/quarantine → stop
│
▼
Groq API call
│
▼
IronClaw /scan/ ← inspect model output before returning
│
├── block/quarantine → stop
│
▼
Return to caller


---

## Setup

```bash
pip install groq
pip install -e .
```

```python
from groq import Groq
from ironclaw_sdk import IronclawClient

groq_client = Groq(api_key="your-groq-api-key")

guard = IronclawClient(
    base_url="http://localhost:8000",
    api_key="your-ironclaw-api-key"
)
```

---

## Guarded Groq Completion

```python
def guarded_groq(user_message: str, agent_id: str = "groq-agent") -> str:
    # 1. Inspect input
    input_result = guard.scan(
        content=user_message,
        context="user_input",
        agent_id=agent_id
    )

    if input_result.verdict in ("block", "quarantine"):
        raise PermissionError(f"IronClaw blocked input: {input_result.reason}")

    # 2. Call Groq
    response = groq_client.chat.completions.create(
        model="llama-3.3-70b-versatile",
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

## Guarded Tool Dispatch

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

    return dispatch_tool(tool_name, tool_args)
```

---

## Handling Verdicts

```python
try:
    reply = guarded_groq("List all users in the database")
except PermissionError as e:
    print(f"Blocked: {e}")
```