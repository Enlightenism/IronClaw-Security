# IronClaw-Security — Documentation

IronClaw-Security is a FastAPI-based AI security and control plane. It sits in
front of agents, tools, and code-execution environments as an enforcement layer
— inspecting every prompt, tool call, and execution plan before it reaches
production.

---

## Documentation Index

| File                                                           | Description                                                                                    |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [api_reference.md](./api_reference.md)                         | Full API reference — every route, request model, response model, verdict enum, and error shape |
| [security_model.md](./security_model.md)                       | Security architecture — trust layers, verdict pipeline, policy enforcement, sandbox, telemetry |
| [quickstart.md](./quickstart.md)                               | Get from zero to first scan in under 5 minutes                                                 |
| [integration_guides/sdk.md](./integration_guides/sdk.md)       | IronClaw Python SDK (`ironclaw_sdk`) — full client usage reference                             |
| [integration_guides/claude.md](./claude_guard_client.md)       | Claude / Anthropic integration guide                                                           |
| [integration_guides/openai.md](./integration_guides/openai.md) | OpenAI integration guide                                                                       |
| [integration_guides/groq.md](./integration_guides/groq.md)     | Groq integration guide                                                                         |
| [integration_guides/mcp.md](./integration_guides/mcp.md)       | MCP-style toolchain integration guide                                                          |

---

## What IronClaw Does

Every LLM or agent action passes through IronClaw before execution. IronClaw
returns a **verdict**:

| Verdict      | Meaning                                   |
| ------------ | ----------------------------------------- |
| `allow`      | Safe to proceed                           |
| `warn`       | Proceed with caution — logged and flagged |
| `quarantine` | Held for human review before execution    |
| `block`      | Rejected — action stopped at the gate     |

IronClaw covers:

- **Prompt injection detection** — catches adversarial instructions embedded in
  inputs so every agent call is protected
- **Tool call guarding** — validates tool names, arguments, and execution
  context before dispatch
- **Data leakage prevention** — detects PII, credentials, and sensitive patterns
  in outputs
- **Policy enforcement** — applies configurable rule sets per agent, user, or
  context
- **Audit logging** — every scan, verdict, and policy decision is persisted
- **Review workflow** — quarantined items enter a human review queue
- **Telemetry** — real-time event stream for observability pipelines
- **Sandboxed execution** — runtime boundaries enforced around code and tool
  calls

---

## Quick Links

- [Quickstart →](./quickstart.md)
- [API Reference →](./api_reference.md)
- [Security Model →](./security_model.md)
- [GitHub Repository →](https://github.com/Enlightenism/IronClaw-Security)
