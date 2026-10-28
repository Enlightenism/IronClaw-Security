# IronClaw-Security — Documentation

IronClaw-Security is a FastAPI-based AI security and control plane. It sits in
front of agents, tools, and code-execution environments as an enforcement layer
— inspecting every prompt, tool call, and execution plan before it reaches
production.

The public installation model is a shared cross-runtime Security Guardian
package that you install once and then enable across supported runtimes, instead
of modeling it as a single-agent or one-off package.

---

## Documentation Index

| File                                                           | Description                                                                                    |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| [api_reference.md](./api_reference.md)                         | Full API reference — every route, request model, response model, binary verdicts, and error shape |
| [security_model.md](./security_model.md)                       | Security architecture — trust layers, verdict pipeline, policy enforcement, sandbox, telemetry |
| [quickstart.md](./quickstart.md)                               | Get from zero to first scan in under 5 minutes                                                 |
| [integration_guides/sdk.md](./integration_guides/sdk.md)       | IronClaw Python SDK (`ironclaw_sdk`) — full client usage reference                             |
| [integration_guides/claude.md](./claude_guard_client.md)       | Claude / Anthropic integration guide                                                           |
| [integration_guides/openai.md](./integration_guides/openai.md) | OpenAI integration guide                                                                       |
| [integration_guides/guard.md](./integration_guides/guard.md)   | Local Prompt Guard classifier and configuration guide                                          |
| [integration_guides/mcp.md](./integration_guides/mcp.md)       | MCP-style toolchain integration guide                                                          |

---

## Shared runtime package model

The shared Security Guardian package is the canonical cross-runtime bundle for
IronClaw installation. Install the product package once, then enable the runtime
families you want protected:

```bash
python -m pip install ironclaw-security
ironclaw install \
  --provider-target security_guardian \
  --provider-target openclaw \
  --provider-target claude_code \
  --provider-target cursor \
  --provider-target goose \
  --provider-target gemini_cli \
  --provider-target copilot
```

This keeps the runtime package model consistent across the installer,
quickstart, and integration docs.

## What IronClaw Does

Every LLM or agent action passes through IronClaw before execution. IronClaw
returns a **verdict**:

| Verdict | Meaning |
| --- | --- |
| `allow` | All applicable checks completed without suspicious signals or errors |
| `block` | A suspicious signal, matched rule, malicious classifier result, or scan error was detected |

Quarantine is an operational isolation and review state, not a final verdict.
Historical records may retain legacy verdict labels.

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
- **Review workflow** — blocked items may be isolated for human review; the
  review status is separate from the final verdict
- **Telemetry** — real-time event stream for observability pipelines
- **Sandboxed execution** — runtime boundaries enforced around code and tool
  calls

---

## Quick Links

- [Quickstart →](./quickstart.md)
- [API Reference →](./api_reference.md)
- [Security Model →](./security_model.md)
- [GitHub Repository →](https://github.com/Enlightenism/IronClaw-Security)
