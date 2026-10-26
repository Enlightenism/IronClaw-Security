<img width="2000" height="2000" alt="Golden Knight 4k 2gb" src="https://github.com/user-attachments/assets/436aa4e8-1276-48e7-8763-fb67205c42e9" />
# IronClaw-Security

> **The enforcement layer that makes powerful AI usable, observable, and safe at
> scale.**

IronClaw-Security is a local-first, FastAPI-based AI security and control plane
built to stop the attacks that AI platforms were never designed to defend
against — prompt injection, unsafe tool execution, data exfiltration, malicious
agent returns, and trust collapse — before they reach your workflow, your files,
or your machine.

While every major AI platform ships powerful capabilities with almost zero
runtime enforcement, IronClaw sits in front of every agent action, every tool
call, every inbound return, and every code execution path as a dedicated
hardened guard rail. Every LLM output passes through IronClaw. Every verdict is
auditable. Every threat is logged, isolated, and controlled.

**V1 is live and shipping.** V2 is the full-spectrum expansion — protecting
every user, every device, from every AI-native attack vector possible.

---

## Why IronClaw-Security exists <img width="128" height="128" alt="logo128pxl shield" src="https://github.com/user-attachments/assets/ce18fd1c-81ed-4313-a47f-1f8252683deb" />


AI agents are now executing real actions: writing files, calling APIs, running
shell commands, fetching remote content, and returning results directly into
user workflows. The attack surface is enormous and almost entirely undefended at
the infrastructure level.

The threats are real and active:

- **Direct prompt injection** — attacker-supplied instructions are typed
  directly into a chat flow and trick the model into ignoring policy, bypassing
  safety, or disclosing secrets.
- **Indirect prompt injection** — malicious instructions are embedded in web
  pages, docs, tickets, emails, tool results, or repository content that the
  agent reads as normal context.
- **Hidden instructions** — malicious text is hidden in white-on-white content,
  HTML comments, tiny fonts, base64, or obfuscated markup that still reaches the
  model as trusted context.
- **Jailbreak attacks** — specially crafted prompts coerce the model into
  ignoring its safety rules or developer constraints.
- **Policy violations** — an injected instruction causes the agent to bypass
  permitted workflows, access restricted data, or call disallowed tools.
- **Tool poisoning** — a compromised tool or data source feeds false results to
  the agent, causing unsafe actions and bad operational decisions.
- **Data exfiltration** — sensitive data is encoded into responses, logs,
  requests, or tool parameters and sent to attacker-controlled destinations.
- **Sensitive information disclosure** — the agent reveals credentials, PII,
  internal docs, config values, or tokens in normal output paths.
- **Training data poisoning** — malicious data injected into training or tuning
  workflows creates persistent backdoors or biased behavior.
- **Model backdoors** — hidden triggers or poisoned model state cause the system
  to behave maliciously only under attacker-specified conditions.
- **Evasion attacks** — inputs are reformulated to bypass heuristics or filters
  while still causing the agent to misbehave.
- **Abuse attacks** — the agent is used for spam, scam generation, harassment,
  or coercive workflows that the operator did not intend.
- **Privacy attacks** — model queries are used to infer or extract private user,
  customer, or training-data information.
- **Membership inference** — attackers test model behavior to determine whether
  a record or sample was likely used in training.
- **Model inversion** — partial reconstruction of training data from model
  responses or outputs.
- **Model extraction** — heavy querying is used to replicate proprietary model
  behavior or approximate model logic.
- **Property inference** — attackers infer high-level properties of training
  data or operational context from repeated outputs.
- **Insecure output handling** — generated content is treated as trusted and is
  executed, rendered, or dispatched without validation.
- **System prompt leakage** — the agent reveals internal instructions or hidden
  operational context that can improve future attacks.
- **Excessive agency** — an agent is given too much power, so one successful
  injection creates a major security incident across the environment.
- **Insecure plugin design** — tools, plugins, or skills call arbitrary URLs,
  run unsafe code, or fail to validate inputs properly.
- **Supply chain vulnerabilities** — malicious or compromised dependencies,
  plugins, skills, or packages silently add vulnerabilities or exfiltration
  paths.
- **Model denial of service** — large, costly, or recursive prompts overwhelm
  the model or degrade its safe decision process.
- **Unbounded consumption** — prompts or loops keep consuming compute, memory,
  or network bandwidth until the system is destabilized or billed out.
- **Hallucination manipulation** — the model is led into confidently false
  conclusions that the agent then acts on as if they were true.
- **Social engineering attacks** — the agent generates convincing phishing,
  impersonation, or scam content that tricks human operators.
- **Malicious agent skills** — skills or workflow definitions appear harmless
  but contain hidden instructions, data theft logic, or dangerous command
  chains.
- **Malicious MCP tools** — untrusted MCP servers or tool adapters send poisoned
  context or unsafe actions into the agent loop.
- **Remote code execution (RCE)** — injected instructions cause the agent to run
  arbitrary code or unsafe commands on the local machine.
- **Server-side request forgery (SSRF)** — the model is tricked into reaching
  internal or sensitive services over the network.
- **Cross-site scripting (XSS)** — untrusted model output is rendered in a web
  app without sanitization.
- **Cross-site request forgery (CSRF)** — actions are triggered on behalf of a
  logged-in user without proper validation.
- **SQL injection** — untrusted input reaches a database layer through the agent
  workflow and manipulates queries.
- **Command injection** — user- or tool-derived content is concatenated into a
  shell command without sanitization.
- **Malware installation** — the agent downloads or executes a malicious payload
  after being manipulated by bad instructions.
- **Ransomware deployment** — a successful command-execution or file-access
  chain encrypts or damages critical systems.
- **Silent data exfiltration via tool parameters** — secrets are sent through
  query strings, headers, request bodies, or logging endpoints as normal tool
  traffic.
- **Markdown injection / rendering attacks** — malicious content triggers data
  leaks or code execution when rendered in a browser or mail client.
- **Memory poisoning** — unsafe instructions are seeded into the model's memory
  or session context and later retrieved as trusted guidance.
- **Skill persistence attacks** — malicious skills install themselves into the
  runtime so they continue to exist across sessions and updates.
- **Context window flooding** — large amounts of adversarial content push out
  safety instructions and increase the chance that malicious instructions are
  obeyed.

IronClaw intercepts the entire surface area before those instructions can reach
execution. It validates what enters, isolates what is risky, scores what is
malicious, applies policy, and enforces a final verdict before any action is
allowed to proceed.

---

## V1 mission <img width="128" height="128" alt="logo128pxl shield" src="https://github.com/user-attachments/assets/a889204a-0f66-440e-98a8-5256f55d3021" />


One locked, shipping mission:

- **One-command install** into Claude Code, OpenClaw, Cursor, Hermes, Copilot,
  Goose and Gemini CLI
- **Intercept every inbound agent return** before it reaches the user workflow.
- **Sandbox-isolate** every artifact for evaluation.
- **Local Prompt Guard classifier + policy engine** combine optional,
  model-based malicious-content classification with deterministic rule
  enforcement.
- **Return one final verdict** — no ambiguity, no silent pass-through:
  - `allow` — safe, released.
  - `warn` — risky, surfaced with caution.
  - `quarantine` — isolated, not released by default.
  - `block` — denied. Hard stop.

---

## What IronClaw-Security stops

### Prompt injection — the primary threat

Prompt injection is the most dangerous and most underdefended attack class in AI
systems today. An attacker embeds adversarial instructions inside content the
agent will process — a document, a webpage, a tool response, a memory entry —
and the model executes those instructions as if they were legitimate user
commands.

IronClaw's prompt injection defense operates at multiple layers simultaneously:

- **Pattern-based heuristics** scan inbound content for known injection
  signatures, role-override attempts, instruction-smuggling patterns, and
  jailbreak constructs before the content is released.
- **Local Prompt Guard classification** can add a malicious-content signal to
  the rule-based assessment when `GUARD_ENABLED=true`.
- **Risk scoring** assigns a 0–100 score to every artifact. Scores above
  configurable thresholds route to quarantine or block automatically.
- **Policy enforcement** applies organization-level rules on top of the brain
  verdict — no single point of failure.
- **Sandbox isolation** means even content that passes initial checks is never
  released directly — it is evaluated inside a controlled runtime boundary
  first.

### Full protection scope in v1

- Agent-returned text — every LLM output inspected before release.
- Agent-returned files — every file artifact intercepted, normalized, and
  evaluated.
- Tool output — every tool call return verified before it re-enters the agent
  loop.
- Command and execution payloads — shell strings, code blocks, and execution
  plans evaluated against policy before execution is permitted.
- Fetched and transformed content — remote content retrieved by agents inspected
  for embedded injection payloads before the agent processes it.
- Archive and compressed content — unpacked and scanned before release to the
  user environment.
- GitHub repository content — repository-level scans for malicious patterns
  before agent consumption.

---

## Core v1 enforcement flow <img width="128" height="128" alt="logo128pxl shield" src="https://github.com/user-attachments/assets/ee8313cc-734d-4edd-a0a9-a8027712d14e" />


Agent output │ ▼ ┌─────────────────────────────────┐ │ IronClaw Ingress
Interceptor │ ← Intercepts before user workflow
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Artifact Normalizer │ ← Canonical runtime artifact contract
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Sandbox Router │ ← Isolated evaluation boundary
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Heuristic + Pattern Engine │ ← Rule-based threat detection
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │ Local
Prompt Guard Classifier │ ← Malicious-content classification
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Policy Enforcer │ ← Org-level policy rules applied
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Verdict Enforcer │ ← Final decision: allow/warn/quarantine/block
└─────────────────────────────────┘ │ ▼ VERDICT

Every single agent output traverses every single layer. There is no bypass path.
There is no silent pass-through.

---

## Verdicts

| Verdict      | Risk score range     | Behavior                                           |
| ------------ | -------------------- | -------------------------------------------------- |
| `allow`      | 0–29                 | Content released into the protected flow           |
| `warn`       | 30–69 (configurable) | Content surfaced with risk signal — caller decides |
| `quarantine` | 30–69 (configurable) | Content isolated, not released, pending review     |
| `block`      | 70–100               | Content denied. Hard stop. No release.             |

Thresholds are fully configurable via environment variables. The verdict engine
has no hardcoded safe defaults that can be silently misconfigured.

---

## Platform integrations in v1 <img width="128" height="128" alt="Golden Knight Logo128" src="https://github.com/user-attachments/assets/c43ab18f-e9e1-4149-b33f-e3c67be4d424" />


| Platform / runtime         | Support path                                                                | Status                     |
| -------------------------- | --------------------------------------------------------------------------- | -------------------------- |
| Claude Code                | `app/adapters/claude_code_adapter.py`, `app/api/routes/integrations.py`     | ✅ Active                  |
| OpenClaw                   | `app/adapters/openclaw_adapter.py`, `app/api/routes/integrations.py`        | ✅ Active                  |
| Cursor                     | `app/api/routes/integrations.py`, `ironclaw_installer.py`, `cli/install.py` | ✅ Active                  |
| Goose                      | `app/api/routes/integrations.py`, `ironclaw_installer.py`, `cli/install.py` | ✅ Active                  |
| Gemini CLI                 | `app/api/routes/integrations.py`, `ironclaw_installer.py`, `cli/install.py` | ✅ Active                  |
| GitHub Copilot             | `app/api/routes/integrations.py`, `ironclaw_installer.py`, `cli/install.py` | ✅ Active                  |
| Hermes Agent               | `app/adapters/hermes_adapter.py`, `app/api/routes/integrations.py`          | ✅ Active                  |
| Security Guardian          | `ironclaw_installer.py`, `app/api/routes/integrations.py`                   | ✅ Shared protection layer |
| MCP tool integration layer | `app/adapters/mcp_tool_adapter.py`, `app/services/integration_registry.py`  | ✅ Active support layer    |

The system treats every supported runtime as a trust boundary that must be
protected. The integrations are part of the security model, not just optional
add-ons.

V2 target: every major AI runtime, every major agent framework, and every major
MCP / toolchain integration that executes untrusted content in a privileged
context.

---

## Current security shape

IronClaw-Security is a full runtime protection stack, not a single feature or a
single app. It combines enforcement, reasoning, orchestration, quarantine,
telemetry, review control, and agent-platform integrations into one coherent
security control plane for AI-native tooling.

### 1. Core runtime and control plane

- `app/main.py` — application bootstrap and route assembly.
- `app/service.py` — runtime lifecycle and control-plane service entrypoint.
- `app/bootstrap.py` — startup orchestration and environment bootstrapping.
- `app/facade.py` — orchestration façade for centralized runtime operations.
- `app/config.py` — system configuration and runtime defaults.
- `app/dependencies.py` — dependency injection and initialization wiring.
- `app/guard_router.py` — central guard enforcement routing layer.
- `app/verify.py` — install and runtime verification flows.
- `app/api/` — product API modules and integration endpoints.
- `app/routers/` — route surface for the control plane.
- `app/clients/` — application and runtime integration clients.
- `app/providers/` — provider registry and platform abstraction layer.
- `app/repositories/` — persistence and repository interfaces.
- `app/schemas/` — typed API, policy, and verdict models.
- `app/security/` — control-plane security primitives and hardening logic.
- `app/orchestrator/` — centralized runtime orchestration.
- `app/system/` — diagnostics, health, and service lifecycle monitoring.
- `app/worker/` — background enforcement and async execution tasks.

### 2. Enforcement, sandbox, and execution control

- `app/runtime/` — runtime guard, coordination, sandboxing, and execution
  control.
- `app/runtime/filereturnguard.py` — file-return interception and release
  gating.
- `app/runtime/toolcallguard.py` — tool-call policy evaluation and execution
  gating.
- `app/runtime/sandboxrouter.py` — sandbox routing and isolated execution flow.
- `app/runtime/commandsupervisor.py` — command supervision and enforcement.
- `app/runtime/networkguard.py` — outbound network analysis and boundary
  control.
- `app/runtime/status.py` — runtime state and health reporting.
- `app/runtime/` additional guard utilities and runtime-control orchestrators.

### 3. Integration layer and install surface

- `app/adapters/` — concrete runtime integration layer.
- `app/adapters/base.py` — base adapter contract.
- `app/adapters/claude_code_adapter.py` — Claude Code integration.
- `app/adapters/openclaw_adapter.py` — OpenClaw integration.
- `app/adapters/hermes_adapter.py` — Hermes runtime integration.
- `app/adapters/mcp_tool_adapter.py` — MCP tool integration boundary.
- `app/adapters/cape_adapter.py` — CAPE-related adapter interface.
- `app/adapters/llamafirewall_adapter.py` — LlamaFirewall adapter.
- `app/adapters/malwi_adapter.py` — Malwi adapter.
- `app/adapters/rebuff_adapter.py` — Rebuff adapter.
- `app/adapters/secret_scanner_adapter.py` — secret-scanning adapter.
- `app/adapters/sandboxruntimeadapter.py` — sandbox runtime adapter.
- `app/api/routes/integrations.py` — canonical supported-platform registry and
  install metadata.
- `ironclaw_installer.py` — platform install and runtime protection bootstrap.
- `cli/install.py` — install flow for protected runtimes.
- `cli/update.py` — update path for installed runtime protections.
- `cli/uninstall.py` — clean removal of runtime protections.
- `cli/verify.py` — validation of installed security state.
- `cli/package.py` — packaging and distribution support.

### 4. Threat intelligence, policy, and verdicting

- `app/services/` — service layer for evaluation, policy, decisioning, and
  response.
- `app/services/guard_security_brain.py` — local Prompt Guard security evaluation.
- `app/services/policy.py` — policy evaluation and rule enforcement.
- `app/services/verdict_enforcer.py` — final allow / warn / quarantine / block
  enforcement.
- `app/services/securityorchestrator.py` — unified orchestration and control
  flow.
- `app/services/threat_detection_engine.py` — correlation, scoring, and
  multi-step attack analysis.
- `app/services/secret_service.py` — secret discovery and redaction workflows.
- `app/services/scan_to_guard_adapter.py` — detection-to-enforcement translation
  layer.
- `app/services/integration_registry.py` — runtime integration mapping and
  compatibility registry.
- `app/services/integrationinstaller.py` — integration install logic and runtime
  setup support.
- `app/services/integration_verifier.py` — verification of protection health.
- `app/models/` — canonical runtime artifact and verdict contracts.
- `app/models/runtime_artifact.py` — normalized artifact model for inbound
  evaluation.
- `app/models/runtime_verdict.py` — normalized verdict model for policy
  outcomes.

### 5. Review, quarantine, and evidence handling

- `app/review/` and `app/reviews/` — operator review and decisioning workflows.
- `app/quarantine/` — quarantine handling and isolated artifact control.
- `app/incidents/` — incident lifecycle tracking and response handling.
- `app/audit/` — audit trail capture for decisions, actions, and policy
  outcomes.
- `app/services/auditlogservice.py` and `app/services/audit_store.py` — audit
  event storage.
- `app/services/quarantinestore.py` and `app/services/quarantine_store.py` —
  quarantine persistence.
- `app/services/alertstore.py` and `app/services/alert_store.py` — evidence and
  alert retention.
- `app/services/incidentstore.py` and `app/services/incident_store.py` —
  incident persistence.

### 6. Operator experience and dashboard

- `frontend/` — React operator surface and security dashboard.
- `frontend/src/App.jsx` and `frontend/src/App.js` — application routing and
  shell.
- `frontend/src/pages/` — landing, dashboard, auth, review, and incident
  surfaces.
- `frontend/src/components/` — reusable security widgets and dashboard panels.
- `frontend/src/lib/api.js` — live client API contract for the supported runtime
  surface.
- `frontend/src/context/` — auth and operator-state context providers.
- `frontend/src/pages/Landing.jsx` — threat model and system narrative for the
  product story.

### 7. Skills, packaging, and developer workflow

- `ironclaw_skill/` — skill runtime, integration, and platform adaptation layer.
- `ironclaw_skill/config.py` — skill config resolution and integration wiring.
- `ironclaw_skill/context.py` — integration context resolution and payload
  handling.
- `ironclaw_skill/contracts.py` — runtime contracts and payload model
  definitions.
- `ironclaw_skill/router.py` — skill endpoints and platform adaptation routes.
- `ironclaw_skill/middleware.py` — skill middleware and request handling.
- `cli_brain.py` — local brain decision and validation flow.
- `pyproject.toml` — package metadata, dependencies, and script entrypoints.

This is the real security shape of the project: a hardened AI runtime control
plane designed to sit in front of agent behavior, review every action, isolate
risk, and enforce a final verdict before unsafe execution can occur.

---

## CLI entry points

The CLI surface is centered on the real operating flow: install protection,
validate the environment, and manage the runtime security layer.

### Operator-facing commands

| Command              | Purpose                                                                    |
| -------------------- | -------------------------------------------------------------------------- |
| `ironclaw`           | Main management CLI for install, update, uninstall, and platform setup.    |
| `ironclaw install`   | Install the protection layer on a supported AI or runtime target.          |
| `ironclaw verify`    | Validate the installed security state and confirm the guardrail is active. |
| `ironclaw update`    | Refresh the installed protection and platform integration state.           |
| `ironclaw uninstall` | Remove IronClaw protection cleanly from a target runtime.                  |

### Internal engineering and validation commands

These tools exist for local engineering work, validation, and advanced security
analysis, but they are not the normal operator workflow:

| Command               | Purpose                                                           |
| --------------------- | ----------------------------------------------------------------- |
| `ironclaw-brain`      | Local security-brain runner for decision and scanning validation. |
| `ironclaw-skill`      | Skill packaging and integration helper used in local development. |
| `ironclaw-smoketest`  | Smoke-test client for runtime validation and platform checks.     |
| `ironclaw-testclient` | Local verification client for security and guard-control testing. |

Example workflow for the shipped system:

```powershell
ironclaw install --provider-target security_guardian --provider-target openclaw --provider-target claude_code
ironclaw verify
ironclaw update
ironclaw uninstall --provider-target claude_code
```

For deeper local validation and security workflow work, the internal tools
remain available:

```powershell
python -m cli_brain --text "drop table users;" --mode enforce --json
python -m cli_brain --file payload.txt --mode strict --session-id my-session
```

---

## Final principle

IronClaw-Security is built around one truth: every AI action is a trust
boundary, and every trust boundary must be granted, observed, and enforced
before it can become operationally dangerous.

The product story is not a setup guide and not a broad configuration appendix.
It is a security architecture for real-world AI workloads: intercept, assess,
contain, and decide before unsafe behavior reaches users, systems, or data.
