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

## Why IronClaw exists

AI agents are now executing real actions: writing files, calling APIs, running
shell commands, fetching remote content, and returning results directly into
user workflows. The attack surface is enormous and almost entirely undefended at
the infrastructure level.

The threats are real and active:

- **Prompt injection** — adversarial instructions hidden inside agent-returned
  content designed to hijack the model's next action, exfiltrate data, or
  override system policy.
- **Indirect prompt injection** — malicious payloads embedded in fetched web
  content, documents, or tool responses that the agent processes and then
  executes without user awareness.
- **Unsafe tool execution** — agent-initiated tool calls that write to disk,
  execute shell commands, or make outbound network requests with no enforcement
  boundary.
- **Data exfiltration via agent output** — sensitive data encoded into agent
  responses and routed out through tool calls or returned content before any
  human reviews it.
- **Trust collapse** — agents operating on stale, compromised, or
  adversarially-poisoned context that causes cascading unsafe decisions across a
  session.
- **Malicious file returns** — agent-returned files containing embedded
  payloads, macro execution triggers, or archive bombs routed directly into the
  user environment.
- **Command injection** — shell command strings constructed from agent output
  and executed without sanitization or policy enforcement.

IronClaw intercepts all of it. Before it lands.

---

## V1 mission

One locked, shipping mission:

- **One-command install** into Claude Code and OpenClaw.
- **Intercept every inbound agent return** before it reaches the user workflow.
- **Sandbox-isolate** every artifact for evaluation.
- **AI brain + policy engine** evaluate every artifact with LLM-assisted
  reasoning and deterministic rule enforcement.
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
- **Groq-powered AI brain analysis** applies LLM-assisted semantic reasoning to
  detect novel, obfuscated, or context-dependent injection attempts that
  rule-based systems miss.
- **Risk scoring** assigns a 0–100 score to every artifact. Scores above
  configurable thresholds route to quarantine or block automatically.
- **Policy enforcement** applies organization-level rules on top of the brain
  verdict — no single point of failure.
- **Sandbox isolation** means even content that passes initial checks is never
  released directly — it is evaluated inside a controlled runtime boundary
  first.

No other local-first AI security system applies all five layers to every single
inbound artifact.

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

## Core v1 enforcement flow

Agent output │ ▼ ┌─────────────────────────────────┐ │ IronClaw Ingress
Interceptor │ ← Intercepts before user workflow
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Artifact Normalizer │ ← Canonical runtime artifact contract
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Sandbox Router │ ← Isolated evaluation boundary
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │
Heuristic + Pattern Engine │ ← Rule-based threat detection
└─────────────────────────────────┘ │ ▼ ┌─────────────────────────────────┐ │ AI
Brain (Groq LLM) │ ← Semantic reasoning, injection detection
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

## Platform integrations in v1

| Platform       | Adapter                                 | Status         |
| -------------- | --------------------------------------- | -------------- |
| Claude Code    | `app/adapters/claude_code_adapter.py`   | ✅ V1 shipping |
| OpenClaw       | `app/adapters/openclaw_adapter.py`      | ✅ V1 shipping |
| Groq LLM brain | `app/services/groq_security_brain.py`   | ✅ V1 shipping |
| Generic agent  | `app/adapters/generic_agent_adapter.py` | ✅ V1 shipping |

V2 target: every major AI runtime, every major agent framework, every major
MCP-style toolchain.

---

## V2 — Full-spectrum AI security for every user and every device

V2 is the expansion from one focused interceptor into a full-spectrum AI
security platform.

The V2 mission: **protect every user, on every device, from every AI-native
attack vector possible.**

V2 target capabilities:

- **Universal agent interceptor** — protection layer for every major AI
  platform, not just Claude Code and OpenClaw.
- **Device-level enforcement** — local agent running on-device, enforcing policy
  before any AI output reaches the OS, filesystem, or user applications.
- **Real-time threat intelligence feed** — live threat signatures, injection
  pattern updates, and adversarial payload databases updated continuously.
- **Cross-session trust tracking** — behavioral baseline monitoring that detects
  when an agent's behavior pattern drifts into adversarial territory across
  sessions.
- **Multi-model brain** — OpenAI, Anthropic, and Groq reasoning layers working
  in parallel consensus for zero-miss detection on the most dangerous payloads.
- **Organization-wide policy management** — centralized policy bundles signed,
  versioned, and deployed across all devices and all agent integrations from a
  single control plane.
- **Audit and compliance export** — full telemetry, incident reports, and
  verdict history exportable for SOC2, ISO 27001, and enterprise compliance
  workflows.
- **Zero-trust agent execution** — every agent action treated as untrusted by
  default, every tool call verified, every execution plan approved before it
  runs.

---

## Current product shape

Core v1 files:

- `app/main.py` — main FastAPI app entrypoint and router mounting.
- `ironclaw_installer.py` — install/bootstrap entrypoint.
- `service.py` — local service lifecycle entrypoint.
- `scripts/ironclaw_service_windows.ps1` — Windows service wrapper/start path.
- `ironclaw_skill/config.py` — skill/config resolution for integration wiring.
- `ironclaw_skill/context.py` — integration context resolution.
- `app/adapters/claude_code_adapter.py` — Claude Code adapter.
- `app/adapters/openclaw_adapter.py` — OpenClaw adapter.
- `app/runtime/filereturnguard.py` — file-return interception and control.
- `app/runtime/toolcallguard.py` — guarded tool-call evaluation.
- `app/runtime/sandboxrouter.py` — sandbox routing.
- `app/runtime/commandsupervisor.py` — command supervision.
- `app/runtime/networkguard.py` — network boundary checks.
- `cli_brain.py` — AI brain CLI entry layer (`ironclaw-brain` script entry
  point).
- `app/services/groq_security_brain.py` — Groq-backed security reasoning.
- `app/services/policy.py` — policy evaluation layer.
- `app/services/verdict_enforcer.py` — final verdict execution.
- `app/services/runtime_ingress.py` — canonical inbound runtime intake.
- `app/models/runtime_artifact.py` — normalized runtime artifact contract.
- `app/models/runtime_verdict.py` — normalized verdict contract.

---

## Local setup

Copy the environment template and fill in your values before starting:

```powershell
cp .env.example .env
```

Install dependencies (editable install — do not run
`pip install -r requirements.txt` directly):

```powershell
pip install -e ".[dev]"
```

The editable install (`-e`) wires all CLI entry points and package imports from
source. Running `pip install -r requirements.txt` instead will produce a stale
install that does not register the CLI scripts and will break `ironclaw`,
`ironclaw-brain`, and related entry points.

---

## Run locally

```powershell
python -m uvicorn app.main:app --reload
```

Default binding: `http://127.0.0.1:8000`

To override the port set `APP_PORT` in `.env` and pass it explicitly:

```powershell
python -m uvicorn app.main:app --host 127.0.0.1 --port 8011 --reload
```

---

## Basic local checks

Open:

- [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- [http://127.0.0.1:8000/mission](http://127.0.0.1:8000/mission)

---

## Test

```powershell
python -m pytest -q
```

Collection check only (no execution):

```powershell
python -m pytest --co -q
```

---

## CLI entry points

After `pip install -e ".[dev]"` the following scripts are available:

| Command               | Module                   | Purpose                                          |
| --------------------- | ------------------------ | ------------------------------------------------ |
| `ironclaw`            | `app.cli.main:main`      | Integration management CLI                       |
| `ironclaw-brain`      | `cli_brain:main`         | Brain scan CLI — scan text via `/brain/decision` |
| `ironclaw-skill`      | `ironclawskill.cli:main` | Skill package CLI                                |
| `ironclaw-smoketest`  | `smoketestclient:main`   | Smoke test client                                |
| `ironclaw-testclient` | `testclient:main`        | Full test client                                 |

Brain CLI quick usage:

```powershell
python -m cli_brain --text "drop table users;" --mode enforce --json
python -m cli_brain --file payload.txt --mode strict --session-id my-session
```

---

## Configuration reference

Copy `.env.example` to `.env`. All keys listed below. Keys marked **REQUIRED**
will cause a silent failure or hard error if absent when the feature they gate
is active.

### Application identity

| Key           | Default             | Notes                                                |
| ------------- | ------------------- | ---------------------------------------------------- |
| `APP_NAME`    | `IronClaw-Security` | Shown in logs and API responses                      |
| `APP_VERSION` | `0.1.0`             | Semantic version of the running build                |
| `ENVIRONMENT` | `development`       | `development` \| `test` \| `staging` \| `production` |
| `DEBUG`       | `false`             | Never `true` in production                           |
| `RELOAD`      | `false`             | Uvicorn hot-reload — development only                |
| `API_PREFIX`  | _(empty)_           | Optional URL prefix for all routes, e.g. `/api/v1`   |

### Server binding

| Key                 | Default                        | Notes                                                                                                                                                                                                                |
| ------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `APP_HOST`          | `127.0.0.1`                    | Bind address                                                                                                                                                                                                         |
| `APP_PORT`          | `8000`                         | Bind port                                                                                                                                                                                                            |
| `APP_BASE_URL`      | `http://127.0.0.1:8000`        | Base URL used in generated links                                                                                                                                                                                     |
| `ENGINE_BASE_URL`   | `http://{APP_HOST}:{APP_PORT}` | Target URL for the IronClaw engine — consumed by `service.py` and `IronClawClient` callers. Defaults to `http://127.0.0.1:8000`. Override when the engine runs on a different host or port than the default binding. |
| `IRONCLAW_ENV`      | `development`                  | Legacy alias — kept for backward compatibility                                                                                                                                                                       |
| `IRONCLAW_BASE_URL` | `http://127.0.0.1:8000`        | Legacy alias — kept for backward compatibility                                                                                                                                                                       |

### Logging

| Key                          | Default | Notes                                                   |
| ---------------------------- | ------- | ------------------------------------------------------- |
| `LOG_LEVEL`                  | `INFO`  | `DEBUG` \| `INFO` \| `WARNING` \| `ERROR` \| `CRITICAL` |
| `STRUCTURED_LOGGING_ENABLED` | `true`  | Set `false` for human-readable local output             |

### Policy and verdict defaults

| Key                     | Default        | Notes                                                            |
| ----------------------- | -------------- | ---------------------------------------------------------------- |
| `DEFAULT_SCAN_VERDICT`  | `allow`        | Verdict when no rule matches: `allow` \| `block` \| `quarantine` |
| `DEFAULT_REVIEW_STATUS` | `not_required` | `not_required` \| `pending` \| `approved` \| `rejected`          |

### Risk thresholds

All values are integers 0–100. Constraint: `RISK_THRESHOLD_ALLOW_MAX` <
`RISK_THRESHOLD_QUARANTINE_MIN` ≤ `RISK_THRESHOLD_BLOCK_MIN`. Violating this
ordering produces undefined verdict behavior.

| Key                             | Default | Meaning                                  |
| ------------------------------- | ------- | ---------------------------------------- |
| `RISK_THRESHOLD_ALLOW_MAX`      | `29`    | Scores at or below this are auto-allowed |
| `RISK_THRESHOLD_QUARANTINE_MIN` | `30`    | Scores at or above this are quarantined  |
| `RISK_THRESHOLD_BLOCK_MIN`      | `70`    | Scores at or above this are hard-blocked |

### Scan feature flags

| Key                           | Default |
| ----------------------------- | ------- |
| `ENABLE_TEXT_SCANNING`        | `true`  |
| `ENABLE_URL_SCANNING`         | `true`  |
| `ENABLE_GITHUB_REPO_SCANNING` | `true`  |
| `ENABLE_ARCHIVE_SCANNING`     | `true`  |

### Guard and execution control flags

| Key                            | Default |
| ------------------------------ | ------- |
| `ENABLE_GUARD_ACTIONS`         | `true`  |
| `ENABLE_GUARD_ACTION_POLICY`   | `true`  |
| `ENABLE_GUARD_ACTION_DECISION` | `true`  |
| `ENABLE_QUARANTINE_REVIEW`     | `true`  |

### Input size limits

| Key                       | Default  | Unit       |
| ------------------------- | -------- | ---------- |
| `MAX_TEXT_CHARS`          | `100000` | characters |
| `MAX_URL_LENGTH`          | `2048`   | characters |
| `MAX_ARCHIVE_NAME_LENGTH` | `512`    | characters |
| `MAX_REPO_URL_LENGTH`     | `2048`   | characters |

### Authentication

> **Conditional requirement:** When `AUTH_REQUIRED=true`, at least one key slot
> below must be set or all protected routes will reject every request with 401.

| Key                         | Default   | Notes                                                                       |
| --------------------------- | --------- | --------------------------------------------------------------------------- |
| `AUTH_REQUIRED`             | `true`    | Set `true` in staging and production                                        |
| `API_KEY`                   | _(empty)_ | General-purpose key for standard callers                                    |
| `ADMIN_API_KEY`             | _(empty)_ | Elevated key for admin operations                                           |
| `PLATFORM_API_KEY`          | _(empty)_ | Key for trusted platform integrations                                       |
| `INTERNAL_PLATFORM_API_KEY` | _(empty)_ | Internal service-to-service key — highest trust level                       |
| `IRONCLAW_API_KEY`          | _(empty)_ | Primary IronClaw identity key — aliases all key slots above if none are set |

### Groq — LLM-assisted analysis

> **Conditional requirement:** `GROQ_API_KEY` is **REQUIRED** when
> `GROQ_ENABLED=true`. The brain service will fail at inference time if the key
> is absent and Groq is enabled. Obtain a key at
> [https://console.groq.com](https://console.groq.com).

| Key                    | Default          | Notes                                 |
| ---------------------- | ---------------- | ------------------------------------- |
| `GROQ_ENABLED`         | `true`           | Enable Groq-powered analysis passes   |
| `GROQ_API_KEY`         | _(empty)_        | **REQUIRED when `GROQ_ENABLED=true`** |
| `GROQ_MODEL`           | `llama3-8b-8192` | Groq model identifier                 |
| `GROQ_TIMEOUT_SECONDS` | `120.0`          | Per-request timeout in seconds        |

### OpenAI

| Key              | Default   | Notes                          |
| ---------------- | --------- | ------------------------------ |
| `OPENAI_API_KEY` | _(empty)_ | Optional — future / plugin use |

### Supabase — persistence layer

> All three Supabase keys are **REQUIRED** for full operation. Routes that write
> to or read from the persistence layer will error at runtime if these are
> absent.

| Key                         | Notes                                                               |
| --------------------------- | ------------------------------------------------------------------- |
| `SUPABASE_URL`              | Project URL from Supabase dashboard → Settings → API                |
| `SUPABASE_SERVICE_ROLE_KEY` | Service role key — bypasses RLS. **Keep secret, server-side only.** |
| `SUPABASE_ANON_KEY`         | Anon / public key for client-side or read-only operations           |

### File storage paths

| Key              | Default             |
| ---------------- | ------------------- |
| `REPORTS_DIR`    | `./data/reports`    |
| `UPLOADS_DIR`    | `./data/uploads`    |
| `QUARANTINE_DIR` | `./data/quarantine` |
| `BACKUP_DIR`     | `./data/backups`    |

---

## Windows service path

For the local machine protection flow, the main Windows-oriented service files
are:

- `ironclaw_installer.py`
- `service.py`
- `scripts/ironclaw_service_windows.ps1`

These are part of the one-command install and persistent local protection path.

---

## Minimal API surface for v1

The app is shaped around a small, hardened runtime surface — not a sprawling
public platform API.

V1 focus areas:

- System health and status routes.
- Claude Code and OpenClaw integration bootstrap routes.
- Guard and action execution routes.
- Sandbox verification flow.
- Policy evaluation routes.
- Incident and quarantine routes required to support protected decisions.

If a route does not directly support install, integration, interception, sandbox
verification, verdicting, or minimal protected status visibility, it is not part
of the core v1 shipping path.

---

## Notes

- Keep the public story centered on the locked v1 mission and what it can do for
  all users and companies
- Keep route documentation aligned with the actual mounted routers in
  `app/main.py`.
- Do not document broad legacy surfaces as if they are part of the release path.
- Prefer narrow, testable, shipping-safe contracts while IronClaw-Security v1 is
  being completed.
