# IronClaw-Security

IronClaw-Security is a local-first AI security system focused on one job in v1: install into Claude Code and OpenClaw with a single setup flow, intercept inbound agent returns before they reach the user workflow, isolate them in a sandbox, verify them with the AI brain plus policy system, and then allow, warn, quarantine, or block the result.

This README is intentionally narrowed to the locked v1 mission. It does not describe every legacy route or every broad platform surface in the repo. It describes the shipping path we are building now.

## V1 mission

- One-command install.
- Claude Code integration.
- OpenClaw integration.
- Intercept inbound agent returns.
- Route inbound returns into sandbox isolation.
- Verify with AI brain plus policy engine.
- Return one final verdict:
  - `allow`
  - `warn`
  - `quarantine`
  - `block`

## What IronClaw-Security protects

IronClaw-Security v1 is designed to act as a front-line defender for agentic AI platforms.

Primary protection scope in this version:

- Agent-returned text.
- Agent-returned files.
- Tool output returned toward the user workflow.
- Risky command or execution payloads discovered during guarded evaluation.
- Suspicious fetched or transformed content that should not be released directly to the user environment.

## Core v1 flow

1. User installs IronClaw-Security.
2. IronClaw-Security connects to Claude Code or OpenClaw.
3. Inbound agent output is intercepted before release.
4. The artifact is normalized and routed into the guarded runtime path.
5. The artifact is isolated in the sandbox.
6. The AI brain and policy layer evaluate the artifact.
7. IronClaw-Security returns a final verdict.
8. Safe content is released, unsafe content is warned, quarantined, or blocked.

## Current product shape

This repo is being narrowed around the following v1 path:

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
- `cli_brain.py` — AI brain entry layer.
- `app/services/groq_security_brain.py` — Groq-backed security reasoning.
- `app/services/policy.py` — policy evaluation layer.
- `app/services/verdict_enforcer.py` — final verdict execution.
- `app/services/runtime_ingress.py` — canonical inbound runtime intake if needed.
- `app/models/runtime_artifact.py` — normalized runtime artifact contract if needed.
- `app/models/runtime_verdict.py` — normalized verdict contract if needed.

## Supported verdicts

IronClaw-Security uses these verdict states in v1:

- `allow`
- `warn`
- `quarantine`
- `block`

General intent:

- `allow` — content may continue through the protected flow.
- `warn` — content is risky and should surface caution in the protected flow.
- `quarantine` — content is isolated and not released by default.
- `block` — content is denied from release or execution.

## Local setup

```powershell
py -m pip install -r requirements.txt
```

## Run locally

```powershell
python -m uvicorn app.main:app --reload
```

## Basic local checks

Open:

- [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
- [http://127.0.0.1:8000/health](http://127.0.0.1:8000/health)
- [http://127.0.0.1:8000/mission](http://127.0.0.1:8000/mission)

## Test

```powershell
py -m pytest -q
```

## Windows service path

For the local machine protection flow, the main Windows-oriented service files are:

- `ironclaw_installer.py`
- `service.py`
- `scripts/ironclaw_service_windows.ps1`

These are part of the one-command install and persistent local protection path.

## Minimal API intent for v1

The app is being shaped around a small protected runtime surface, not a giant public platform surface.

Expected v1 focus areas:

- System health and status routes.
- Claude Code and OpenClaw integration bootstrap routes.
- Guard and action execution routes.
- Sandbox verification flow.
- Policy evaluation routes.
- Incident and quarantine routes needed to support protected decisions.

If a route does not directly support install, integration, interception, sandbox verification, verdicting, or minimal protected status visibility, it is not part of the core v1 shipping path.

## Example mission summary

IronClaw-Security receives inbound agent output, evaluates it inside a guarded runtime path, applies AI-assisted reasoning plus policy enforcement, and returns a controlled release decision.

## Development method

Current build workflow for this repo:

1. Update one page at a time.
2. Replace the full page when needed.
3. Run:

```powershell
py -m pytest -q
```

4. Fix the next failing or incomplete page.
5. Repeat until the v1 mission path is complete.

## Notes

- Keep the public story centered on the locked v1 mission.
- Keep route documentation aligned with the actual mounted routers in `app/main.py`.
- Do not document broad legacy surfaces as if they are part of the release path.
- Prefer narrow, testable, shipping-safe contracts while IronClaw-Security v1 is being completed.