# Render Deployment

The IronClaw API and the Docker sandbox broker are separate security
components.

Render Web Services can run the API image, but a normal Render container does
not provide the Docker socket required to create the mandatory isolated
scanner containers. Render deployments must connect the API to a Docker-capable
sandbox broker hosted on a private Docker host or VM.

## API Service

Use the repository's `render.yaml` blueprint. Configure these secret values in
the Render dashboard:

- `SANDBOX_BROKER_URL`
- `SANDBOX_BROKER_TOKEN`

Set `SANDBOX_BROKER_URL` to the private broker health/run endpoint. Do not use
`host.docker.internal` or an unrelated public origin. Set the broker token to
the same value used by the broker process.

The existing Render service must use Docker runtime. Set the dashboard
`PYTHON_VERSION` to `3.12.10` or remove the stale `3.12.x` value. Do not use
a wildcard Python version.

The API remains production-fail-closed:

- Missing broker configuration blocks startup.
- Missing or unreachable broker blocks startup after the startup grace period.
- Missing scanner image, Prompt Guard model, or policy snapshot blocks startup.
- A broker timeout or malformed response cannot become an output allow.

## Broker Host

The broker host must provide:

- Docker Engine
- `/var/run/docker.sock`
- The pinned `ironclaw-sandbox-scanner:1` image
- The Prompt Guard model bundle
- `sandbox_broker/security_rules.json`
- `sandbox_broker/policy_snapshot.json`

Start the broker only with a loopback or private-network topology approved for
the deployment. The broker token is mandatory.

```bash
python -m sandbox_broker.build_image
python -m sandbox_broker.main
```
