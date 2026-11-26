from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_sandbox_startup_error_names_missing_broker_configuration() -> None:
    from app.main import _sandbox_startup_block_message

    message = _sandbox_startup_block_message({"reason": "broker_unconfigured"})

    assert "SANDBOX_BROKER_URL" in message
    assert "SANDBOX_BROKER_TOKEN" in message


def test_sandbox_startup_error_names_invalid_broker_url() -> None:
    from app.main import _sandbox_startup_block_message

    message = _sandbox_startup_block_message({"reason": "broker_url_invalid"})

    assert "SANDBOX_BROKER_URL" in message
    assert "http://" in message
    assert "https://" in message


def test_sandbox_broker_url_normalization_rejects_untrusted_forms() -> None:
    from app.services.sandbox_broker_client import normalize_broker_url

    assert normalize_broker_url("https://broker.internal.example:8443") == "https://broker.internal.example:8443"
    assert normalize_broker_url("ftp://broker.internal.example") is None
    assert normalize_broker_url("https://user:password@broker.internal.example") is None
    assert normalize_broker_url("https://broker.internal.example/health?token=secret") is None


def test_compose_runs_mandatory_sandbox_broker_service() -> None:
    compose = (PROJECT_ROOT / "compose.yaml").read_text(encoding="utf-8")

    assert "sandbox-broker:" in compose
    assert "/var/run/docker.sock:/var/run/docker.sock" in compose
    assert 'network_mode: "service:sandbox-broker"' in compose
    assert "python -m sandbox_broker.build_image" in compose
    assert 'SANDBOX_BROKER_URL: "http://127.0.0.1:8088"' in compose


def test_app_dockerfile_contains_sandbox_security_package() -> None:
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "docker.io" in dockerfile
    assert "prompt-guard-86m" in dockerfile
    assert "sandbox_broker" in dockerfile


def test_render_blueprint_pins_supported_runtime_and_external_broker() -> None:
    render = (PROJECT_ROOT / "render.yaml").read_text(encoding="utf-8")

    assert "runtime: docker" in render
    assert "dockerfilePath: ./Dockerfile" in render
    assert "healthCheckPath: /health/readiness" in render
    assert "PYTHON_VERSION" not in render
    assert "key: SANDBOX_BROKER_URL" in render
    assert "key: SANDBOX_BROKER_TOKEN" in render
    assert "sync: false" in render
    assert "SANDBOX_BROKER_STARTUP_GRACE_SECONDS" in render


def test_deployment_python_and_healthcheck_configuration_is_compatible() -> None:
    python_version = (PROJECT_ROOT / ".python-version").read_text(encoding="utf-8").strip()
    dockerfile = (PROJECT_ROOT / "Dockerfile").read_text(encoding="utf-8")
    render = (PROJECT_ROOT / "render.yaml").read_text(encoding="utf-8")

    assert python_version == "3.12.10"
    assert "python:3.12-slim" in dockerfile
    assert "/health/readiness" in dockerfile
    assert "healthCheckPath: /health/readiness" in render
