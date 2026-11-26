from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
