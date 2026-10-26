from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from typing import NoReturn

import pytest

from app.services.prompt_guard import PromptGuardLabel, PromptGuardResult
from ironclawskill import adapterguard as guard_adapter_module
from ironclawskill.adapterguard import (
    GuardAdapter,
    GuardSkillAdapter,
    adaptguardrequest,
    adaptguardresponse,
)
from ironclawskill.config import IronClawSkillConfig, ProviderConfig
from ironclawskill.contracts import (
    RiskLevel,
    SkillDecision,
    SkillExecutionRequest,
    SkillProvider,
)
from ironclawskill.errors import ProviderExecutionError
from ironclawskill.router import SkillExecutionAPIRequest, _RouterState
from ironclawskill.runtime import IronClawRuntime


def test_guard_adapter_classifies_locally_and_preserves_response_shape(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "prompt-guard"
    model_path.mkdir()
    (model_path / "config.json").write_text("{}", encoding="utf-8")
    (model_path / "model.safetensors").touch()

    monkeypatch.delenv("IRONCLAWSKILL_GUARD_MODEL_PATH", raising=False)
    monkeypatch.delenv("GUARD_MODEL_PATH", raising=False)
    monkeypatch.setattr(
        guard_adapter_module,
        "get_settings",
        lambda: SimpleNamespace(
            guard_enabled=True,
            guard_model_path=str(model_path),
            guard_threshold=0.73,
        ),
    )

    calls: list[tuple[str, str, float]] = []
    classification = PromptGuardResult(
        label="MALICIOUS",
        malicious_score=0.91,
        model_name="prompt-guard-86m-local",
    )

    def classify(
        text: str,
        *,
        model_path: str,
        threshold: float,
    ) -> PromptGuardResult:
        calls.append((text, model_path, threshold))
        return classification

    monkeypatch.setattr(
        guard_adapter_module,
        "classify_prompt_guard",
        classify,
    )

    adapter = GuardAdapter(
        config=ProviderConfig(
            name="guard",
            enabled=True,
            model_path=str(model_path),
        ),
    )
    result = asyncio.run(
        adapter.execute(
            {
                "prompt": "Classify this prompt",
                "messages": [
                    {"role": "system", "content": "Do not classify this"},
                    {"role": "user", "content": "User message"},
                ],
                "input_artifacts": [{"content": "Artifact context"}],
            },
        ),
    )

    expected_text = "Classify this prompt\n\nUser message\n\nArtifact context"
    assert calls == [(expected_text, str(model_path.resolve()), 0.73)]
    assert result == {
        "provider": "guard",
        "model": "prompt-guard-86m-local",
        "output_text": ("Prompt Guard classification: MALICIOUS (malicious score 0.910; model prompt-guard-86m-local)."),
        "finish_reason": "classified",
        "usage": {},
        "raw_response": classification.to_dict(),
    }
    assert adapter.healthcheck()["ok"] is True


def test_guard_adapter_rejects_empty_text_without_classification(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "prompt-guard"
    model_path.mkdir()
    (model_path / "config.json").write_text("{}", encoding="utf-8")
    (model_path / "model.safetensors").touch()

    monkeypatch.delenv("IRONCLAWSKILL_GUARD_MODEL_PATH", raising=False)
    monkeypatch.delenv("GUARD_MODEL_PATH", raising=False)
    monkeypatch.setattr(
        guard_adapter_module,
        "get_settings",
        lambda: SimpleNamespace(
            guard_enabled=True,
            guard_model_path=str(model_path),
            guard_threshold=0.73,
        ),
    )

    def fail_classification(*_args: object, **_kwargs: object) -> NoReturn:
        pytest.fail("Classifier should not be called for empty text.")

    monkeypatch.setattr(
        guard_adapter_module,
        "classify_prompt_guard",
        fail_classification,
    )

    adapter = GuardAdapter(
        config=ProviderConfig(
            name="guard",
            enabled=True,
            model_path=str(model_path),
        ),
    )

    with pytest.raises(ProviderExecutionError, match="contains no text"):
        asyncio.run(adapter.execute({"prompt": "  "}))


@pytest.mark.parametrize(
    ("label", "score", "expected_decision", "expected_risk"),
    [
        ("MALICIOUS", 0.91, SkillDecision.BLOCK, RiskLevel.HIGH),
        ("BENIGN", 0.01, SkillDecision.ALLOW, RiskLevel.LOW),
    ],
)
@pytest.mark.parametrize("async_execution", [False, True])
def test_guard_runtime_maps_local_classification_to_policy_decision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: PromptGuardLabel,
    score: float,
    expected_decision: SkillDecision,
    expected_risk: RiskLevel,
    async_execution: bool,
) -> None:
    local_model_path = tmp_path / "prompt-guard"
    local_model_path.mkdir()
    (local_model_path / "config.json").write_text("{}", encoding="utf-8")
    (local_model_path / "model.safetensors").touch()

    monkeypatch.delenv("IRONCLAWSKILL_GUARD_ENABLED", raising=False)
    monkeypatch.delenv("IRONCLAWSKILL_GUARD_MODEL_PATH", raising=False)
    monkeypatch.delenv("GUARD_MODEL_PATH", raising=False)
    monkeypatch.setattr(
        guard_adapter_module,
        "get_settings",
        lambda: SimpleNamespace(
            guard_enabled=True,
            guard_model_path=str(local_model_path),
            guard_threshold=0.73,
        ),
    )

    def classify(
        _text: str,
        *,
        model_path: str,
        threshold: float,
    ) -> PromptGuardResult:
        assert model_path == str(local_model_path.resolve())
        assert threshold == 0.73
        return PromptGuardResult(
            label=label,
            malicious_score=score,
            model_name="prompt-guard-86m-local",
        )

    monkeypatch.setattr(
        guard_adapter_module,
        "classify_prompt_guard",
        classify,
    )

    config = IronClawSkillConfig.from_mapping(
        {
            "default_provider": "guard",
            "providers": {
                "guard": {
                    "enabled": True,
                    "model_path": str(local_model_path),
                },
            },
        },
        root_dir=tmp_path,
    )
    runtime = IronClawRuntime(config=config)
    request = SkillExecutionRequest(
        requestid="guard-runtime-test",
        provider=SkillProvider.GUARD,
        prompt="Classify this input",
    )

    if async_execution:
        result = asyncio.run(runtime.execute_async(request))
    else:
        result = runtime.execute(request)

    assert result.provider is SkillProvider.GUARD
    assert result.decision is expected_decision
    assert result.risk is expected_risk
    assert result.metadata["guard_label"] == label
    assert result.metadata["guard_malicious_score"] == score
    assert result.outputtext == (f"Prompt Guard classification: {label} (malicious score {score:.3f}; model prompt-guard-86m-local).")


def test_guard_skill_route_classifies_user_messages_without_system_prompt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    model_path = tmp_path / "prompt-guard"
    model_path.mkdir()
    (model_path / "config.json").write_text("{}", encoding="utf-8")
    (model_path / "model.safetensors").touch()

    monkeypatch.delenv("IRONCLAWSKILL_GUARD_ENABLED", raising=False)
    monkeypatch.delenv("IRONCLAWSKILL_GUARD_MODEL_PATH", raising=False)
    monkeypatch.delenv("GUARD_MODEL_PATH", raising=False)
    monkeypatch.setattr(
        guard_adapter_module,
        "get_settings",
        lambda: SimpleNamespace(
            guard_enabled=True,
            guard_model_path=str(model_path),
            guard_threshold=0.73,
        ),
    )

    def classify(
        text: str,
        *,
        model_path: str,
        threshold: float,
    ) -> PromptGuardResult:
        assert text == "Classify this user message"
        assert model_path == str((tmp_path / "prompt-guard").resolve())
        assert threshold == 0.73
        return PromptGuardResult(
            label="MALICIOUS",
            malicious_score=0.91,
            model_name="prompt-guard-86m-local",
        )

    monkeypatch.setattr(
        guard_adapter_module,
        "classify_prompt_guard",
        classify,
    )

    config = IronClawSkillConfig.from_mapping(
        {
            "default_provider": "guard",
            "providers": {
                "guard": {
                    "enabled": True,
                    "model_path": str(model_path),
                },
            },
        },
        root_dir=tmp_path,
    )
    state = _RouterState(config=config)
    request = SkillExecutionAPIRequest(
        provider="guard",
        requestid="guard-api-test",
        messages=[
            {"role": "system", "content": "Exclude this system prompt"},
            {"role": "user", "content": "Classify this user message"},
        ],
    )

    response = asyncio.run(state.execute(request))

    assert response.provider == "guard"
    assert response.decision == SkillDecision.BLOCK.value
    assert response.blocked is True
    assert response.result["outputtext"] == ("Prompt Guard classification: MALICIOUS (malicious score 0.910; model prompt-guard-86m-local).")


def test_guard_adapter_aliases_and_adapters_preserve_payloads() -> None:
    payload = {"prompt": "Classify this"}
    response = {"label": "BENIGN"}
    classification = PromptGuardResult(
        label="BENIGN",
        malicious_score=0.01,
        model_name="prompt-guard-86m-local",
    )

    adapted_payload = adaptguardrequest(payload)
    adapted_response = adaptguardresponse(response)

    assert GuardSkillAdapter is GuardAdapter
    assert adapted_payload == payload
    assert adapted_payload is not payload
    assert adapted_response == response
    assert adapted_response is not response
    assert adaptguardresponse(classification) == classification.to_dict()
