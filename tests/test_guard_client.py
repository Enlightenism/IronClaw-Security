from __future__ import annotations

import pytest

from app.services.guard_client import GuardChatClient, GuardChatMessage
from app.services.prompt_guard import PromptGuardResult
import app.services.prompt_guard_client as prompt_guard_client_module
from app.services.prompt_guard_client import PromptGuardClient


def _client(*, enabled: bool = True, threshold: float = 0.5) -> GuardChatClient:
    return GuardChatClient(
        prompt_guard_client=PromptGuardClient(
            enabled=enabled,
            model_path="models/prompt-guard-86m",
            threshold=threshold,
        ),
    )


def _install_classifier(
    monkeypatch: pytest.MonkeyPatch,
    result: PromptGuardResult,
) -> list[tuple[str, str, float]]:
    calls: list[tuple[str, str, float]] = []

    def classify_prompt_guard(
        text: str,
        *,
        model_path: str,
        threshold: float,
    ) -> PromptGuardResult:
        calls.append((text, model_path, threshold))
        return result

    monkeypatch.setattr(
        prompt_guard_client_module,
        "classify_prompt_guard",
        classify_prompt_guard,
    )
    return calls


def test_chat_formats_classification_and_scans_only_user_messages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_classifier(
        monkeypatch,
        PromptGuardResult(
            label="BENIGN",
            malicious_score=0.12,
            model_name="prompt-guard-86m",
        ),
    )
    client = _client(threshold=0.75)

    response = client.chat(
        messages=[
            {"role": "system", "content": "trusted instructions"},
            {"role": "user", "content": " first user prompt "},
            {"role": "assistant", "content": "assistant history"},
            {"role": "user", "content": " second user prompt "},
        ],
        model="legacy-chat-model",
        metadata={"request_id": "request-001"},
    )

    assert response == ("Prompt Guard classification: BENIGN (malicious score 0.120; model prompt-guard-86m).")
    assert calls == [
        (
            "first user prompt\nsecond user prompt",
            "models/prompt-guard-86m",
            0.75,
        ),
    ]


def test_chat_formats_malicious_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_classifier(
        monkeypatch,
        PromptGuardResult(
            label="MALICIOUS",
            malicious_score=0.97,
            model_name="prompt-guard-86m",
        ),
    )

    response = _client().chat(
        messages=[{"role": "user", "content": "suspicious prompt"}],
    )

    assert response == ("Prompt Guard classification: MALICIOUS (malicious score 0.970; model prompt-guard-86m).")


def test_unrecognized_message_roles_are_coerced_to_user(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = _install_classifier(
        monkeypatch,
        PromptGuardResult(
            label="BENIGN",
            malicious_score=0.12,
            model_name="prompt-guard-86m",
        ),
    )

    _client().chat(
        messages=[{"role": "tool", "content": "untrusted tool output"}],
    )

    assert calls[0][0] == "untrusted tool output"


def test_disabled_guard_returns_explicit_non_echoing_stub(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        prompt_guard_client_module,
        "classify_prompt_guard",
        lambda *_args, **_kwargs: pytest.fail("disabled guard must not load the model"),
    )

    response = _client(enabled=False).chat(
        messages=[{"role": "user", "content": "password=do-not-repeat"}],
    )

    assert "guard_disabled" in response
    assert "password=do-not-repeat" not in response
    assert "Conversation length: 1 message(s)" in response
    assert "prompt-guard-86m-local local stub" in response


@pytest.mark.parametrize(
    ("messages", "reason"),
    [
        ([], "no_user_message"),
        ([{"role": "user", "content": "  "}], "empty_prompt"),
    ],
)
def test_missing_or_empty_user_content_returns_stub_without_loading_model(
    monkeypatch: pytest.MonkeyPatch,
    messages: list[dict[str, str]],
    reason: str,
) -> None:
    monkeypatch.setattr(
        prompt_guard_client_module,
        "classify_prompt_guard",
        lambda *_args, **_kwargs: pytest.fail("empty input must not load the model"),
    )

    response = _client().chat(messages=messages)

    assert reason in response


def test_local_model_errors_are_not_hidden(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_classification(
        text: str,
        *,
        model_path: str,
        threshold: float,
    ) -> PromptGuardResult:
        raise RuntimeError("local model failure")

    monkeypatch.setattr(
        prompt_guard_client_module,
        "classify_prompt_guard",
        fail_classification,
    )

    with pytest.raises(RuntimeError, match="local model failure"):
        _client().chat(messages=[{"role": "user", "content": "classify this"}])


def test_guard_chat_message_to_dict_preserves_role_and_content() -> None:
    message = GuardChatMessage(role="assistant", content="classification complete")

    assert message.to_dict() == {
        "role": "assistant",
        "content": "classification complete",
    }
