from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from app.services.prompt_guard import PromptGuardResult
from app.services.prompt_guard_client import PromptGuardClient

GuardRole = Literal["system", "user", "assistant"]


@dataclass(slots=True)
class GuardChatMessage:
    role: GuardRole
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(slots=True)
class GuardChatClient:
    """Text-shaped compatibility client backed by local Prompt Guard classification."""

    default_model: str = "prompt-guard-86m-local"
    prompt_guard_client: PromptGuardClient = field(default_factory=PromptGuardClient.default)

    @classmethod
    def default(cls) -> GuardChatClient:
        return cls()

    def chat(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        model: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        """Classify user messages and format the result as plain text.

        The model and metadata arguments remain for API compatibility. The
        configured local Prompt Guard checkpoint controls classification.
        """
        normalized = [
            GuardChatMessage(
                role=_coerce_role(message.get("role", "user")),
                content=str(message.get("content", "") or ""),
            )
            for message in messages
        ]
        last_user = _last_message_with_role(normalized, "user")
        user_content = "\n".join(message.content.strip() for message in normalized if message.role == "user" and message.content.strip())

        if not user_content:
            reason = "empty_prompt" if last_user is not None else "no_user_message"
            return self._fallback_response(normalized, reason=reason)

        classification = self.prompt_guard_client.classify(user_content)
        if classification is None:
            reason = "guard_disabled" if not self.prompt_guard_client.enabled else "empty_prompt"
            return self._fallback_response(normalized, reason=reason)

        return self._classification_response(classification)

    def _classification_response(self, classification: PromptGuardResult) -> str:
        return f"Prompt Guard classification: {classification.label} (malicious score {classification.malicious_score:.3f}; model {classification.model_name or self.default_model})."

    def _fallback_response(
        self,
        messages: Sequence[GuardChatMessage],
        *,
        reason: str,
    ) -> str:
        return f"{self.default_model} local stub\nPrompt Guard did not classify this conversation ({reason}); the configured model is a classifier, not a generative model.\n\nConversation length: {len(messages)} message(s)"


def _coerce_role(raw: Any) -> GuardRole:
    value = str(raw or "").strip().lower()
    if value == "system":
        return "system"
    if value == "assistant":
        return "assistant"
    return "user"


def _last_message_with_role(
    messages: Iterable[GuardChatMessage],
    role: GuardRole,
) -> GuardChatMessage | None:
    last: GuardChatMessage | None = None
    for message in messages:
        if message.role == role:
            last = message
    return last
