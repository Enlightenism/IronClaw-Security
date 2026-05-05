from __future__ import annotations

import importlib
import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Literal, Mapping, Sequence, cast

GroqRole = Literal["system", "user", "assistant"]


@dataclass(slots=True)
class GroqChatMessage:
    role: GroqRole
    content: str

    def to_dict(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(slots=True)
class GroqChatClient:
    """
    Thin Groq chat client abstraction for the IronClaw security brain + UI.

    Design goals:
    - Keep the public surface tiny and stable: one .chat() method.
    - Never make network calls in test by default; fall back to a local echo
      stub if the groq SDK or API key is missing or raises.
    - Allow production deployments to wire a real Groq backend via env vars
      without changing any callers.

    Callers typically do:
        client = GroqChatClient.default()
        answer = client.chat(messages=[...], model="groq-security-copilot")

    All callers must only rely on .default() and .chat(...).
    """

    default_model: str = "groq-security-copilot"

    @classmethod
    def default(cls) -> "GroqChatClient":
        """
        Factory used throughout IronClaw (UI copilot, remediation, etc.).

        The default model can be overridden with GROQ_MODEL_DEFAULT.
        """
        model = os.getenv("GROQ_MODEL_DEFAULT", cls.default_model)
        return cls(default_model=model)

    def chat(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        model: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> str:
        """
        Synchronous chat call.

        Behavior:
        - If GROQ_API_KEY and groq SDK are available, call Groq.
        - Otherwise, return a deterministic echo-style stub so tests
          and local dev always have a response and never hard-crash.

        The return is always a plain text reply.
        """
        normalized: list[GroqChatMessage] = [
            GroqChatMessage(
                role=_coerce_role(message.get("role", "user")),
                content=str(message.get("content", "") or ""),
            )
            for message in messages
        ]

        api_key = os.getenv("GROQ_API_KEY")
        if api_key and _groq_sdk_available():
            try:
                return _call_groq_api(
                    api_key=api_key,
                    messages=normalized,
                    model_override=model,
                    default_model=self.default_model,
                    metadata=metadata,
                )
            except Exception:
                return self._fallback_response(normalized)

        return self._fallback_response(normalized)

    def _fallback_response(self, messages: Sequence[GroqChatMessage]) -> str:
        last_user = _last_message_with_role(messages, "user")
        last_content = last_user.content if last_user else ""

        summary_bits: list[str] = []

        if last_content:
            snippet = last_content.strip()
            if len(snippet) > 500:
                snippet = snippet[:500].rstrip() + "…"
            summary_bits.append(f"Last user message:\n{snippet}")
        else:
            summary_bits.append("Last user message: <empty>")

        summary_bits.append(f"Conversation length: {len(messages)} message(s)")

        return (
            "Groq Security Copilot (local stub)\n"
            "No live Groq backend is configured; this is a deterministic "
            "echo-style response for testing.\n\n"
            + "\n\n".join(summary_bits)
        )


def _groq_sdk_available() -> bool:
    try:
        importlib.import_module("groq")
        return True
    except ModuleNotFoundError:
        return False


def _call_groq_api(
    *,
    api_key: str,
    messages: Sequence[GroqChatMessage],
    model_override: str | None,
    default_model: str,
    metadata: Mapping[str, Any] | None,
) -> str:
    groq_module = importlib.import_module("groq")
    Groq = getattr(groq_module, "Groq")

    client = Groq(api_key=api_key)
    model = model_override or default_model
    payload_messages = [message.to_dict() for message in messages]

    safe_metadata: dict[str, Any] | None = None
    if metadata:
        try:
            json.dumps(metadata)
            safe_metadata = dict(metadata)
        except Exception:
            safe_metadata = None

    completion = client.chat.completions.create(
        model=model,
        messages=payload_messages,
        temperature=0.2,
        metadata=safe_metadata,
    )

    try:
        message = completion.choices[0].message
        content = message.content
    except Exception:
        return "Groq Security Copilot encountered an unexpected response shape from the Groq API."

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        parts: list[str] = []
        for item in cast(list[Any], content):
            if isinstance(item, dict):
                text = item.get("text")
                if text:
                    parts.append(str(text))
            elif hasattr(item, "text"):
                text = getattr(item, "text", None)
                if text:
                    parts.append(str(text))
        if parts:
            return "".join(parts)

    return "Groq Security Copilot returned an empty response."


def _coerce_role(raw: Any) -> GroqRole:
    value = str(raw or "").strip().lower()
    if value == "system":
        return "system"
    if value == "assistant":
        return "assistant"
    return "user"


def _last_message_with_role(
    messages: Iterable[GroqChatMessage],
    role: GroqRole,
) -> GroqChatMessage | None:
    last: GroqChatMessage | None = None
    for message in messages:
        if message.role == role:
            last = message
    return last