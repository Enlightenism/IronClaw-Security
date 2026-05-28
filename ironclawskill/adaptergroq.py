from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import os
from typing import Any

import httpx

from .config import ProviderConfig
from .errors import ProviderAuthenticationError, ProviderExecutionError

_GROQ_DEFAULT_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions"
_GROQ_DEFAULT_MODEL = "llama3-8b-8192"


def _env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _resolve_groq_api_key(config_key: str | None) -> str | None:
    return _env("IRONCLAWSKILL_GROQ_API_KEY") or _env("GROQ_API_KEY") or config_key


def _normalize_messages(messages: Sequence[Any]) -> list[dict[str, str]]:
    normalized: list[dict[str, str]] = []
    for message in messages:
        role = getattr(message, "role", None)
        content = getattr(message, "content", None)
        if role is None and isinstance(message, Mapping):
            role = message.get("role")
            content = message.get("content")
        normalized.append(
            {
                "role": str(role or "user"),
                "content": str(content or ""),
            },
        )
    return normalized


def _extract_text(payload: Mapping[str, Any]) -> str:
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, Mapping):
            message = first.get("message")
            if isinstance(message, Mapping):
                content = message.get("content")
                if isinstance(content, str):
                    return content.strip()
            delta = first.get("delta")
            if isinstance(delta, Mapping):
                content = delta.get("content")
                if isinstance(content, str):
                    return content.strip()
            text = first.get("text")
            if isinstance(text, str):
                return text.strip()

    content = payload.get("content")
    if isinstance(content, str):
        return content.strip()

    return ""


def _extract_finish_reason(payload: Mapping[str, Any]) -> str:
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, Mapping):
            reason = first.get("finish_reason")
            if isinstance(reason, str):
                return reason
    return "unknown"


def _extract_usage(payload: Mapping[str, Any]) -> dict[str, Any]:
    usage_raw = payload.get("usage")
    return dict(usage_raw) if isinstance(usage_raw, Mapping) else {}


@dataclass(slots=True)
class GroqAdapter:
    config: ProviderConfig

    @property
    def name(self) -> str:
        return self.config.name

    def _effective_api_key(self) -> str | None:
        return _resolve_groq_api_key(self.config.api_key)

    def _effective_endpoint(self) -> str:
        return self.config.endpoint or _GROQ_DEFAULT_ENDPOINT

    def _effective_model(self, request_model: str | None = None) -> str:
        return request_model or self.config.model or _GROQ_DEFAULT_MODEL

    def healthcheck(self) -> dict[str, Any]:
        api_key = self._effective_api_key()
        configured = self.config.enabled and bool(api_key)
        return {
            "provider": self.name,
            "ok": configured,
            "message": "ready" if configured else "missing configuration",
        }

    async def execute(self, request: Any) -> dict[str, Any]:
        if not self.config.enabled:
            from .errors import ProviderConfigurationError

            raise ProviderConfigurationError(f"Provider '{self.name}' is disabled")

        api_key = self._effective_api_key()
        if not api_key:
            raise ProviderAuthenticationError(f"{self.name} requires an API key. " "Set IRONCLAWSKILL_GROQ_API_KEY or GROQ_API_KEY.")

        model = self._effective_model(getattr(request, "model", None))
        endpoint = self._effective_endpoint()

        headers: dict[str, str] = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            **dict(self.config.headers),
        }

        messages: list[dict[str, str]] = []
        system_prompt = getattr(request, "system_prompt", None)
        if system_prompt:
            messages.append({"role": "system", "content": str(system_prompt)})
        messages.extend(_normalize_messages(getattr(request, "messages", ())))

        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "max_tokens": int(getattr(request, "max_tokens", 1024)),
        }

        temperature = getattr(request, "temperature", None)
        if temperature is not None:
            payload["temperature"] = float(temperature)

        timeout = httpx.Timeout(
            timeout=self.config.timeout_seconds,
            connect=self.config.connect_timeout_seconds,
        )

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    endpoint,
                    headers=headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise ProviderExecutionError(f"{self.name} request timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderExecutionError(f"{self.name} transport error: {exc}") from exc

        if response.status_code in {401, 403}:
            raise ProviderAuthenticationError(f"{self.name} authentication failed")

        if response.status_code == 429:
            from .errors import SkillRateLimitError

            raise SkillRateLimitError(f"{self.name} rate limit exceeded")

        if response.status_code >= 400:
            raise ProviderExecutionError(
                f"{self.name} returned {response.status_code}: {response.text}",
            )

        data = response.json()

        return {
            "provider": self.name,
            "model": model,
            "output_text": _extract_text(data),
            "finish_reason": _extract_finish_reason(data),
            "usage": _extract_usage(data),
            "raw_response": data,
        }


GroqSkillAdapter = GroqAdapter


def adaptgroqrequest(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Groq request payload must be a JSON object.")
    return dict(payload)


def adaptgroqresponse(response: Any) -> dict[str, Any]:
    if hasattr(response, "model_dump") and callable(response.model_dump):
        dumped = response.model_dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    if hasattr(response, "todict") and callable(response.todict):
        dumped = response.todict()
        if isinstance(dumped, dict):
            return dumped
    if isinstance(response, dict):
        return dict(response)
    return {"result": response}


__all__ = [
    "GroqAdapter",
    "GroqSkillAdapter",
    "adaptgroqrequest",
    "adaptgroqresponse",
]
