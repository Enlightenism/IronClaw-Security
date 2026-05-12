from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from .config import ProviderConfig
from .errors import ProviderAuthenticationError, ProviderExecutionError


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
            }
        )
    return normalized


def _extract_text(payload: Mapping[str, Any]) -> str:
    content = payload.get("content")
    if isinstance(content, str):
        return content.strip()

    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, Mapping):
                if item.get("type") == "text" and isinstance(item.get("text"), str):
                    parts.append(item["text"])
                elif isinstance(item.get("content"), str):
                    parts.append(item["content"])
            elif isinstance(item, str):
                parts.append(item)
        return "\n".join(part for part in parts if part).strip()

    output_text = payload.get("output_text")
    if isinstance(output_text, str):
        return output_text.strip()

    completion = payload.get("completion")
    if isinstance(completion, str):
        return completion.strip()

    return ""


@dataclass(slots=True)
class ClaudeAdapter:
    config: ProviderConfig

    @property
    def name(self) -> str:
        return self.config.name

    def healthcheck(self) -> dict[str, Any]:
        configured = self.config.enabled and bool(
            self.config.endpoint and self.config.api_key and self.config.model
        )
        return {
            "provider": self.name,
            "ok": configured,
            "message": "ready" if configured else "missing configuration",
        }

    async def execute(self, request: Any) -> dict[str, Any]:
        self.config.require_ready()

        headers = {
            "x-api-key": self.config.api_key or "",
            "content-type": "application/json",
            "anthropic-version": "2023-06-01",
            **dict(self.config.headers),
        }

        if self.config.organization:
            headers["anthropic-organization-id"] = self.config.organization

        payload: dict[str, Any] = {
            "model": getattr(request, "model", None) or self.config.model,
            "max_tokens": int(getattr(request, "max_tokens", 1024)),
            "messages": _normalize_messages(getattr(request, "messages", ())),
        }

        system_prompt = getattr(request, "system_prompt", None)
        if system_prompt:
            payload["system"] = system_prompt

        temperature = getattr(request, "temperature", None)
        if temperature is not None:
            payload["temperature"] = temperature

        metadata = getattr(request, "metadata", None)
        if metadata:
            payload["metadata"] = dict(metadata)

        timeout = httpx.Timeout(
            timeout=self.config.timeout_seconds,
            connect=self.config.connect_timeout_seconds,
        )

        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.post(
                    self.config.endpoint,
                    headers=headers,
                    json=payload,
                )
        except httpx.TimeoutException as exc:
            raise ProviderExecutionError(f"{self.name} request timed out") from exc
        except httpx.HTTPError as exc:
            raise ProviderExecutionError(f"{self.name} transport error: {exc}") from exc

        if response.status_code in {401, 403}:
            raise ProviderAuthenticationError(f"{self.name} authentication failed")

        if response.status_code >= 400:
            raise ProviderExecutionError(
                f"{self.name} returned {response.status_code}: {response.text}"
            )

        data = response.json()
        usage_raw = data.get("usage")
        usage = dict(usage_raw) if isinstance(usage_raw, Mapping) else {}

        return {
            "provider": self.name,
            "model": str(payload["model"]),
            "output_text": _extract_text(data),
            "finish_reason": str(data.get("stop_reason") or data.get("finish_reason") or "unknown"),
            "usage": usage,
            "raw_response": data,
        }


ClaudeSkillAdapter = ClaudeAdapter


def adaptclauderequest(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Claude request payload must be a JSON object.")
    return dict(payload)


def adaptclauderesponse(response: Any) -> dict[str, Any]:
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
    "ClaudeAdapter",
    "ClaudeSkillAdapter",
    "adaptclauderequest",
    "adaptclauderesponse",
]