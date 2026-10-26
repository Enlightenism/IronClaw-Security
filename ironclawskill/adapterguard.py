from __future__ import annotations

import asyncio
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import os
from pathlib import Path
from typing import Any

from app.core.settings import get_settings
from app.services.prompt_guard import (
    PromptGuardResult,
    classify_prompt_guard,
    resolve_prompt_guard_path,
)

from .config import ProviderConfig
from .errors import ProviderConfigurationError, ProviderExecutionError

_GUARD_DEFAULT_MODEL = "prompt-guard-86m-local"


def _env(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None
    value = value.strip()
    return value or None


def _resolve_guard_config(config_path: str | None = None) -> str:
    settings = get_settings()
    model_path = _env("IRONCLAWSKILL_GUARD_MODEL_PATH") or _env("GUARD_MODEL_PATH") or (config_path.strip() if config_path and config_path.strip() else None) or settings.guard_model_path
    return str(resolve_prompt_guard_path(model_path))


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


def _request_value(request: Any, name: str, default: Any = None) -> Any:
    if isinstance(request, Mapping):
        return request.get(name, default)
    return getattr(request, name, default)


def _request_text(request: Any) -> str:
    parts: list[str] = []

    prompt = _request_value(request, "prompt")
    if prompt is None:
        prompt = _request_value(request, "content")
    if prompt is not None and str(prompt).strip():
        parts.append(str(prompt).strip())

    messages = _request_value(request, "messages", ())
    if isinstance(messages, Sequence) and not isinstance(messages, str | bytes):
        parts.extend(message["content"].strip() for message in _normalize_messages(messages) if message["role"].strip().casefold() == "user" and message["content"].strip())

    artifacts = _request_value(request, "inputartifacts")
    if artifacts is None:
        artifacts = _request_value(request, "input_artifacts", ())
    if isinstance(artifacts, Sequence) and not isinstance(artifacts, str | bytes):
        for artifact in artifacts:
            content = _request_value(artifact, "content")
            if content is not None and str(content).strip():
                parts.append(str(content).strip())

    return "\n\n".join(dict.fromkeys(parts))


def _model_files_present(model_path: Path) -> bool:
    return model_path.is_dir() and (model_path / "config.json").is_file() and (model_path / "model.safetensors").is_file()


def _format_classification(classification: PromptGuardResult) -> str:
    return f"Prompt Guard classification: {classification.label} (malicious score {classification.malicious_score:.3f}; model {_GUARD_DEFAULT_MODEL})."


@dataclass(slots=True)
class GuardAdapter:
    config: ProviderConfig

    @property
    def name(self) -> str:
        return self.config.name

    def _effective_model_path(self) -> Path:
        return Path(_resolve_guard_config(self.config.model_path))

    def healthcheck(self) -> dict[str, Any]:
        settings = get_settings()
        model_files_present = _model_files_present(self._effective_model_path())
        configured = self.config.enabled and settings.guard_enabled and model_files_present
        return {
            "provider": self.name,
            "ok": configured,
            "message": "ready" if configured else "missing configuration",
        }

    def classify(self, request: Any) -> PromptGuardResult:
        if not self.config.enabled:
            raise ProviderConfigurationError(
                f"Provider '{self.name}' is disabled",
            )

        settings = get_settings()
        if not settings.guard_enabled:
            raise ProviderConfigurationError("Guard inference is disabled.")

        model_path = self._effective_model_path()
        if not _model_files_present(model_path):
            raise ProviderConfigurationError(
                f"{self.name} model files are missing.",
            )

        text = _request_text(request)
        if not text:
            raise ProviderExecutionError(
                f"{self.name} request contains no text to classify.",
            )

        return classify_prompt_guard(
            text,
            model_path=str(model_path),
            threshold=settings.guard_threshold,
        )

    async def execute(self, request: Any) -> dict[str, Any]:
        classification = await asyncio.to_thread(
            self.classify,
            request,
        )

        return {
            "provider": self.name,
            "model": _GUARD_DEFAULT_MODEL,
            "output_text": _format_classification(classification),
            "finish_reason": "classified",
            "usage": {},
            "raw_response": classification.to_dict(),
        }


GuardSkillAdapter = GuardAdapter


def adaptguardrequest(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Guard request payload must be a JSON object.")
    return dict(payload)


def adaptguardresponse(response: Any) -> dict[str, Any]:
    if hasattr(response, "model_dump") and callable(response.model_dump):
        dumped = response.model_dump(mode="json")
        if isinstance(dumped, dict):
            return dumped
    if hasattr(response, "to_dict") and callable(response.to_dict):
        dumped = response.to_dict()
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
    "GuardAdapter",
    "GuardSkillAdapter",
    "adaptguardrequest",
    "adaptguardresponse",
]
