from __future__ import annotations

from dataclasses import dataclass

from app.core.settings import get_settings
from app.services.prompt_guard import PromptGuardResult, classify_prompt_guard


@dataclass(frozen=True, slots=True)
class PromptGuardClient:
    enabled: bool
    model_path: str
    threshold: float

    @classmethod
    def default(cls) -> PromptGuardClient:
        settings = get_settings()
        return cls(
            enabled=settings.guard_enabled,
            model_path=settings.guard_model_path,
            threshold=settings.guard_threshold,
        )

    def classify(self, text: str) -> PromptGuardResult | None:
        if not self.enabled or not text.strip():
            return None
        return classify_prompt_guard(
            text,
            model_path=self.model_path,
            threshold=self.threshold,
        )
