from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

PromptGuardLabel = Literal["BENIGN", "MALICIOUS"]


@dataclass(frozen=True, slots=True)
class PromptGuardResult:
    label: PromptGuardLabel
    malicious_score: float
    model_name: str

    @property
    def is_malicious(self) -> bool:
        return self.label == "MALICIOUS"

    def to_dict(self) -> dict[str, str | float]:
        return {
            "status": "classified",
            "label": self.label,
            "malicious_score": self.malicious_score,
            "model_name": self.model_name,
        }


def resolve_prompt_guard_path(model_path: str) -> Path:
    path = Path(model_path).expanduser()
    if not path.is_absolute():
        path = Path(__file__).resolve().parents[2] / path
    return path.resolve()


def classify_prompt_guard(
    text: str,
    *,
    model_path: str,
    threshold: float,
) -> PromptGuardResult:
    if not text.strip():
        raise ValueError("text must contain non-whitespace characters")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("GUARD_THRESHOLD must be between 0.0 and 1.0")

    score = _score_prompt_guard(text, model_path=model_path)
    label: PromptGuardLabel = "MALICIOUS" if score >= threshold else "BENIGN"
    return PromptGuardResult(
        label=label,
        malicious_score=score,
        model_name=resolve_prompt_guard_path(model_path).name,
    )


@lru_cache(maxsize=1)
def _load_prompt_guard(model_path: str) -> tuple[Any, Any, Any]:
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer

    path = resolve_prompt_guard_path(model_path)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        path,
        local_files_only=True,
    )
    model.eval()
    return torch, tokenizer, model


def _score_prompt_guard(text: str, *, model_path: str) -> float:
    torch, tokenizer, model = _load_prompt_guard(model_path)
    encoded = tokenizer(
        [text],
        truncation=True,
        max_length=512,
        stride=64,
        return_overflowing_tokens=True,
        padding="max_length",
        return_tensors="pt",
    )

    labels = getattr(model.config, "id2label", {}) or {}
    # The Prompt Guard 2 binary checkpoint uses class 1 for malicious if labels are absent.
    malicious_class_index = next(
        (int(class_index) for class_index, label in labels.items() if "malicious" in str(label).casefold()),
        1,
    )

    maximum_score = 0.0
    for chunk_index in range(encoded["input_ids"].shape[0]):
        model_inputs = {key: encoded[key][chunk_index : chunk_index + 1] for key in tokenizer.model_input_names if key in encoded}
        with torch.inference_mode():
            logits = model(**model_inputs).logits[0]
            probabilities = torch.softmax(logits, dim=-1)
        if malicious_class_index >= probabilities.shape[-1]:
            raise ValueError("Prompt-guard model has no malicious classification output.")
        maximum_score = max(
            maximum_score,
            float(probabilities[malicious_class_index].item()),
        )

    return maximum_score
