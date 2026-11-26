"""IronClaw isolated return scanner."""

from __future__ import annotations

from functools import lru_cache
import json
import math
import os
from pathlib import Path
import re
import sys
from typing import Any
import unicodedata

MAX_INPUT_BYTES = 2_097_152
RULES_PATH = Path(__file__).with_name("security_rules.json")
POLICY_PATH = Path(__file__).with_name("policy_snapshot.json")
MODEL_PATH = Path(
    os.environ.get(
        "IRONCLAW_PROMPT_GUARD_PATH",
        "/opt/ironclaw/models/prompt-guard-86m",
    )
)

ZERO_WIDTH_RE = re.compile(r"[\u200B-\u200D\uFEFF\u2060-\u2069]")
CONTROL_RE = re.compile(r"[\u0000-\u001F\u007F-\u009F]")

SECRET_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("aws_access_key", "credential", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", "credential", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("openai_key", "credential", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("anthropic_key", "credential", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("slack_token", "credential", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("bearer_token", "credential", re.compile(r"\bBearer\s+[A-Za-z0-9._~-]{16,}", re.IGNORECASE)),
    ("jwt", "credential", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key", "credential", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("database_url", "credential", re.compile(r"\b(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^\s\"']+", re.IGNORECASE)),
)

NETWORK_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("cloud_metadata", "network", re.compile(r"(169\.254\.169\.254|169\.254\.170\.2|100\.100\.100\.200|fd00:ec2::254|metadata\.google\.internal)", re.IGNORECASE)),
    ("local_network", "network", re.compile(r"(127\.0\.0\.1|localhost|0\.0\.0\.0|host\.docker\.internal|\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b)", re.IGNORECASE)),
    ("unsafe_scheme", "network", re.compile(r"(file://|gopher://|dict://|tftp://|ldap://|smb://)", re.IGNORECASE)),
)

FILE_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    ("private_key_path", "file", re.compile(r"(\.ssh[/\\]|authorized_keys|id_rsa|id_ed25519)", re.IGNORECASE)),
    ("cloud_credentials", "file", re.compile(r"(\.aws[/\\]credentials|\.config[/\\]gcloud|\.azure[/\\]|kubeconfig)", re.IGNORECASE)),
    ("sensitive_system_path", "file", re.compile(r"(/etc/(passwd|shadow)|/proc/|/root/|[A-Z]:\\Windows\\System32\\config\\SAM)", re.IGNORECASE)),
    ("suspicious_extension", "file", re.compile(r"\.(exe|dll|scr|ps1|bat|cmd|hta|vbs|msi|jar)(?:\b|\s)", re.IGNORECASE)),
)


def _normalize(text: str) -> str:
    normalized = unicodedata.normalize("NFKC", text)
    normalized = ZERO_WIDTH_RE.sub("", normalized)
    normalized = CONTROL_RE.sub(" ", normalized)
    return re.sub(r"\s+", " ", normalized).strip()


def _collect_strings(value: Any, output: list[str]) -> None:
    if isinstance(value, str):
        output.append(value)
    elif isinstance(value, dict):
        for key, item in value.items():
            output.append(str(key))
            _collect_strings(item, output)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _collect_strings(item, output)


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RuntimeError(f"missing_security_snapshot:{path.name}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise RuntimeError(f"invalid_security_snapshot:{path.name}") from exc
    if not isinstance(data, dict):
        raise RuntimeError(f"invalid_security_snapshot:{path.name}")
    return data


@lru_cache(maxsize=1)
def _load_policy() -> dict[str, Any]:
    return _load_json(POLICY_PATH)


@lru_cache(maxsize=1)
def _load_rules() -> tuple[tuple[str, str, str, re.Pattern[str]], ...]:
    data = _load_json(RULES_PATH)
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RuntimeError("invalid_security_rule_library")

    compiled: list[tuple[str, str, str, re.Pattern[str]]] = []
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            raise RuntimeError("invalid_security_rule")
        code = raw_rule.get("code")
        category = raw_rule.get("category")
        severity = raw_rule.get("severity")
        pattern = raw_rule.get("pattern")
        if not isinstance(code, str) or not isinstance(category, str) or severity not in {"low", "medium", "high", "critical"} or not isinstance(pattern, str):
            raise RuntimeError("invalid_security_rule")
        try:
            compiled.append((code, category, severity, re.compile(pattern, re.IGNORECASE | re.DOTALL)))
        except re.error as exc:
            raise RuntimeError("invalid_security_rule_pattern") from exc
    return tuple(compiled)


@lru_cache(maxsize=1)
def _load_prompt_guard() -> tuple[Any, Any, Any]:
    if not MODEL_PATH.is_dir():
        raise RuntimeError("prompt_guard_model_missing")
    try:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        tokenizer = AutoTokenizer.from_pretrained(
            str(MODEL_PATH),
            local_files_only=True,
        )
        model = AutoModelForSequenceClassification.from_pretrained(
            str(MODEL_PATH),
            local_files_only=True,
        )
        model.eval()
        return torch, tokenizer, model
    except Exception as exc:
        raise RuntimeError("prompt_guard_unavailable") from exc


def _prompt_guard_result(text: str) -> dict[str, Any]:
    torch, tokenizer, model = _load_prompt_guard()
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
    malicious_index = next(
        (int(index) for index, label in labels.items() if "malicious" in str(label).casefold()),
        1,
    )

    maximum_score = 0.0
    for index in range(encoded["input_ids"].shape[0]):
        model_inputs = {key: encoded[key][index : index + 1] for key in tokenizer.model_input_names if key in encoded}
        with torch.inference_mode():
            logits = model(**model_inputs).logits[0]
            probabilities = torch.softmax(logits, dim=-1)
        if malicious_index >= probabilities.shape[-1]:
            raise RuntimeError("prompt_guard_invalid_output")
        maximum_score = max(
            maximum_score,
            float(probabilities[malicious_index].item()),
        )

    if not math.isfinite(maximum_score) or not 0.0 <= maximum_score <= 1.0:
        raise RuntimeError("prompt_guard_invalid_output")
    policy = _load_policy()
    threshold = policy.get("prompt_guard_threshold", 0.5)
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
        raise RuntimeError("invalid_prompt_guard_policy")
    threshold = float(threshold)
    if not math.isfinite(threshold) or not 0.0 <= threshold <= 1.0:
        raise RuntimeError("invalid_prompt_guard_policy")

    return {
        "score": maximum_score,
        "label": "MALICIOUS" if maximum_score >= threshold else "BENIGN",
        "model_name": "prompt-guard-86m",
        "threshold": threshold,
    }


def _reason(
    code: str,
    category: str,
    severity: str,
    detail: str,
) -> dict[str, str | int]:
    return {
        "code": code,
        "category": category,
        "severity": severity,
        "detail": detail,
        "risk_delta": {
            "low": 10,
            "medium": 25,
            "high": 45,
            "critical": 70,
        }[severity],
    }


def _block(
    reason: str,
    reasons: list[dict[str, str | int]] | None = None,
    risk_score: int = 100,
) -> dict[str, Any]:
    return {
        "verdict": "block",
        "status": "blocked",
        "executor": "docker",
        "reason": reason,
        "reasons": reasons or [{"code": reason, "category": "security", "severity": "critical", "detail": reason, "risk_delta": 70}],
        "risk_score": max(risk_score, 70),
        "untrusted": True,
        "released_text": None,
    }


def _allow(released_text: str, reasons: list[dict[str, str | int]] | None = None) -> dict[str, Any]:
    return {
        "verdict": "allow",
        "status": "completed",
        "executor": "docker",
        "reason": "clean",
        "reasons": reasons or [],
        "risk_score": 0,
        "untrusted": False,
        "released_text": released_text,
    }


def evaluate(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_INPUT_BYTES:
        return _block("input_too_large")
    try:
        text = raw.decode("utf-8")
        request = json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return _block("invalid_request")
    if not isinstance(request, dict):
        return _block("invalid_request")

    payload = request.get("payload")
    if payload is None:
        payload = request
    if not isinstance(payload, dict):
        return _block("invalid_request")

    strings: list[str] = []
    _collect_strings(payload, strings)
    haystack = _normalize("\n".join([text, *strings]))
    if not haystack:
        return _block("empty_scan_payload")

    reasons: list[dict[str, str | int]] = []
    risk_score = 0

    try:
        policy = _load_policy()
        rules = _load_rules()
        block_threshold = policy.get("block_threshold", 70)
        if isinstance(block_threshold, bool) or not isinstance(block_threshold, int):
            raise RuntimeError("invalid_security_policy")
        if not 1 <= block_threshold <= 100:
            raise RuntimeError("invalid_security_policy")
    except Exception:
        return _block("security_snapshot_unavailable")

    for code, category, severity, pattern in rules:
        if pattern.search(haystack):
            detail = f"Matched isolated security rule {code}"
            finding = _reason(code, category, severity, detail)
            reasons.append(finding)
            risk_score = max(risk_score, int(finding["risk_delta"]))

    for code, category, pattern in SECRET_PATTERNS:
        if pattern.search(haystack):
            finding = _reason(code, category, "critical", f"Detected {code} in the isolated return")
            reasons.append(finding)
            risk_score = max(risk_score, int(finding["risk_delta"]))

    for code, category, pattern in NETWORK_PATTERNS:
        if pattern.search(haystack):
            severity = "critical" if code in {"cloud_metadata", "unsafe_scheme"} else "high"
            finding = _reason(code, category, severity, f"Detected {code} in the isolated return")
            reasons.append(finding)
            risk_score = max(risk_score, int(finding["risk_delta"]))

    for code, category, pattern in FILE_PATTERNS:
        if pattern.search(haystack):
            finding = _reason(code, category, "high", f"Detected {code} in the isolated return")
            reasons.append(finding)
            risk_score = max(risk_score, int(finding["risk_delta"]))

    if reasons:
        return _block(
            str(reasons[0]["code"]) if reasons else "suspicious_content",
            reasons,
            risk_score,
        )

    try:
        prompt_guard = _prompt_guard_result(haystack)
    except Exception:
        return _block(
            "prompt_guard_unavailable",
            [
                _reason(
                    "prompt_guard_unavailable",
                    "prompt_guard",
                    "critical",
                    "Prompt Guard 2 could not classify the isolated return",
                )
            ],
        )

    if prompt_guard["label"] == "MALICIOUS":
        score = float(prompt_guard["score"])
        reasons.append(
            _reason(
                "prompt_guard_malicious",
                "prompt_injection",
                "critical",
                f"Prompt Guard 2 classified the return as MALICIOUS (score={score:.4f})",
            )
        )
        risk_score = max(risk_score, 100)

    if reasons:
        return _block(
            str(reasons[0]["code"]) if reasons else "suspicious_content",
            reasons,
            risk_score,
        )
    released_text = payload.get("content")
    if not isinstance(released_text, str):
        released_text = ""
    return _allow(released_text=released_text)


def main() -> int:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    sys.stdout.write(json.dumps(evaluate(raw), ensure_ascii=False, separators=(",", ":")))
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
