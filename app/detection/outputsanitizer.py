from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import re
from typing import Any, Callable, Iterable


SECRET_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "openai_api_key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        0.42,
    ),
    (
        "github_pat",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
        0.44,
    ),
    (
        "aws_access_key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        0.40,
    ),
    (
        "slack_token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        0.36,
    ),
    (
        "jwt_token",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}\b"),
        0.28,
    ),
    (
        "bearer_token",
        re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{16,}\b", re.IGNORECASE),
        0.24,
    ),
    (
        "private_key_block",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"
        ),
        0.60,
    ),
]


COMMAND_PATTERNS: list[tuple[str, re.Pattern[str], str, float]] = [
    (
        "powershell_download_execute",
        re.compile(
            r"(invoke-webrequest|iwr|curl)\b[\s\S]{0,120}(iex|invoke-expression|powershell\s+-enc)",
            re.IGNORECASE,
        ),
        "block",
        0.48,
    ),
    (
        "shell_pipe_to_sh",
        re.compile(r"(curl|wget)\b[\s\S]{0,80}\|\s*(sh|bash)\b", re.IGNORECASE),
        "block",
        0.52,
    ),
    (
        "dangerous_rm_rf",
        re.compile(
            r"\brm\s+-rf\s+/(?:\s|$)|\bdel\s+/f\s+/s\s+/q\b",
            re.IGNORECASE,
        ),
        "block",
        0.58,
    ),
    (
        "encoded_powershell",
        re.compile(
            r"powershell(?:\.exe)?\s+-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{20,}",
            re.IGNORECASE,
        ),
        "block",
        0.50,
    ),
    (
        "credential_exfiltration",
        re.compile(
            r"(upload|post|send).{0,80}(token|secret|credential|password)",
            re.IGNORECASE,
        ),
        "review",
        0.24,
    ),
]


PROMPT_LEAK_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "system_prompt_leak",
        re.compile(
            r"\b(system prompt|hidden instructions|developer message|chain of thought)\b",
            re.IGNORECASE,
        ),
        0.18,
    ),
    (
        "policy_bypass_guidance",
        re.compile(
            r"\b(ignore previous instructions|disable guardrails|bypass policy|override safety)\b",
            re.IGNORECASE,
        ),
        0.34,
    ),
    (
        "tool_schema_exposure",
        re.compile(
            r"\b(api key|secret key|internal endpoint|private repo|sandbox token)\b",
            re.IGNORECASE,
        ),
        0.20,
    ),
]


PATH_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "unix_sensitive_path",
        re.compile(
            r"\b/(?:etc/passwd|etc/shadow|root/\.ssh|home/[^/\s]+/\.ssh/[^\s]+)\b"
        ),
        0.26,
    ),
    (
        "windows_sensitive_path",
        re.compile(
            r"\b[A-Za-z]:\\(?:Users\\[^\\]+\\\.ssh\\|Windows\\System32\\config\\SAM)\b"
        ),
        0.26,
    ),
]


@dataclass(slots=True)
class SanitizerSignal:
    name: str
    weight: float
    evidence: str
    category: str


@dataclass(slots=True)
class SanitizationAction:
    kind: str
    start: int | None = None
    end: int | None = None
    replacement: str | None = None
    detail: str | None = None


@dataclass(slots=True)
class OutputSanitizationResult:
    original_text: str
    sanitized_text: str
    verdict: str
    severity: str
    score: float
    confidence: float
    reasons: list[str]
    signals: list[SanitizerSignal]
    actions: list[SanitizationAction]
    blocked: bool
    sanitized: bool
    analyzed_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def as_dict(self) -> dict[str, Any]:
        return {
            "original_text": self.original_text,
            "sanitized_text": self.sanitized_text,
            "verdict": self.verdict,
            "severity": self.severity,
            "score": float(self.score),
            "confidence": float(self.confidence),
            "reasons": list(self.reasons),
            "signals": [
                {
                    "name": signal.name,
                    "weight": float(signal.weight),
                    "evidence": signal.evidence,
                    "category": signal.category,
                }
                for signal in self.signals
            ],
            "actions": [
                {
                    "kind": action.kind,
                    "start": action.start,
                    "end": action.end,
                    "replacement": action.replacement,
                    "detail": action.detail,
                }
                for action in self.actions
            ],
            "blocked": bool(self.blocked),
            "sanitized": bool(self.sanitized),
            "analyzed_at": self.analyzed_at,
        }


class OutputSanitizer:
    def sanitize(
        self,
        text: str,
        *,
        context: str | None = None,
        redact_secrets: bool = True,
        block_unsafe_commands: bool = True,
    ) -> OutputSanitizationResult:
        working = text or ""
        signals: list[SanitizerSignal] = []
        actions: list[SanitizationAction] = []

        if redact_secrets and working:
            working, secret_signals, secret_actions = self._redact_by_patterns(
                working,
                SECRET_PATTERNS,
                replacement_builder=lambda name: f"[REDACTED_{name.upper()}]",
                category="secret",
            )
            signals.extend(secret_signals)
            actions.extend(secret_actions)

        if working:
            working, path_signals, path_actions = self._redact_by_patterns(
                working,
                PATH_PATTERNS,
                replacement_builder=lambda _name: "[REDACTED_PATH]",
                category="path",
            )
            signals.extend(path_signals)
            actions.extend(path_actions)

        if working:
            command_signals, command_actions = self._scan_commands(
                working,
                block_unsafe_commands=block_unsafe_commands,
            )
            signals.extend(command_signals)
            actions.extend(command_actions)

        if working:
            leak_signals = self._scan_prompt_leaks(working, context=context)
            signals.extend(leak_signals)

        deduped_signals = self._dedupe_signals(signals)
        score = self._resolve_score(deduped_signals)
        severity = self._resolve_severity(score)
        verdict = self._resolve_verdict(
            deduped_signals,
            score,
            block_unsafe_commands=block_unsafe_commands,
        )
        blocked = verdict == "block"

        if blocked:
            blocked_message = self._blocked_message(deduped_signals)
            working = blocked_message
            actions.append(
                SanitizationAction(
                    kind="replace_all",
                    start=0,
                    end=len(blocked_message),
                    replacement=blocked_message,
                    detail="Replaced entire output because blocking indicators were present.",
                )
            )

        sanitized = working != text
        confidence = self._resolve_confidence(
            deduped_signals,
            sanitized=sanitized,
            blocked=blocked,
        )
        reasons = self._build_reasons(
            signals=deduped_signals,
            verdict=verdict,
            severity=severity,
            context=context,
            sanitized=sanitized,
            blocked=blocked,
        )

        return OutputSanitizationResult(
            original_text=text,
            sanitized_text=working,
            verdict=verdict,
            severity=severity,
            score=score,
            confidence=confidence,
            reasons=reasons,
            signals=deduped_signals,
            actions=actions,
            blocked=blocked,
            sanitized=sanitized,
        )

    def _redact_by_patterns(
        self,
        text: str,
        pattern_specs: Iterable[tuple[str, re.Pattern[str], float]],
        *,
        replacement_builder: Callable[[str], str],
        category: str,
    ) -> tuple[str, list[SanitizerSignal], list[SanitizationAction]]:
        updated = text
        signals: list[SanitizerSignal] = []
        actions: list[SanitizationAction] = []

        for name, pattern, weight in pattern_specs:
            search_offset = 0
            replacement_label = replacement_builder(name)
            while True:
                match = pattern.search(updated, search_offset)
                if not match:
                    break

                matched_value = match.group(0)
                start, end = match.span()
                updated = f"{updated[:start]}{replacement_label}{updated[end:]}"
                search_offset = start + len(replacement_label)

                signals.append(
                    SanitizerSignal(
                        name=name,
                        weight=float(weight),
                        evidence=self._clip_evidence(matched_value),
                        category=category,
                    )
                )
                actions.append(
                    SanitizationAction(
                        kind="redact",
                        start=start,
                        end=start + len(replacement_label),
                        replacement=replacement_label,
                        detail=f"Redacted {name}.",
                    )
                )

        return updated, signals, actions

    def _scan_commands(
        self,
        text: str,
        *,
        block_unsafe_commands: bool,
    ) -> tuple[list[SanitizerSignal], list[SanitizationAction]]:
        signals: list[SanitizerSignal] = []
        actions: list[SanitizationAction] = []

        if not text:
            return signals, actions

        for name, pattern, disposition, weight in COMMAND_PATTERNS:
            for match in pattern.finditer(text):
                evidence = self._clip_evidence(match.group(0))
                adjusted_weight = float(weight) if block_unsafe_commands else float(
                    min(weight, 0.22)
                )
                signals.append(
                    SanitizerSignal(
                        name=name,
                        weight=adjusted_weight,
                        evidence=evidence,
                        category="command",
                    )
                )
                actions.append(
                    SanitizationAction(
                        kind="flag",
                        start=match.start(),
                        end=match.end(),
                        detail=f"Detected command pattern {name} with disposition {disposition}.",
                    )
                )

        return signals, actions

    def _scan_prompt_leaks(
        self,
        text: str,
        *,
        context: str | None,
    ) -> list[SanitizerSignal]:
        signals: list[SanitizerSignal] = []
        if not text:
            return signals

        context_lower = context.lower() if context else ""
        is_prompt_context = "prompt" in context_lower

        for name, pattern, weight in PROMPT_LEAK_PATTERNS:
            for match in pattern.finditer(text):
                adjusted = float(weight)
                if is_prompt_context:
                    adjusted = min(adjusted + 0.06, 0.5)
                signals.append(
                    SanitizerSignal(
                        name=name,
                        weight=adjusted,
                        evidence=self._clip_evidence(match.group(0)),
                        category="policy",
                    )
                )
        return signals

    def _resolve_score(self, signals: list[SanitizerSignal]) -> float:
        if not signals:
            return 0.0
        total = sum(float(signal.weight) for signal in signals)
        if any(signal.name == "private_key_block" for signal in signals):
            total = max(total, 0.92)
        return round(min(total, 1.0), 4)

    def _resolve_severity(self, score: float) -> str:
        if score >= 0.85:
            return "critical"
        if score >= 0.55:
            return "high"
        if score >= 0.25:
            return "medium"
        return "low"

    def _resolve_verdict(
        self,
        signals: list[SanitizerSignal],
        score: float,
        *,
        block_unsafe_commands: bool,
    ) -> str:
        if not signals:
            return "allow"

        names = {signal.name for signal in signals}
        secret_hits = sum(1 for signal in signals if signal.category == "secret")
        command_hits = sum(1 for signal in signals if signal.category == "command")

        if "private_key_block" in names:
            return "block"
        if block_unsafe_commands and command_hits > 0 and score >= 0.48:
            return "block"
        if secret_hits >= 2 or score >= 0.48:
            return "sanitize"
        if score >= 0.18:
            return "review"
        return "allow"

    def _resolve_confidence(
        self,
        signals: list[SanitizerSignal],
        *,
        sanitized: bool,
        blocked: bool,
    ) -> float:
        base = 0.42
        if signals:
            base += min(len(signals) * 0.05, 0.28)
        if sanitized:
            base += 0.10
        if blocked:
            base += 0.12
        return round(min(base, 0.99), 4)

    def _build_reasons(
        self,
        *,
        signals: list[SanitizerSignal],
        verdict: str,
        severity: str,
        context: str | None,
        sanitized: bool,
        blocked: bool,
    ) -> list[str]:
        reasons: list[str] = [
            f"Output sanitation verdict is {verdict} with {severity} severity."
        ]

        if context:
            reasons.append(f"Evaluation context: {context}.")

        if sanitized:
            reasons.append(
                "Sensitive content was redacted or transformed before release."
            )

        if blocked:
            reasons.append("Unsafe output was blocked from leaving the pipeline.")

        if signals:
            for signal in sorted(
                signals,
                key=lambda item: item.weight,
                reverse=True,
            )[:5]:
                reasons.append(f"{signal.name}: {signal.evidence}")

        if len(reasons) == 1:
            reasons.append("No sanitization triggers were detected.")

        return reasons

    def _blocked_message(self, signals: list[SanitizerSignal]) -> str:
        if not signals:
            return "[BLOCKED_OUTPUT] Unsafe output suppressed by OutputSanitizer."
        top_names = [
            signal.name
            for signal in sorted(
                signals,
                key=lambda item: item.weight,
                reverse=True,
            )[:3]
        ]
        joined = ", ".join(top_names)
        return f"[BLOCKED_OUTPUT] Unsafe output suppressed by OutputSanitizer due to: {joined}"

    def _clip_evidence(self, value: str, limit: int = 120) -> str:
        compact = " ".join(value.split())
        if len(compact) <= limit:
            return compact
        return compact[: limit - 3] + "..."

    def _dedupe_signals(self, signals: list[SanitizerSignal]) -> list[SanitizerSignal]:
        deduped: list[SanitizerSignal] = []
        seen: set[tuple[str, str, str]] = set()
        for signal in signals:
            key = (signal.name, signal.category, signal.evidence)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(signal)
        return deduped


def build_output_sanitizer() -> OutputSanitizer:
    return OutputSanitizer()


__all__ = [
    "SanitizerSignal",
    "SanitizationAction",
    "OutputSanitizationResult",
    "OutputSanitizer",
    "build_output_sanitizer",
]