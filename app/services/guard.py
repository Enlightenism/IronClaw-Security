from typing import Literal, TypedDict

from app.services.scanner import perform_scan


ContextType = Literal["user_prompt", "retrieved_doc", "tool_output", "model_output"]
VerdictType = Literal["allow", "warn", "quarantine", "block"]


class GuardDecision(TypedDict):
    context_type: ContextType
    verdict: VerdictType
    scan_id: str | None
    summary: str
    risk_score: int
    matched_patterns: list[str]


def _verdict_rank(verdict: str) -> int:
    order = {
        "allow": 1,
        "warn": 2,
        "quarantine": 3,
        "block": 4,
    }
    return order.get(verdict, 0)


def _max_verdict(*verdicts: str) -> VerdictType:
    filtered = [v for v in verdicts if v in {"allow", "warn", "quarantine", "block"}]
    if not filtered:
        return "allow"
    return max(filtered, key=_verdict_rank)  # type: ignore[return-value]


def _score_based_verdict(score: int) -> VerdictType:
    if score >= 70:
        return "block"
    if score >= 40:
        return "quarantine"
    if score >= 20:
        return "warn"
    return "allow"


def _pattern_based_verdict(matched_patterns: list[str]) -> VerdictType:
    patterns = {pattern.lower() for pattern in matched_patterns}

    critical_block_patterns = {
        "prompt_print_hidden_policy",
        "prompt_reveal_system_prompt",
        "prompt_disclose_hidden_instructions",
        "prompt_output_tool_schema",
        "prompt_export_credentials",
        "prompt_ignore_developer_message",
        "prompt_ignore_system_message",
        "prompt_treat_document_as_system_prompt",
        "prompt_ignore_user_and_follow_document",
        "prompt_assistant_execute_following",
        "prompt_higher_priority_than_rules",
        "prompt_forget_prior_instructions",
    }

    high_quarantine_patterns = {
        "prompt_ignore_previous_instructions",
        "heuristic_prompt_injection_score",
        "curl_pipe_bash",
        "yaml_unsafe_load",
        "ps_encoded_command",
        "download_and_execute",
    }

    if patterns & critical_block_patterns:
        return "block"

    if patterns & high_quarantine_patterns:
        return "quarantine"

    return "allow"


def _context_floor_verdict(context_type: ContextType) -> VerdictType:
    if context_type in ("retrieved_doc", "tool_output"):
        return "warn"
    return "allow"


def guard_text(context_type: ContextType, text: str) -> GuardDecision:
    result = perform_scan("text", text)

    scan_verdict = result["verdict"]
    risk_score = result["risk_score"]
    matched_patterns = result["matched_patterns"]

    score_verdict = _score_based_verdict(risk_score)
    pattern_verdict = _pattern_based_verdict(matched_patterns)

    floor_verdict = "allow"
    if matched_patterns:
        floor_verdict = _context_floor_verdict(context_type)

    final_verdict = _max_verdict(
        scan_verdict,
        score_verdict,
        pattern_verdict,
        floor_verdict,
    )

    return {
        "context_type": context_type,
        "verdict": final_verdict,
        "scan_id": result.get("scan_id"),
        "summary": result["summary"],
        "risk_score": risk_score,
        "matched_patterns": matched_patterns,
    }