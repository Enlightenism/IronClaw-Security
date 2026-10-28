from typing import Literal, TypedDict

from app.services.guard import guard_text

ContextType = Literal["user_prompt", "retrieved_doc", "tool_output", "model_output"]
VerdictType = Literal["allow", "block"]


class GuardedText(TypedDict):
    context_type: ContextType
    verdict: VerdictType
    scan_id: str | None
    summary: str
    risk_score: int
    matched_patterns: list[str]
    original_text: str
    effective_text: str
    should_halt: bool
    should_warn: Literal[False]
    client_id: str | None
    session_id: str | None


class PromptGuardBundle(TypedDict):
    user_prompt: GuardedText | None
    retrieved_doc: GuardedText | None
    tool_output: GuardedText | None
    model_output: GuardedText | None
    highest_verdict: VerdictType
    should_halt: bool
    should_warn: Literal[False]
    client_id: str | None
    session_id: str | None


def _verdict_rank(verdict: VerdictType) -> int:
    order: dict[VerdictType, int] = {
        "allow": 0,
        "block": 1,
    }
    return order[verdict]


def analyze_text(
    context_type: ContextType,
    text: str,
    client_id: str | None = None,
    session_id: str | None = None,
) -> GuardedText:
    """Run the Ironclaw scan for the given context and return a structured
    decision the agent / UI can act on.

    Allow proceeds normally. A block must halt execution; effective_text stays
    equal to the original so the caller can decide how to replace or redact it.
    should_warn is always false.
    """
    decision = guard_text(context_type, text)
    verdict = decision["verdict"]

    should_halt = verdict == "block"
    should_warn: Literal[False] = False

    return {
        "context_type": context_type,
        "verdict": verdict,
        "scan_id": decision.get("scan_id"),
        "summary": decision["summary"],
        "risk_score": decision["risk_score"],
        "matched_patterns": decision["matched_patterns"],
        "original_text": text,
        "effective_text": text,
        "should_halt": should_halt,
        "should_warn": should_warn,
        "client_id": client_id,
        "session_id": session_id,
    }


def analyze_prompt_bundle(
    user_prompt: str | None = None,
    retrieved_doc: str | None = None,
    tool_output: str | None = None,
    model_output: str | None = None,
    client_id: str | None = None,
    session_id: str | None = None,
) -> PromptGuardBundle:
    """Guard multiple text sources that may participate in one agent turn.

    This is useful for internal routing where you want one consolidated
    decision across:
    - the user prompt,
    - retrieved documents,
    - tool output,
    - and model output.

    highest_verdict is chosen using this precedence:
        allow < block

    Bundle-level should_halt is true only for block; should_warn is always false.
    """
    guarded_user_prompt = analyze_text("user_prompt", user_prompt, client_id=client_id, session_id=session_id) if user_prompt is not None else None
    guarded_retrieved_doc = analyze_text("retrieved_doc", retrieved_doc, client_id=client_id, session_id=session_id) if retrieved_doc is not None else None
    guarded_tool_output = analyze_text("tool_output", tool_output, client_id=client_id, session_id=session_id) if tool_output is not None else None
    guarded_model_output = analyze_text("model_output", model_output, client_id=client_id, session_id=session_id) if model_output is not None else None

    results: list[GuardedText] = [
        item
        for item in (
            guarded_user_prompt,
            guarded_retrieved_doc,
            guarded_tool_output,
            guarded_model_output,
        )
        if item is not None
    ]

    if not results:
        highest_verdict: VerdictType = "allow"
    else:
        highest_verdict = max(
            (item["verdict"] for item in results),
            key=_verdict_rank,
        )

    should_warn: Literal[False] = False
    return {
        "user_prompt": guarded_user_prompt,
        "retrieved_doc": guarded_retrieved_doc,
        "tool_output": guarded_tool_output,
        "model_output": guarded_model_output,
        "highest_verdict": highest_verdict,
        "should_halt": highest_verdict == "block",
        "should_warn": should_warn,
        "client_id": client_id,
        "session_id": session_id,
    }
