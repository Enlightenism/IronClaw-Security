import json
import sys
from urllib import request

IRONCLAW_SCAN_URL = "http://127.0.0.1:8000/scan/"
IRONCLAW_POLICY_URL = "http://127.0.0.1:8000/policy/guard-bundle"


def read_stdin():
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except Exception:
        return {"raw_input": raw}


def extract_text(payload):
    parts = []

    if isinstance(payload, dict):
        session_id = payload.get("session_id")
        if session_id:
            parts.append(f"session_id={session_id}")

        prompt = payload.get("prompt")
        if isinstance(prompt, str):
            parts.append(prompt)

        tool_name = payload.get("tool_name")
        if isinstance(tool_name, str):
            parts.append(f"tool_name={tool_name}")

        tool_input = payload.get("tool_input")
        if isinstance(tool_input, dict | list):
            parts.append(json.dumps(tool_input, ensure_ascii=False))
        elif isinstance(tool_input, str):
            parts.append(tool_input)

        for key in ("raw_input", "input", "query", "command"):
            value = payload.get(key)
            if isinstance(value, str):
                parts.append(value)

    return "\n".join(parts).strip()


def build_prompt_bundle(payload):
    """Build a minimal prompt bundle from the hook payload.

    We keep this conservative:
    - user_prompt: main user message / prompt
    - retrieved_doc: reserved (unused here, but kept for structure)
    - tool_output: any prior tool result if available
    - model_output: not available at this stage, so None
    """
    user_prompt = None
    retrieved_doc = None
    tool_output = None
    model_output = None

    if isinstance(payload, dict):
        # Primary user text
        if isinstance(payload.get("prompt"), str):
            user_prompt = payload["prompt"]
        elif isinstance(payload.get("input"), str):
            user_prompt = payload["input"]
        elif isinstance(payload.get("query"), str):
            user_prompt = payload["query"]
        elif isinstance(payload.get("command"), str):
            user_prompt = payload["command"]

        # Tool output, if present in a generic field
        if isinstance(payload.get("tool_output"), str):
            tool_output = payload["tool_output"]
        elif isinstance(payload.get("previous_response"), str):
            tool_output = payload["previous_response"]

        # retrieved_doc left as None in this generic hook

    bundle = {}
    if user_prompt is not None:
        bundle["user_prompt"] = user_prompt
    if retrieved_doc is not None:
        bundle["retrieved_doc"] = retrieved_doc
    if tool_output is not None:
        bundle["tool_output"] = tool_output
    if model_output is not None:
        bundle["model_output"] = model_output

    return bundle


def http_post_json(url, payload, timeout=5):
    body = json.dumps(payload).encode("utf-8")
    req = request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def policy_guard_bundle(bundle):
    """Call /policy/guard-bundle with the constructed bundle."""
    if not bundle:
        raise ValueError("Cannot evaluate an empty policy bundle.")

    return http_post_json(IRONCLAW_POLICY_URL, bundle)


def scan_text(text):
    """Legacy single-text scan, kept as a fallback."""
    payload = {"target_type": "text", "target_value": text}
    return http_post_json(IRONCLAW_SCAN_URL, payload)


def main():
    payload = read_stdin()
    text = extract_text(payload)

    # First try the bundle-based guard
    try:
        bundle = build_prompt_bundle(payload)
        if not bundle:
            raise ValueError("No scannable prompt bundle was produced.")
        policy_result = policy_guard_bundle(bundle)
    except Exception as e:
        try:
            result = scan_text(text or "")
        except Exception as scan_err:
            print(
                json.dumps(
                    {
                        "continue": False,
                        "suppressOutput": False,
                        "stopReason": f"IronClaw unavailable: {e}; fallback scan error: {scan_err}",
                    }
                )
            )
            return
        if not isinstance(result, dict):
            print(
                json.dumps(
                    {
                        "continue": False,
                        "suppressOutput": False,
                        "stopReason": "IronClaw fallback scan returned an invalid response; blocked by policy.",
                    }
                )
            )
            return

        verdict = result.get("verdict")
        summary = result.get("summary", "")
        matched = result.get("matched_patterns") or []
        has_errors = bool(result.get("error") or result.get("errors") or result.get("failed_checks"))
        if verdict != "allow" or matched or has_errors:
            print(
                json.dumps(
                    {
                        "continue": False,
                        "suppressOutput": False,
                        "stopReason": f"IronClaw blocked this action. {summary} Matched: {matched}",
                    }
                )
            )
            return
        print(
            json.dumps(
                {
                    "continue": True,
                    "suppressOutput": False,
                    "decision_reason": f"IronClaw explicitly allowed this action. {summary}",
                }
            )
        )
        return

    if not isinstance(policy_result, dict):
        print(
            json.dumps(
                {
                    "continue": False,
                    "suppressOutput": False,
                    "stopReason": "IronClaw policy returned an invalid response; blocked by policy.",
                }
            )
        )
        return

    highest_verdict = policy_result.get("highest_verdict")
    should_halt = policy_result.get("should_halt", True)
    should_warn = policy_result.get("should_warn", True)
    has_errors = bool(policy_result.get("error") or policy_result.get("errors") or policy_result.get("failed_checks"))

    # Try to surface the most relevant summary
    user_ctx = policy_result.get("user_prompt") or {}
    model_ctx = policy_result.get("model_output") or {}
    summary = user_ctx.get("summary") or model_ctx.get("summary") or f"Bundle verdict={highest_verdict}"

    if highest_verdict != "allow" or should_halt is not False or should_warn is not False or has_errors:
        print(
            json.dumps(
                {
                    "continue": False,
                    "suppressOutput": False,
                    "stopReason": f"IronClaw policy halted bundle. {summary}",
                }
            )
        )
        return

    decision_reason = f"IronClaw bundle verdict={highest_verdict}. {summary}"

    print(
        json.dumps(
            {
                "continue": True,
                "suppressOutput": False,
                "decision_reason": decision_reason,
            }
        )
    )


if __name__ == "__main__":
    main()
