from __future__ import annotations

import argparse
import json
import sys
from typing import Any
import uuid

import requests

API_BASE = "http://127.0.0.1:8011"


def call_brain_decision(
    *,
    target_type: str,
    target_value: str,
    mode: str = "enforce",
    source: str | None = "cli",
    session_id: str | None = None,
    user_id: str | None = None,
    context: str | None = None,
    use_history: bool = True,
    max_history: int = 20,
    timeout: int = 10,
) -> dict[str, Any]:
    payload = {
        "target_type": target_type,
        "target_value": target_value,
        "mode": mode,
        "source": source,
        "session_id": session_id,
        "user_id": user_id,
        "context": context,
        "use_history": use_history,
        "max_history": max_history,
    }

    resp = requests.post(f"{API_BASE}/brain/decision", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="IronClaw-Security brain CLI — scan text and get a security decision.",
    )
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument(
        "--text",
        type=str,
        help="Raw text to scan.",
    )
    src.add_argument(
        "--file",
        type=str,
        help="Path to a text file to scan.",
    )

    parser.add_argument(
        "--target-type",
        type=str,
        default="text",
        choices=["text"],
        help="Target type. Currently only 'text' is supported in this CLI.",
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="enforce",
        choices=["enforce", "monitor", "strict"],
        help="Policy mode for the scan.",
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Optional session/conversation ID. If omitted, a random one is generated for this run.",
    )
    parser.add_argument(
        "--user-id",
        type=str,
        default=None,
        help="Optional user ID.",
    )
    parser.add_argument(
        "--context",
        type=str,
        default="cli invocation",
        help="Short description of the context for this scan.",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Disable history-based reasoning for this decision.",
    )
    parser.add_argument(
        "--max-history",
        type=int,
        default=20,
        help="Maximum number of related history items to consider.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print full JSON response instead of a one-line summary.",
    )

    args = parser.parse_args()

    if args.text is not None:
        target_value = args.text
    else:
        try:
            with open(args.file, encoding="utf-8") as f:
                target_value = f.read()
        except OSError as e:
            print(f"Error reading file {args.file}: {e}", file=sys.stderr)
            sys.exit(1)

    session_id = args.session_id or f"cli-{uuid.uuid4()}"
    user_id = args.user_id or "cli-user"

    try:
        data = call_brain_decision(
            target_type=args.target_type,
            target_value=target_value,
            mode=args.mode,
            source="cli",
            session_id=session_id,
            user_id=user_id,
            context=args.context,
            use_history=not args.no_history,
            max_history=args.max_history,
        )
    except requests.HTTPError as e:
        print(f"HTTP error from IronClaw API: {e}", file=sys.stderr)
        if e.response is not None:
            try:
                print(e.response.text, file=sys.stderr)
            except Exception:
                pass
        sys.exit(1)
    except requests.RequestException as e:
        print(f"Error connecting to IronClaw API: {e}", file=sys.stderr)
        sys.exit(1)

    decision = data.get("decision", {})
    scan = data.get("scan", {})

    if args.json:
        print(json.dumps(data, indent=2))
        return

    final_action = decision.get("final_action")
    confidence = decision.get("confidence")
    reason = decision.get("reason", "").strip()
    risk_score = scan.get("risk_score")
    sandbox_lane = scan.get("sandbox_lane")
    matched_patterns = scan.get("matched_patterns") or []

    patterns_str = ",".join(matched_patterns) if matched_patterns else "none"

    print(
        f"ACTION={final_action} CONFIDENCE={confidence:.2f} RISK_SCORE={risk_score} LANE={sandbox_lane} PATTERNS={patterns_str}",
    )
    if reason:
        print(f"REASON: {reason}")


if __name__ == "__main__":
    main()
