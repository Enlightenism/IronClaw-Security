from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any
import uuid

import requests

_DEFAULT_API_BASE = "http://127.0.0.1:8011"

_VERDICT_EXIT_CODES: dict[str, int] = {
    "allow": 0,
    "warn": 2,
    "quarantine": 3,
    "block": 4,
}


def _api_base(override: str | None = None) -> str:
    return (override or os.environ.get("IRONCLAW_API_BASE") or _DEFAULT_API_BASE).rstrip("/")


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
    base_url: str | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
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
    url = f"{_api_base(base_url)}/brain/decision"
    resp = requests.post(url, json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()  # type: ignore[no-any-return]


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ironclaw-brain",
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
        choices=["prompt", "github_repo", "skill", "archive", "url", "text", "local_path"],
        help="Target type (default: text).",
    )
    parser.add_argument(
        "--mode",
        type=str,
        default="enforce",
        choices=["enforce", "monitor", "strict"],
        help="Policy mode for the scan.",
    )
    parser.add_argument(
        "--source",
        type=str,
        default="cli",
        help="Source identifier passed to the brain (default: cli).",
    )
    parser.add_argument(
        "--session-id",
        type=str,
        default=None,
        help="Optional session/conversation ID. If omitted, a random one is generated.",
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
        "--base-url",
        type=str,
        default=None,
        help="Override IronClaw API base URL (default: $IRONCLAW_API_BASE or http://127.0.0.1:8011).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP request timeout in seconds (default: 10).",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print debug info to stderr (URL, session ID, payload size).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Print full JSON response instead of a one-line summary.",
    )
    parser.add_argument(
        "--exit-on-verdict",
        action="store_true",
        dest="exit_on_verdict",
        help=("Exit with a non-zero code based on verdict: allow=0, warn=2, quarantine=3, block=4."),
    )

    args = parser.parse_args()

    if args.text is not None:
        target_value = args.text
    else:
        try:
            with open(args.file, encoding="utf-8") as fh:
                target_value = fh.read()
        except OSError as exc:
            print(f"Error reading file {args.file}: {exc}", file=sys.stderr)
            sys.exit(1)

    session_id = args.session_id or f"cli-{uuid.uuid4()}"
    user_id = args.user_id or "cli-user"
    resolved_base_url = _api_base(args.base_url)

    if args.verbose:
        print(
            f"[ironclaw-brain] POST {resolved_base_url}/brain/decision  session={session_id}  chars={len(target_value)}",
            file=sys.stderr,
        )

    try:
        data = call_brain_decision(
            target_type=args.target_type,
            target_value=target_value,
            mode=args.mode,
            source=args.source,
            session_id=session_id,
            user_id=user_id,
            context=args.context,
            use_history=not args.no_history,
            max_history=args.max_history,
            timeout=args.timeout,
            base_url=resolved_base_url,
        )
    except requests.HTTPError as exc:
        print(f"HTTP error from IronClaw API: {exc}", file=sys.stderr)
        if exc.response is not None:
            try:
                print(exc.response.text, file=sys.stderr)
            except Exception:
                pass
        sys.exit(1)
    except requests.RequestException as exc:
        print(f"Error connecting to IronClaw API at {resolved_base_url}: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.emit_json:
        print(json.dumps(data, indent=2))
        if args.exit_on_verdict:
            decision: dict[str, Any] = data.get("decision") or {}
            final_action = decision.get("final_action") or ""
            sys.exit(_VERDICT_EXIT_CODES.get(final_action, 1))
        return

    decision = data.get("decision") or {}
    scan: dict[str, Any] = data.get("scan") or {}

    final_action = decision.get("final_action")
    raw_confidence = decision.get("confidence")
    confidence_str = f"{raw_confidence:.2f}" if isinstance(raw_confidence, (int, float)) else str(raw_confidence)
    reason = (decision.get("reason") or "").strip()
    risk_score = scan.get("risk_score")
    sandbox_lane = scan.get("sandbox_lane")
    matched_patterns: list[str] = scan.get("matched_patterns") or []

    patterns_str = ",".join(matched_patterns) if matched_patterns else "none"

    print(
        f"ACTION={final_action} CONFIDENCE={confidence_str} RISK_SCORE={risk_score} LANE={sandbox_lane} PATTERNS={patterns_str}",
    )
    if reason:
        print(f"REASON: {reason}")

    if args.exit_on_verdict:
        sys.exit(_VERDICT_EXIT_CODES.get(final_action or "", 1))


if __name__ == "__main__":
    main()
