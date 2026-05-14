from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import requests

API_BASE = "http://127.0.0.1:8000"


def _read_json_from_stdin() -> dict[str, Any]:
    data = sys.stdin.read()
    if not data.strip():
        raise ValueError("No JSON input received on stdin.")
    return json.loads(data)


def _read_json_from_file(path: str) -> dict[str, Any]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def call_scan(payload: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    resp = requests.post(f"{API_BASE}/scan", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def call_scan_batch(payload: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    resp = requests.post(f"{API_BASE}/scan/batch", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def call_brain_decision(payload: dict[str, Any], timeout: int = 10) -> dict[str, Any]:
    # Maps directly to PromptGuardRequest -> PromptGuardResponse
    # POST /guard/prompt-bundle
    resp = requests.post(f"{API_BASE}/guard/prompt-bundle", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=("IronClaw-Security tool runner.\nReads JSON input (tool arguments), calls the IronClaw API, and prints JSON output for machine consumption."),
    )

    parser.add_argument(
        "--tool",
        type=str,
        required=True,
        choices=["scan", "scan_batch", "brain_decision"],
        help="Which IronClaw tool to invoke.",
    )
    parser.add_argument(
        "--input-file",
        type=str,
        default=None,
        help="Path to a JSON file containing the tool arguments. If omitted, reads JSON from stdin.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds.",
    )

    args = parser.parse_args()

    try:
        if args.input_file:
            payload = _read_json_from_file(args.input_file)
        else:
            payload = _read_json_from_stdin()
    except Exception as e:
        print(f"Error reading JSON input: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        if args.tool == "scan":
            result = call_scan(payload, timeout=args.timeout)
        elif args.tool == "scan_batch":
            result = call_scan_batch(payload, timeout=args.timeout)
        else:  # brain_decision
            result = call_brain_decision(payload, timeout=args.timeout)
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
    except Exception as e:
        print(f"Unexpected error calling IronClaw API: {e}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
