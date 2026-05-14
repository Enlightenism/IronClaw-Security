from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys

from ironclawclient import IronClawClient, IronClawClientError


def _print_header() -> None:
    print("[ironclaw-shell-guard] IronClaw-Security local shell guard")


def _run_command(command: str) -> int:
    try:
        completed = subprocess.run(
            command,
            check=False,
            shell=True,
        )
        return completed.returncode
    except OSError as exc:
        print(f"[ironclaw-shell-guard] Failed to execute command: {exc}", file=sys.stderr)
        return 1


def _read_yes_no(prompt: str) -> bool:
    while True:
        answer = input(f"{prompt} [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False
        print("Please answer 'y' or 'n'.")


def _infer_target_from_command(command: str) -> str | None:
    try:
        parts: list[str] = shlex.split(command, posix=False)
        if not parts:
            return None
        return parts[0]
    except ValueError:
        return None


def _decision_to_dict(decision) -> dict:
    return {
        "action_type": decision.action_type,
        "target": decision.target,
        "policy_mode": decision.policy_mode,
        "verdict": decision.verdict,
        "decision_source": decision.decision_source,
        "summary": decision.summary,
        "risk_score": decision.risk_score,
        "matched_patterns": decision.matched_patterns,
        "should_halt": decision.should_halt,
        "should_warn": decision.should_warn,
        "client_id": decision.client_id,
        "session_id": decision.session_id,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="IronClaw-Security shell command guard",
    )
    parser.add_argument(
        "--command",
        "-c",
        required=True,
        help="Shell command to evaluate and potentially execute.",
    )
    parser.add_argument(
        "--client-id",
        default="local-shell",
        help="Client identifier for telemetry and policy routing.",
    )
    parser.add_argument(
        "--session-id",
        default="session-local",
        help="Session identifier for telemetry and policy routing.",
    )
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8010",
        help="Base URL for the IronClaw-Security API.",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Automatically approve warnings (skip interactive prompt).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON decision and exit without executing the command.",
    )

    args = parser.parse_args(argv)
    command: str = args.command

    _print_header()
    print(f"[ironclaw-shell-guard] Evaluating command:\n  {command}\n")

    target = _infer_target_from_command(command)
    client = IronClawClient(base_url=args.base_url)

    try:
        decision = client.guard_action_decision(
            action_type="shell_command",
            target=target,
            content=command,
            client_id=args.client_id,
            session_id=args.session_id,
        )
    except IronClawClientError as exc:
        print(
            "[ironclaw-shell-guard] Guard service unreachable. Blocking by default.",
            file=sys.stderr,
        )
        print(f"[ironclaw-shell-guard] ERROR: {exc}", file=sys.stderr)
        return 1

    if args.json:
        payload = _decision_to_dict(decision)
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 1 if decision.should_halt else 0

    print(
        "[ironclaw-shell-guard] decision:\n"
        f"  verdict          = {decision.verdict}\n"
        f"  source           = {decision.decision_source}\n"
        f"  policy_mode      = {decision.policy_mode}\n"
        f"  risk_score       = {decision.risk_score}\n"
        f"  should_halt      = {decision.should_halt}\n"
        f"  should_warn      = {decision.should_warn}\n"
        f"  matched_patterns = {decision.matched_patterns}\n",
    )

    if decision.should_halt:
        print("[ironclaw-shell-guard] Command BLOCKED by IronClaw.")
        print(f"[ironclaw-shell-guard] Summary: {decision.summary}")
        return 1

    if decision.should_warn:
        print("[ironclaw-shell-guard] WARNING: Command is risky.")
        print(f"[ironclaw-shell-guard] Summary: {decision.summary}")
        if args.yes:
            print("[ironclaw-shell-guard] --yes supplied; proceeding without prompt.")
        else:
            proceed = _read_yes_no("Proceed with execution?")
            if not proceed:
                print("[ironclaw-shell-guard] User chose to cancel.")
                return 1

    print("[ironclaw-shell-guard] Command allowed. Executing...\n")
    return_code = _run_command(command)
    print(f"[ironclaw-shell-guard] Command exited with code {return_code}")
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
