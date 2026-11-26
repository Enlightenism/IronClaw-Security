"""Builds the scanner image that the sandbox broker runs for every return.

Run from the repository root on the broker host:
    python -m sandbox_broker.build_image
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

from sandbox_broker.config import BrokerConfig

BUILD_CONTEXT = Path(__file__).resolve().parents[1]
DOCKERFILE = Path(__file__).resolve().parent / "Dockerfile"
REQUIRED_MODEL_FILES = (
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
    "special_tokens_map.json",
    "model.safetensors",
)


class ScannerBuildPreflightError(RuntimeError):
    pass


def validate_scanner_build_bundle(root: Path | None = None) -> dict[str, str]:
    bundle_root = root or BUILD_CONTEXT
    required_files = (
        DOCKERFILE if root is None else Path(root) / "sandbox_broker" / "Dockerfile",
        bundle_root / "sandbox_broker" / "scanner.py",
        bundle_root / "sandbox_broker" / "security_rules.json",
        bundle_root / "sandbox_broker" / "policy_snapshot.json",
    )
    missing = [str(path) for path in required_files if not path.is_file()]

    model_root = bundle_root / "models" / "prompt-guard-86m"
    missing.extend(str(model_root / filename) for filename in REQUIRED_MODEL_FILES if not (model_root / filename).is_file())
    if missing:
        raise ScannerBuildPreflightError("missing_required_scanner_build_files: " + ", ".join(missing))

    try:
        rules = json.loads((bundle_root / "sandbox_broker" / "security_rules.json").read_text(encoding="utf-8"))
        policy = json.loads((bundle_root / "sandbox_broker" / "policy_snapshot.json").read_text(encoding="utf-8"))
        model_config = json.loads((model_root / "config.json").read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, OSError) as exc:
        raise ScannerBuildPreflightError("invalid_required_scanner_build_file") from exc

    if not isinstance(rules, dict) or not isinstance(rules.get("rules"), list):
        raise ScannerBuildPreflightError("invalid_security_rules")
    if not rules["rules"]:
        raise ScannerBuildPreflightError("empty_security_rules")
    try:
        for rule in rules["rules"]:
            if not isinstance(rule, dict):
                raise ScannerBuildPreflightError("invalid_security_rule")
            if not isinstance(rule.get("code"), str) or not rule["code"]:
                raise ScannerBuildPreflightError("invalid_security_rule")
            if rule.get("severity") not in {
                "low",
                "medium",
                "high",
                "critical",
            }:
                raise ScannerBuildPreflightError("invalid_security_rule")
            pattern = rule.get("pattern")
            if not isinstance(pattern, str):
                raise ScannerBuildPreflightError("invalid_security_rule")
            re.compile(pattern)
    except re.error as exc:
        raise ScannerBuildPreflightError("invalid_security_rule_pattern") from exc

    if not isinstance(policy, dict):
        raise ScannerBuildPreflightError("invalid_policy_snapshot")
    if policy.get("fail_closed") is not True:
        raise ScannerBuildPreflightError("policy_snapshot_not_fail_closed")
    if policy.get("prompt_guard_model") != "prompt-guard-86m":
        raise ScannerBuildPreflightError("unsupported_prompt_guard_model")

    threshold = policy.get("prompt_guard_threshold")
    if isinstance(threshold, bool) or not isinstance(threshold, (int, float)) or not 0.0 <= float(threshold) <= 1.0:
        raise ScannerBuildPreflightError("invalid_prompt_guard_threshold")

    block_threshold = policy.get("block_threshold")
    if isinstance(block_threshold, bool) or not isinstance(block_threshold, int) or not 1 <= block_threshold <= 100:
        raise ScannerBuildPreflightError("invalid_block_threshold")

    if not isinstance(model_config, dict):
        raise ScannerBuildPreflightError("invalid_prompt_guard_config")
    if model_config.get("model_type") != "deberta-v2":
        raise ScannerBuildPreflightError("unsupported_prompt_guard_architecture")
    if model_config.get("architectures") != ["DebertaV2ForSequenceClassification"]:
        raise ScannerBuildPreflightError("unsupported_prompt_guard_classifier")

    return {
        "scanner_version": "1",
        "prompt_guard_model": "prompt-guard-86m",
        "rules_version": str(rules.get("version") or "1"),
        "policy_version": str(policy.get("version") or "1"),
    }


def sync_security_rules_from_runtime(root: Path | None = None) -> int:
    bundle_root = root or BUILD_CONTEXT
    try:
        from app.services.rules import ALL_RULE_GROUPS

        exported_rules = [
            {
                "code": rule["id"],
                "pattern": rule["pattern"],
                "severity": rule["severity"],
                "category": rule["category"],
            }
            for group in ALL_RULE_GROUPS
            for rule in group
        ]
    except Exception as exc:
        raise ScannerBuildPreflightError("runtime_security_rules_unavailable") from exc
    if not isinstance(exported_rules, list) or not exported_rules:
        raise ScannerBuildPreflightError("empty_runtime_security_rules")

    for rule in exported_rules:
        if not isinstance(rule, dict):
            raise ScannerBuildPreflightError("invalid_runtime_security_rule")
        code = rule.get("code")
        pattern = rule.get("pattern")
        severity = rule.get("severity")
        category = rule.get("category")
        if not isinstance(code, str) or not isinstance(pattern, str) or severity not in {"low", "medium", "high", "critical"} or not isinstance(category, str):
            raise ScannerBuildPreflightError("invalid_runtime_security_rule")
    output = bundle_root / "sandbox_broker" / "security_rules.json"
    output.write_text(
        json.dumps(
            {
                "version": "runtime-1",
                "rules": exported_rules,
            },
            indent=2,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )
    return len(exported_rules)


def build_command(config: BrokerConfig) -> list[str]:
    return [
        config.docker_binary,
        "build",
        "-f",
        str(DOCKERFILE),
        "--build-arg",
        f"SCANNER_VERSION={config.scanner_image_version}",
        "--build-arg",
        f"PROMPT_GUARD_MODEL_VERSION={config.prompt_guard_model_version}",
        "-t",
        config.image,
        str(BUILD_CONTEXT),
    ]


def main() -> int:
    try:
        sync_security_rules_from_runtime()
        validate_scanner_build_bundle()
        from sandbox_broker.config import (
            BROKER_DOCKER_BINARY_ENV,
            BROKER_IMAGE_ENV,
            DEFAULT_DOCKER_BINARY,
            DEFAULT_IMAGE,
        )

        docker_binary = os.environ.get(BROKER_DOCKER_BINARY_ENV, "").strip() or DEFAULT_DOCKER_BINARY
        image = os.environ.get(BROKER_IMAGE_ENV, "").strip() or DEFAULT_IMAGE
        config = BrokerConfig(
            token="build-only",
            docker_binary=docker_binary,
            image=image,
        )
    except ScannerBuildPreflightError as exc:
        sys.stderr.write(f"[ironclaw-sandbox] Build preflight failed: {exc}\n")
        return 1

    try:
        completed = subprocess.run(build_command(config), check=False)
    except OSError as exc:
        sys.stderr.write(f"[ironclaw-sandbox] Docker build could not start: {exc}\n")
        return 1
    if completed.returncode != 0:
        sys.stderr.write("[ironclaw-sandbox] Docker scanner image build failed.\n")
    return completed.returncode


if __name__ == "__main__":
    sys.exit(main())
