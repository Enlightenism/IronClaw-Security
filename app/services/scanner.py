from pathlib import Path
import yaml

BASE_DIR = Path(__file__).resolve().parents[2]
RULES_DIR = BASE_DIR / "rules" / "openclaw"

def load_yaml(filename: str) -> dict:
    path = RULES_DIR / filename
    if not path.exists():
        return {}
    with path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def normalize_text(target_type: str, target_value: str) -> str:
    return f"{target_type}\n{target_value}".lower()

def find_matches(text: str, values: list[str]) -> list[str]:
    hits = []
    for value in values:
        if value and value.lower() in text:
            hits.append(value)
    return hits

def evaluate_checks(target_type: str, target_value: str, checks: list[str]) -> list[str]:
    text = normalize_text(target_type, target_value)
    failed = []

    if "localhost_only" in checks and "0.0.0.0" in text:
        failed.append("localhost_only")
    if "auth_enabled" in checks and "auth disabled" in text:
        failed.append("auth_enabled")
    if "unsafe_exec_disabled" in checks and ("exec(" in text or "subprocess" in text):
        failed.append("unsafe_exec_disabled")
    if "trusted_skill_source" in checks and "untrusted skill" in text:
        failed.append("trusted_skill_source")

    return failed

def calculate_risk_score(pattern_hits: list[str], risky_hits: list[str], failed_checks: list[str], target_type: str) -> int:
    score = 0
    score += len(pattern_hits) * 50
    score += len(risky_hits) * 20
    score += len(failed_checks) * 10

    if target_type in {"github_repo", "skill", "archive"}:
        score += 10

    return min(score, 100)

def determine_verdict(pattern_hits: list[str], risky_hits: list[str], failed_checks: list[str], risk_score: int) -> str:
    if pattern_hits:
        return "block"
    if risky_hits or failed_checks:
        return "quarantine"
    if risk_score >= 10:
        return "warn"
    return "allow"

def perform_scan(target_type: str, target_value: str):
    blocked_rules = load_yaml("blocked_patterns.yaml")
    risky_rules = load_yaml("risky_files.yaml")
    hardening_rules = load_yaml("hardening_checks.yaml")

    patterns = blocked_rules.get("patterns", [])
    risky_files = risky_rules.get("files", [])
    checks = [item.get("name") for item in hardening_rules.get("checks", []) if item.get("name")]

    scan_text = normalize_text(target_type, target_value)
    pattern_hits = find_matches(scan_text, patterns)
    risky_hits = find_matches(scan_text, risky_files)
    failed_checks = evaluate_checks(target_type, target_value, checks)
    risk_score = calculate_risk_score(pattern_hits, risky_hits, failed_checks, target_type)
    verdict = determine_verdict(pattern_hits, risky_hits, failed_checks, risk_score)

    if pattern_hits:
        summary = f"Matched blocked patterns: {', '.join(pattern_hits)}"
    elif risky_hits:
        summary = f"Matched risky files: {', '.join(risky_hits)}"
    elif failed_checks:
        summary = f"Failed hardening checks: {', '.join(failed_checks)}"
    else:
        summary = f"No blocked patterns matched for {target_type}"

    return {
        "verdict": verdict,
        "summary": summary,
        "target_type": target_type,
        "target_value": 
 target_value,
        "risk_score": risk_score,
        "matched_patterns": pattern_hits,
        "risky_files": risky_hits,
        "checks_loaded": checks,
        "failed_checks": failed_checks
    }
