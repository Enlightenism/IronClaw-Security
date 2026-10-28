from dataclasses import dataclass

from app.config import RISK_THRESHOLD_BLOCK_MIN

QUARANTINE_TARGET_TYPES = {"skill", "archive", "local_path"}
HIGH_RISK_SANDBOX_TARGET_TYPES = {"github_repo"}


@dataclass
class SandboxDecision:
    enforced: bool
    verdict_override: str | None
    summary_suffix: str
    quarantine_reason: str | None
    review_status: str
    untrusted: bool


def evaluate_sandbox(target_type: str, route_mode: str, requires_sandbox: bool) -> SandboxDecision:
    if not requires_sandbox or route_mode != "sandbox":
        return SandboxDecision(
            enforced=False,
            verdict_override=None,
            summary_suffix="",
            quarantine_reason=None,
            review_status="none",
            untrusted=False,
        )

    if target_type in QUARANTINE_TARGET_TYPES:
        return SandboxDecision(
            enforced=True,
            verdict_override="block",
            summary_suffix=" Blocked because this target requires sandbox handling.",
            quarantine_reason=f"{target_type} requires sandbox handling",
            review_status="none",
            untrusted=True,
        )

    if target_type in HIGH_RISK_SANDBOX_TARGET_TYPES:
        return SandboxDecision(
            enforced=True,
            verdict_override="block",
            summary_suffix=" Blocked because repository scanning requires an isolated sandbox that is not configured.",
            quarantine_reason="github_repo sandbox scanner unavailable",
            review_status="none",
            untrusted=True,
        )

    return SandboxDecision(
        enforced=False,
        verdict_override=None,
        summary_suffix="",
        quarantine_reason=None,
        review_status="none",
        untrusted=False,
    )


def apply_sandbox_policy(scan_result: dict, decision: SandboxDecision) -> dict:
    result = dict(scan_result)

    base_summary = result.get("summary", "Sandbox policy applied.")
    if decision.summary_suffix:
        result["summary"] = f"{base_summary}{decision.summary_suffix}".strip()
    else:
        result["summary"] = base_summary

    if decision.enforced:
        result["verdict"] = decision.verdict_override or result.get("verdict", "block")

        failed_checks = list(result.get("failed_checks", []))
        if decision.quarantine_reason and decision.quarantine_reason not in failed_checks:
            failed_checks.append(decision.quarantine_reason)
        result["failed_checks"] = failed_checks

        result["quarantine_reason"] = decision.quarantine_reason
        result["review_status"] = decision.review_status
        result["untrusted"] = decision.untrusted
    else:
        result.setdefault("quarantine_reason", None)
        result.setdefault("review_status", "none")
        result.setdefault("untrusted", False)

    verdict = result.get("verdict")
    if not isinstance(verdict, str) or verdict not in {"allow", "block"}:
        result["verdict"] = "block"
        result["quarantine_reason"] = result.get("quarantine_reason") or "Invalid scan verdict; blocked by sandbox policy."
        result["review_status"] = "none"
        result["untrusted"] = True

    if result["verdict"] == "block":
        result["review_status"] = "none"
        result["untrusted"] = True
        result["risk_score"] = max(
            int(result.get("risk_score", 0)),
            RISK_THRESHOLD_BLOCK_MIN,
        )

    return result
