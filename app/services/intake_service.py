from dataclasses import dataclass

ALLOWED_TARGET_TYPES = {"github_repo", "skill", "archive", "url", "text", "local_path"}
SANDBOX_TARGET_TYPES = {"github_repo", "skill", "archive", "local_path"}


@dataclass
class IntakeDecision:
    target_type: str
    target_value: str
    original_target_value: str
    normalized_target_value: str
    route_mode: str
    requires_sandbox: bool
    content_length: int


def _normalize_target_type(target_type: str) -> str:
    return target_type.strip().lower()


def _strip_null_bytes(target_value: str) -> str:
    return target_value.replace(chr(0), "")


def _normalize_whitespace(target_value: str) -> str:
    return " ".join(target_value.split())


def prepare_intake(target_type: str, target_value: str) -> IntakeDecision:
    normalized_type = _normalize_target_type(target_type)
    if normalized_type not in ALLOWED_TARGET_TYPES:
        raise ValueError("Unsupported target_type")

    original_value = target_value
    cleaned_value = _strip_null_bytes(target_value).strip()
    if not cleaned_value:
        raise ValueError("target_value cannot be empty")

    normalized_value = _normalize_whitespace(cleaned_value)
    requires_sandbox = normalized_type in SANDBOX_TARGET_TYPES
    route_mode = "sandbox" if requires_sandbox else "scan"

    return IntakeDecision(
        target_type=normalized_type,
        target_value=normalized_value,
        original_target_value=original_value,
        normalized_target_value=normalized_value,
        route_mode=route_mode,
        requires_sandbox=requires_sandbox,
        content_length=len(normalized_value),
    )
