from pydantic import BaseModel, Field


class PolicyStatus(BaseModel):
    heuristic_threshold: int
    heuristic_threshold_env: str | None = None
    severity_counts: dict[str, int] = Field(default_factory=dict)
    category_counts: dict[str, int] = Field(default_factory=dict)
    unicode_normalization_enabled: bool
    rule_count: int = 0
    policy_loaded_from_db: bool = False
