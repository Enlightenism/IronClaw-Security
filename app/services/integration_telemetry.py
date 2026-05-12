from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from enum import Enum


class TelemetryState(str, Enum):
    """Normalized state for adapter and integration health."""

    SUPPORTED = "supported"
    WARNING = "warning"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class AdapterTelemetry:
    """
    Telemetry for a single adapter/runtime within an integration.

    This is intentionally minimal and deterministic so platforms can
    store and query it easily (JSON, event streams, etc.).
    """

    adapter_id: str
    runtime_family: str
    version: str
    state: TelemetryState
    reason: str = ""
    # Optional numeric score for the adapter, 0–100 where higher is better.
    score: float | None = None
    # Arbitrary extra fields from the adapter or compatibility layer.
    metadata: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert to a JSON‑friendly dict."""
        data = asdict(self)
        data["state"] = self.state.value
        return data


@dataclass(frozen=True)
class IntegrationTelemetrySummary:
    """
    Roll‑up telemetry for an entire integration across all adapters.

    This is what you send to the platform for dashboards, alerting, or risk views.
    """

    integration_id: str
    total_adapters: int
    counts_by_state: dict[TelemetryState, int]
    overall_state: TelemetryState
    # 0–100, where 100 is ideal (all supported, no warnings).
    risk_score: float
    # Expose a couple of exemplars to make debugging easier.
    sample_unsupported_adapters: list[str] = field(default_factory=list)
    sample_warning_adapters: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Convert to a JSON‑friendly dict with string enum values."""
        return {
            "integration_id": self.integration_id,
            "total_adapters": self.total_adapters,
            "counts_by_state": {
                state.value: count for state, count in self.counts_by_state.items()
            },
            "overall_state": self.overall_state.value,
            "risk_score": self.risk_score,
            "sample_unsupported_adapters": list(self.sample_unsupported_adapters),
            "sample_warning_adapters": list(self.sample_warning_adapters),
        }


def _clamp(value: float, min_value: float, max_value: float) -> float:
    return max(min_value, min(max_value, value))


def summarize_integration_telemetry(
    *,
    integration_id: str,
    adapter_telemetry: Iterable[AdapterTelemetry],
    # Optional explicit weights if we ever want to tweak behaviour without
    # changing the function signature.
    weights: Mapping[TelemetryState, float] | None = None,
) -> IntegrationTelemetrySummary:
    """
    Aggregate adapter‑level telemetry into a single integration summary.

    Rules (deliberately conservative):

    - If there are any UNSUPPORTED adapters, the integration is UNSUPPORTED.
    - Else if there are any WARNING adapters, the integration is WARNING.
    - Else (only SUPPORTED adapters), the integration is SUPPORTED.

    Risk score (0–100, higher is better):

    - Start from 100.
    - Subtract a fixed penalty per WARNING adapter.
    - Subtract a larger penalty per UNSUPPORTED adapter.
    - If adapters provide their own `score`, we blend in the average of those
      to avoid discarding useful per‑adapter risk signals.
    """

    telemetry_list = list(adapter_telemetry)
    total = len(telemetry_list)

    counts: dict[TelemetryState, int] = {
        TelemetryState.SUPPORTED: 0,
        TelemetryState.WARNING: 0,
        TelemetryState.UNSUPPORTED: 0,
    }
    unsupported_ids: list[str] = []
    warning_ids: list[str] = []
    adapter_scores: list[float] = []

    for t in telemetry_list:
        counts[t.state] += 1
        if t.state is TelemetryState.UNSUPPORTED:
            unsupported_ids.append(t.adapter_id)
        elif t.state is TelemetryState.WARNING:
            warning_ids.append(t.adapter_id)
        if t.score is not None:
            adapter_scores.append(float(t.score))

    # Determine overall state in a deterministic way.
    if counts[TelemetryState.UNSUPPORTED] > 0:
        overall_state = TelemetryState.UNSUPPORTED
    elif counts[TelemetryState.WARNING] > 0:
        overall_state = TelemetryState.WARNING
    else:
        # If there are zero adapters, treat as unsupported to be safe.
        overall_state = (
            TelemetryState.SUPPORTED if total > 0 else TelemetryState.UNSUPPORTED
        )

    # Default penalty weights – can be overridden via `weights`.
    penalties = {
        TelemetryState.SUPPORTED: 0.0,
        TelemetryState.WARNING: 5.0,
        TelemetryState.UNSUPPORTED: 20.0,
    }
    if weights:
        penalties.update({k: float(v) for k, v in weights.items()})

    base_score = 100.0
    # Apply penalties per adapter.
    for state, count in counts.items():
        base_score -= penalties[state] * count

    # Blend any per‑adapter scores if present.
    blended_score = base_score
    if adapter_scores:
        avg_adapter_score = sum(adapter_scores) / len(adapter_scores)
        # Simple blend: 70% structural penalty score, 30% average adapter score.
        blended_score = 0.7 * base_score + 0.3 * avg_adapter_score

    risk_score = _clamp(blended_score, 0.0, 100.0)

    return IntegrationTelemetrySummary(
        integration_id=integration_id,
        total_adapters=total,
        counts_by_state=counts,
        overall_state=overall_state,
        risk_score=risk_score,
        sample_unsupported_adapters=unsupported_ids[:3],
        sample_warning_adapters=warning_ids[:3],
    )