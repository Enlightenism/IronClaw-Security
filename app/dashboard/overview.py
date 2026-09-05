from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.core.install_key_formats import InstallKeyFormatRegistry


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on", "enabled"}:
            return True
        if normalized in {"0", "false", "no", "off", "disabled"}:
            return False
    if isinstance(value, int | float):
        return bool(value)
    return default


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _coerce_datetime(value: Any, default: datetime | None = None) -> datetime | None:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    if isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            return default
        candidate = candidate.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return default
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=UTC)
        return parsed.astimezone(UTC)
    return default


@dataclass(frozen=True, slots=True)
class DashboardKPI:
    key: str
    label: str
    value: float
    unit: str = ""
    trend_direction: str = "steady"
    trend_value: float = 0.0
    status: str = "ok"

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "value": self.value,
            "unit": self.unit,
            "trend_direction": self.trend_direction,
            "trend_value": self.trend_value,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class DashboardAlert:
    alert_id: str
    title: str
    severity: str
    status: str
    source: str
    created_at: datetime
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "source": self.source,
            "created_at": _isoformat(self.created_at),
            "summary": self.summary,
        }


_PLACEHOLDER_PURCHASE_MESSAGE = "Keys will be generated after purchase"

_DEFAULT_PLATFORM_FAMILIES: tuple[str, ...] = InstallKeyFormatRegistry.list_programs()
_RUNTIME_ORDER: dict[str, int] = {program: idx for idx, program in enumerate(_DEFAULT_PLATFORM_FAMILIES)}

_PLATFORM_LABELS: dict[str, str] = {
    "openclaw": "OpenClaw",
    "claude_code": "Claude Code",
    "cursor": "Cursor",
    "goose": "Goose",
    "gemini_cli": "Gemini CLI",
    "copilot": "GitHub Copilot",
    "hermes": "Hermes",
}


@dataclass(frozen=True, slots=True)
class DashboardInstallKeySlot:
    key_id: str = ""
    program: str = ""
    label: str = ""
    status: str = "locked"
    active: bool = False
    masked_key: str | None = None
    payment_status: str = "unpaid"
    entitlements_status: str = "not_active"
    issued_after_payment: bool = False
    units_consumed: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key_id": self.key_id,
            "program": self.program,
            "label": self.label,
            "status": self.status,
            "active": self.active,
            "masked_key": self.masked_key,
            "payment_status": self.payment_status,
            "entitlements_status": self.entitlements_status,
            "issued_after_payment": self.issued_after_payment,
            "units_consumed": self.units_consumed,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class DashboardPlatformFamily:
    family: str
    platform: str
    label: str
    status: str = "locked"
    installed: bool = False
    payment_status: str = "unpaid"
    entitlements_status: str = "not_active"
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "platform": self.platform,
            "label": self.label,
            "status": self.status,
            "installed": self.installed,
            "payment_status": self.payment_status,
            "entitlements_status": self.entitlements_status,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True, slots=True)
class DashboardOverview:
    service: str = "ironclaw-security"
    environment: str = "local"
    status: str = "healthy"
    risk_level: str = "moderate"
    owner_key: str = ""
    total_requests: int = 0
    guarded_requests: int = 0
    blocked_actions: int = 0
    blocked_activity_total: int = 0
    quarantined_actions: int = 0
    active_incidents: int = 0
    pending_reviews: int = 0
    policy_coverage_percent: float = 0.0
    tool_execution_allow_rate: float = 0.0
    telemetry_online: bool = True
    review_backlog_present: bool = False
    quarantine_pressure: bool = False
    wallet_total_units: int = 0
    runtime_coverage: dict[str, bool] = field(default_factory=dict)
    kpis: tuple[DashboardKPI, ...] = ()
    alerts: tuple[DashboardAlert, ...] = ()
    platform_families: tuple[DashboardPlatformFamily, ...] = ()
    install_key_slots: tuple[DashboardInstallKeySlot, ...] = ()
    checked_at: datetime = field(default_factory=_utc_now)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "environment": self.environment,
            "status": self.status,
            "risk_level": self.risk_level,
            "owner_key": self.owner_key,
            "total_requests": self.total_requests,
            "guarded_requests": self.guarded_requests,
            "blocked_actions": self.blocked_actions,
            "blocked_activity_total": self.blocked_activity_total,
            "quarantined_actions": self.quarantined_actions,
            "active_incidents": self.active_incidents,
            "pending_reviews": self.pending_reviews,
            "policy_coverage_percent": self.policy_coverage_percent,
            "tool_execution_allow_rate": self.tool_execution_allow_rate,
            "telemetry_online": self.telemetry_online,
            "review_backlog_present": self.review_backlog_present,
            "quarantine_pressure": self.quarantine_pressure,
            "wallet_total_units": self.wallet_total_units,
            "runtime_coverage": dict(self.runtime_coverage),
            "kpis": [item.to_dict() for item in self.kpis],
            "alerts": [item.to_dict() for item in self.alerts],
            "platform_families": [item.to_dict() for item in self.platform_families],
            "install_key_slots": [item.to_dict() for item in self.install_key_slots],
            "available_install_key_slots": [item.to_dict() for item in self.install_key_slots],
            "checked_at": _isoformat(self.checked_at),
        }


def _normalize_kpi(value: Any) -> DashboardKPI | None:
    if not isinstance(value, dict):
        return None

    key = _coerce_str(value.get("key"))
    label = _coerce_str(value.get("label"))
    if not key and not label:
        return None

    return DashboardKPI(
        key=key or label.lower().replace(" ", "_") or "metric",
        label=label or "Metric",
        value=_coerce_float(value.get("value"), 0.0),
        unit=_coerce_str(value.get("unit")),
        trend_direction=_coerce_str(value.get("trend_direction"), "steady") or "steady",
        trend_value=_coerce_float(value.get("trend_value"), 0.0),
        status=_coerce_str(value.get("status"), "ok") or "ok",
    )


def _normalize_alert(value: Any) -> DashboardAlert | None:
    if not isinstance(value, dict):
        return None

    alert_id = _coerce_str(value.get("alert_id"))
    title = _coerce_str(value.get("title"))
    if not alert_id and not title:
        return None

    return DashboardAlert(
        alert_id=alert_id or title.lower().replace(" ", "-") or "alert",
        title=title or "Alert",
        severity=_coerce_str(value.get("severity"), "medium") or "medium",
        status=_coerce_str(value.get("status"), "open") or "open",
        source=_coerce_str(value.get("source"), "runtime") or "runtime",
        created_at=_coerce_datetime(value.get("created_at"), _utc_now()) or _utc_now(),
        summary=_coerce_str(value.get("summary"), "No alert summary provided.") or "No alert summary provided.",
    )


def _normalize_platform_program(value: Any) -> str:
    normalized = _coerce_str(value).lower().replace(" ", "_").replace("-", "_")
    normalized = normalized.replace("__", "_").strip("_")
    stale_legacy_platforms = {
        "ironclaw",
        "iron_claw",
        "standalone_ironclaw",
        "standalone_iron_claw",
        "standalone ironclaw",
    }
    connector_platforms = {
        "security_guardian",
        "securityguardian",
        "security_guardian_skill",
        "security_guardian_skill_",
        "skill",
        "skills",
    }
    if normalized in stale_legacy_platforms or normalized in connector_platforms:
        return ""

    canonical = InstallKeyFormatRegistry.normalize_program(normalized)
    if canonical is not None:
        return canonical

    return normalized if normalized in set(_DEFAULT_PLATFORM_FAMILIES) else ""


def _placeholder_slot_metadata(*, owner_key: str | None = None) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "placeholder": _PLACEHOLDER_PURCHASE_MESSAGE,
        "placeholder_text": _PLACEHOLDER_PURCHASE_MESSAGE,
        "status_message": _PLACEHOLDER_PURCHASE_MESSAGE,
    }
    if owner_key is not None:
        metadata["owner_key"] = owner_key
    metadata["requires_subscription"] = True
    return metadata


def _default_platform_families() -> tuple[DashboardPlatformFamily, ...]:
    return tuple(
        DashboardPlatformFamily(
            family=program,
            platform=program,
            label=_PLATFORM_LABELS.get(program, program.replace("_", " ").title()),
            status="locked",
            installed=False,
            payment_status="unpaid",
            entitlements_status="not_active",
            metadata={"requires_subscription": True, "placeholder": _PLACEHOLDER_PURCHASE_MESSAGE},
        )
        for program in _DEFAULT_PLATFORM_FAMILIES
    )


def _default_install_key_slots() -> tuple[DashboardInstallKeySlot, ...]:
    return tuple(
        DashboardInstallKeySlot(
            key_id="",
            program=program,
            label=_PLATFORM_LABELS.get(program, program.replace("_", " ").title()),
            status="locked",
            active=False,
            masked_key=None,
            payment_status="unpaid",
            entitlements_status="not_active",
            issued_after_payment=False,
            units_consumed=0,
            metadata=_placeholder_slot_metadata(),
        )
        for program in _DEFAULT_PLATFORM_FAMILIES
    )


def _sort_runtime_slots(items: tuple[Any, ...], *, program_attr: str) -> tuple[Any, ...]:
    ordered = [item for item in items if getattr(item, program_attr, "") in _RUNTIME_ORDER]
    ordered.sort(key=lambda item: _RUNTIME_ORDER.get(getattr(item, program_attr, ""), len(_RUNTIME_ORDER)))
    return tuple(ordered)


def _normalize_platform_family(value: Any) -> DashboardPlatformFamily | None:
    if not isinstance(value, dict):
        return None

    family = _normalize_platform_program(value.get("family") or value.get("platform") or value.get("id"))
    if not family:
        return None

    label = _coerce_str(value.get("label") or value.get("display_name") or _PLATFORM_LABELS.get(family, family.replace("_", " ").title()))
    return DashboardPlatformFamily(
        family=family,
        platform=family,
        label=label,
        status=_coerce_str(value.get("status") or value.get("install_key_status"), "locked") or "locked",
        installed=_coerce_bool(value.get("installed"), False),
        payment_status=_coerce_str(value.get("payment_status"), "unpaid") or "unpaid",
        entitlements_status=_coerce_str(value.get("entitlements_status"), "not_active") or "not_active",
        metadata={key: value for key, value in dict(value.get("metadata") or {}).items()},
    )


def _normalize_install_key_slot(value: Any) -> DashboardInstallKeySlot | None:
    if not isinstance(value, dict):
        return None

    program = _normalize_platform_program(value.get("program") or value.get("family") or value.get("platform"))
    if not program:
        return None

    metadata = dict(value.get("metadata") or {})
    if owner_key := _coerce_str(value.get("owner_key")):
        metadata["owner_key"] = owner_key
    if key_id := _coerce_str(value.get("key_id")):
        metadata.setdefault("key_id", key_id)
    status = _coerce_str(value.get("status") or value.get("install_key_status"), "locked") or "locked"
    active = _coerce_bool(value.get("active"), status == "active")
    label = _coerce_str(value.get("label") or value.get("display_name") or _PLATFORM_LABELS.get(program, program.replace("_", " ").title()))

    return DashboardInstallKeySlot(
        key_id=_coerce_str(value.get("key_id")),
        program=program,
        label=label,
        status=status,
        active=active,
        masked_key=(value.get("masked_key") or None),
        payment_status=_coerce_str(value.get("payment_status"), "unpaid") or "unpaid",
        entitlements_status=_coerce_str(value.get("entitlements_status"), "not_active") or "not_active",
        issued_after_payment=_coerce_bool(value.get("issued_after_payment"), False),
        units_consumed=_coerce_int(value.get("units_consumed"), 0),
        metadata=metadata,
    )


def default_dashboard_overview() -> DashboardOverview:
    return DashboardOverview(
        platform_families=_default_platform_families(),
        install_key_slots=_default_install_key_slots(),
    )


def build_dashboard_overview(
    data: dict[str, Any] | None = None,
    *,
    baseline: DashboardOverview | None = None,
) -> DashboardOverview:
    source = data or {}
    current = baseline or default_dashboard_overview()

    owner_key = _coerce_str(source.get("owner_key"), current.owner_key)
    wallet_total_units = max(0, _coerce_int(source.get("wallet_total_units"), current.wallet_total_units))
    blocked_activity_total = max(0, _coerce_int(source.get("blocked_activity_total"), current.blocked_activity_total))
    runtime_coverage = {str(key): _coerce_bool(value, False) for key, value in dict(source.get("runtime_coverage") or current.runtime_coverage or {}).items()}

    raw_kpis = source.get("kpis")
    if isinstance(raw_kpis, list):
        kpis = tuple(item for entry in raw_kpis if (item := _normalize_kpi(entry)) is not None)
    else:
        kpis = current.kpis

    raw_alerts = source.get("alerts")
    if isinstance(raw_alerts, list):
        alerts = tuple(item for entry in raw_alerts if (item := _normalize_alert(entry)) is not None)
    else:
        alerts = current.alerts

    raw_platform_families = source.get("platform_families")
    if isinstance(raw_platform_families, list):
        platform_families = tuple(item for entry in raw_platform_families if (item := _normalize_platform_family(entry)) is not None)
        platform_families = tuple(item for item in platform_families if item.family in _RUNTIME_ORDER)
        platform_families = _sort_runtime_slots(platform_families, program_attr="family")
    else:
        platform_families = current.platform_families or _default_platform_families()

    raw_install_key_slots = source.get("install_key_slots")
    if isinstance(raw_install_key_slots, list):
        install_key_slots = tuple(item for entry in raw_install_key_slots if (item := _normalize_install_key_slot(entry)) is not None)
        install_key_slots = tuple(item for item in install_key_slots if item.program in _RUNTIME_ORDER)
        install_key_slots = _sort_runtime_slots(install_key_slots, program_attr="program")
    else:
        install_key_slots = current.install_key_slots or _default_install_key_slots()

    if not platform_families and install_key_slots:
        platform_families = tuple(
            DashboardPlatformFamily(
                family=slot.program,
                platform=slot.program,
                label=slot.label,
                status=slot.status,
                installed=slot.active,
                payment_status=slot.payment_status,
                entitlements_status=slot.entitlements_status,
                metadata={"key_id": slot.key_id, **slot.metadata},
            )
            for slot in install_key_slots
        )

    if not install_key_slots and platform_families:
        install_key_slots = tuple(
            DashboardInstallKeySlot(
                key_id="",
                program=family.platform,
                label=family.label,
                status=family.status if family.status not in {"", "locked"} else "locked",
                active=bool(family.installed),
                masked_key=None,
                payment_status=family.payment_status,
                entitlements_status=family.entitlements_status,
                issued_after_payment=False,
                units_consumed=0,
                metadata={
                    **_placeholder_slot_metadata(owner_key=source.get("owner_key")),
                    **({"key_id": family.platform} if family.platform else {}),
                },
            )
            for family in platform_families
        )
        install_key_slots = _sort_runtime_slots(install_key_slots, program_attr="program")

    active_incidents = max(0, _coerce_int(source.get("active_incidents"), current.active_incidents))
    pending_reviews = max(0, _coerce_int(source.get("pending_reviews"), current.pending_reviews))
    quarantined_actions = max(0, _coerce_int(source.get("quarantined_actions"), current.quarantined_actions))

    review_backlog_present = _coerce_bool(
        source.get("review_backlog_present"),
        current.review_backlog_present or pending_reviews > 0,
    )
    quarantine_pressure = _coerce_bool(
        source.get("quarantine_pressure"),
        current.quarantine_pressure or quarantined_actions > 0,
    )

    return DashboardOverview(
        service=_coerce_str(source.get("service"), current.service) or current.service,
        environment=_coerce_str(source.get("environment"), current.environment) or current.environment,
        status=_coerce_str(source.get("status"), current.status) or current.status,
        risk_level=_coerce_str(source.get("risk_level"), current.risk_level) or current.risk_level,
        owner_key=owner_key,
        total_requests=max(0, _coerce_int(source.get("total_requests"), current.total_requests)),
        guarded_requests=max(0, _coerce_int(source.get("guarded_requests"), current.guarded_requests)),
        blocked_actions=max(0, _coerce_int(source.get("blocked_actions"), current.blocked_actions)),
        blocked_activity_total=blocked_activity_total,
        quarantined_actions=quarantined_actions,
        active_incidents=active_incidents,
        pending_reviews=pending_reviews,
        policy_coverage_percent=max(
            0.0,
            _coerce_float(source.get("policy_coverage_percent"), current.policy_coverage_percent),
        ),
        tool_execution_allow_rate=max(
            0.0,
            _coerce_float(source.get("tool_execution_allow_rate"), current.tool_execution_allow_rate),
        ),
        telemetry_online=_coerce_bool(source.get("telemetry_online"), current.telemetry_online),
        review_backlog_present=review_backlog_present,
        quarantine_pressure=quarantine_pressure,
        wallet_total_units=wallet_total_units,
        runtime_coverage=runtime_coverage,
        kpis=kpis,
        alerts=alerts,
        platform_families=platform_families,
        install_key_slots=install_key_slots,
        checked_at=_coerce_datetime(source.get("checked_at"), _utc_now()) or _utc_now(),
    )


def dashboard_overview_summary(overview: DashboardOverview) -> dict[str, Any]:
    protection_rate = 0.0
    if overview.total_requests > 0:
        protected_events = overview.blocked_actions + overview.quarantined_actions
        protection_rate = round((protected_events / overview.total_requests) * 100.0, 2)

    return {
        "service": overview.service,
        "environment": overview.environment,
        "status": overview.status,
        "risk_level": overview.risk_level,
        "owner_key": overview.owner_key,
        "telemetry_online": overview.telemetry_online,
        "wallet_total_units": overview.wallet_total_units,
        "blocked_activity_total": overview.blocked_activity_total,
        "runtime_coverage": dict(overview.runtime_coverage),
        "signals": {
            "total_requests": overview.total_requests,
            "guarded_requests": overview.guarded_requests,
            "blocked_actions": overview.blocked_actions,
            "quarantined_actions": overview.quarantined_actions,
            "active_incidents": overview.active_incidents,
            "pending_reviews": overview.pending_reviews,
        },
        "coverage": {
            "policy_coverage_percent": round(overview.policy_coverage_percent, 2),
            "tool_execution_allow_rate": round(overview.tool_execution_allow_rate, 2),
            "protection_rate": protection_rate,
        },
        "pressure": {
            "review_backlog_present": overview.review_backlog_present,
            "quarantine_pressure": overview.quarantine_pressure,
        },
        "platform_families": [item.to_dict() for item in overview.platform_families],
        "install_key_slots": [item.to_dict() for item in overview.install_key_slots],
        "available_install_key_slots": [item.to_dict() for item in overview.install_key_slots],
        "kpis": [item.to_dict() for item in overview.kpis],
        "alerts": [item.to_dict() for item in overview.alerts],
        "checked_at": _isoformat(overview.checked_at),
    }
