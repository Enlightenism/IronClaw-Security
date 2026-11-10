from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from app.core.install_key_formats import InstallKeyFormatRegistry


class InstallKeyDashboardSyncService:
    """Build a runtime-scoped dashboard summary from issued install keys and wallet usage.

    This intentionally keeps the runtime family contract narrow: only canonical
    install-key programs are mapped into the dashboard summary. Security Guardian
    remains a connector/shared family and is excluded from runtime coverage.
    """

    _RUNTIME_PROGRAMS: tuple[str, ...] = InstallKeyFormatRegistry.list_programs()
    _PROGRAM_LABELS: dict[str, str] = {
        "openclaw": "OpenClaw",
        "claude_code": "Claude Code",
        "cursor": "Cursor",
        "goose": "Goose",
        "gemini_cli": "Gemini CLI",
        "copilot": "GitHub Copilot",
        "hermes": "Hermes",
    }

    def _normalize_owner_key(self, value: Any) -> str:
        if value is None:
            raise ValueError("owner_key is required")
        normalized = str(value).strip().lower()
        if not normalized:
            raise ValueError("owner_key is required")
        return normalized

    def _looks_like_generic_platform_auth(self, value: Any) -> bool:
        if value is None:
            return False
        normalized = str(value).strip().lower()
        if not normalized:
            return False
        if normalized.startswith("ic_org_"):
            return False
        if normalized.startswith("owner_") or normalized.startswith("customer_") or normalized.startswith("user_") or normalized.startswith("org_") or normalized.startswith("acct_"):
            return False
        if normalized.startswith("ic_install_"):
            return False
        if normalized.startswith("ic_"):
            return True

        generic_prefixes = (
            "sk_",
            "ghp_",
            "gho_",
            "github_pat_",
            "token_",
            "secret_",
            "api_",
            "api-key",
            "api_key",
            "platform-api-key",
            "platform_api_key",
            "system-api-key",
            "system_api_key",
            "internal-platform-api-key",
            "internal_platform_api_key",
            "bearer ",
            "x-api-key",
        )
        if normalized.startswith(generic_prefixes):
            return True

        return ("platform" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("system" in normalized and ("key" in normalized or "token" in normalized or "secret" in normalized)) or ("api" in normalized and "key" in normalized)

    def _normalize_program(self, value: Any) -> str | None:
        if value is None:
            return None
        normalized = str(value).strip().lower().replace(" ", "_").replace("-", "_")
        normalized = normalized.replace("__", "_").strip("_")
        if not normalized:
            return None
        program = InstallKeyFormatRegistry.normalize_program(normalized)
        if program is None:
            return None
        return str(program)

    def _row_value(self, record: Any, name: str, default: Any = None) -> Any:
        if isinstance(record, dict):
            return record.get(name, default)
        return getattr(record, name, default)

    def _normalize_install_key_record(self, record: Any, *, owner_key: str) -> dict[str, Any] | None:
        if record is None:
            return None

        program = self._normalize_program(self._row_value(record, "program"))
        if program is None or program == "security_guardian":
            return None

        record_owner = self._row_value(record, "owner_key")
        normalized_owner = self._normalize_owner_key(record_owner) if record_owner not in (None, "") else owner_key
        if normalized_owner and normalized_owner != owner_key:
            return None

        key_id = str(self._row_value(record, "key_id") or "").strip()
        masked_key = self._row_value(record, "masked_key")
        if isinstance(masked_key, str):
            masked_key = masked_key.strip() or None

        payment_status = str(self._row_value(record, "payment_status") or "unpaid").strip().lower()
        entitlements_status = str(self._row_value(record, "entitlements_status") or "not_active").strip().lower()
        issued_after_payment = bool(self._row_value(record, "issued_after_payment", False))
        active = bool(self._row_value(record, "active", False))

        if not active or not issued_after_payment:
            return None
        if payment_status not in {"paid", "success", "succeeded", "complete", "completed", "active", "authorized"}:
            return None
        if entitlements_status not in {"active", "paid", "enabled", "granted"}:
            return None

        return {
            "key_id": key_id,
            "owner_key": normalized_owner,
            "program": program,
            "label": self._PROGRAM_LABELS.get(program, program.replace("_", " ").title()),
            "status": "active",
            "active": True,
            "masked_key": masked_key,
            "payment_status": "paid",
            "entitlements_status": "active",
            "issued_after_payment": True,
            "units_consumed": int(self._row_value(record, "units_consumed") or 0),
            "metadata": dict(self._row_value(record, "metadata") or {}),
        }

    def _normalize_usage_entry(self, usage_entry: Any) -> dict[str, Any]:
        if not isinstance(usage_entry, dict):
            return {}
        usage_key_id = str(usage_entry.get("key_id") or usage_entry.get("id") or "").strip()
        if not usage_key_id:
            return {}
        program = self._normalize_program(usage_entry.get("program"))
        if program is None or program == "security_guardian":
            return {}
        usage_by_day = usage_entry.get("usage_by_day") or {}
        if not isinstance(usage_by_day, dict):
            usage_by_day = {}
        normalized_usage_by_day = {str(day): int(units or 0) for day, units in usage_by_day.items()}
        units_used_today = int(usage_entry.get("units_used_today") or usage_entry.get("units_today") or 0)
        units_used_this_week = int(usage_entry.get("units_used_this_week") or usage_entry.get("units_week") or 0)
        if units_used_today < 0 or units_used_this_week < 0 or any(units < 0 for units in normalized_usage_by_day.values()):
            raise ValueError("Install-key usage units must be non-negative.")
        return {
            "key_id": usage_key_id,
            "owner_key": str(usage_entry.get("owner_key") or "").strip().lower(),
            "program": program,
            "total_consumed_units": int(usage_entry.get("total_consumed_units") or usage_entry.get("units_consumed") or 0),
            "units_used_today": units_used_today,
            "units_used_this_week": units_used_this_week,
            "usage_by_day": normalized_usage_by_day,
            "metadata": dict(usage_entry.get("metadata") or {}),
        }

    def _normalize_attack_event(self, event: Any) -> dict[str, Any] | None:
        verdict = str(self._row_value(event, "verdict") or "").strip().lower()
        if verdict != "block":
            return None

        event_id = str(self._row_value(event, "event_id") or self._row_value(event, "id") or "").strip()
        timestamp = self._row_value(event, "created_at") or self._row_value(event, "timestamp")
        if not event_id or timestamp is None:
            return None
        if isinstance(timestamp, datetime):
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=UTC)
            timestamp_value = timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
        elif isinstance(timestamp, str) and timestamp.strip():
            timestamp_value = timestamp.strip()
        else:
            return None

        metadata = self._row_value(event, "metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        event_type = str(self._row_value(event, "event_type") or "").strip()
        threat_type = str(metadata.get("category") or event_type or "security_event").strip()
        severity = str(self._row_value(event, "severity") or "unknown").strip()
        return {
            "id": event_id,
            "title": threat_type.replace("-", " ").replace("_", " ").title(),
            "description": f"Blocked by IronClaw policy ({verdict}).",
            "severity": severity,
            "timestamp": timestamp_value,
            "threat_type": threat_type,
            "risk_score": severity,
            "verdict": verdict.upper(),
        }

    def build_dashboard_summary(
        self,
        *,
        owner_key: Any,
        install_keys: Any,
        wallet_summary: dict[str, Any] | None,
        audit_events: Any = (),
    ) -> dict[str, Any]:
        normalized_owner = self._normalize_owner_key(owner_key)
        if self._looks_like_generic_platform_auth(normalized_owner):
            raise ValueError("owner_key must be a canonical customer or org identity, not a generic platform auth value.")

        wallet_payload = wallet_summary or {}
        runtime_coverage = {program: False for program in self._RUNTIME_PROGRAMS}
        slots_by_program: dict[str, dict[str, Any]] = {}
        units_today = 0
        units_week = 0
        usage_by_day: dict[str, int] = {}
        today_key = datetime.now(UTC).date().isoformat()

        for entry in install_keys or []:
            normalized = self._normalize_install_key_record(entry, owner_key=normalized_owner)
            if normalized is None:
                continue
            program = normalized["program"]
            slots_by_program[program] = normalized
            runtime_coverage[program] = bool(normalized["active"])

        usage_payload = wallet_payload.get("install_key_usage") or {}
        if isinstance(usage_payload, dict):
            for usage_entry in usage_payload.values():
                normalized_usage = self._normalize_usage_entry(usage_entry)
                if not normalized_usage:
                    continue
                if normalized_usage["owner_key"] and normalized_usage["owner_key"] != normalized_owner:
                    continue
                key_id = normalized_usage["key_id"]
                program = normalized_usage["program"]
                if program == "security_guardian" or program not in runtime_coverage:
                    continue
                slot = next((item for item in slots_by_program.values() if item.get("key_id") == key_id), None)
                if slot is None or slot["program"] != program:
                    continue
                slot["units_consumed"] = max(slot.get("units_consumed", 0), normalized_usage["total_consumed_units"])
                slot["metadata"].setdefault("usage_summary", normalized_usage)
                slot["metadata"]["usage_summary"] = normalized_usage
                units_today += max(
                    normalized_usage["units_used_today"],
                    normalized_usage["usage_by_day"].get(today_key, 0),
                )
                units_week += normalized_usage["units_used_this_week"]
                for day, units in normalized_usage["usage_by_day"].items():
                    usage_by_day[day] = usage_by_day.get(day, 0) + units

        install_key_slots = []
        for program in self._RUNTIME_PROGRAMS:
            slot = slots_by_program.get(program)
            if slot is None:
                continue
            install_key_slots.append(
                {
                    "key_id": slot.get("key_id", ""),
                    "program": slot["program"],
                    "label": slot["label"],
                    "status": slot.get("status", "locked"),
                    "active": bool(slot.get("active", False)),
                    "masked_key": slot.get("masked_key"),
                    "payment_status": slot.get("payment_status", "unpaid"),
                    "entitlements_status": slot.get("entitlements_status", "not_active"),
                    "issued_after_payment": bool(slot.get("issued_after_payment", False)),
                    "units_consumed": int(slot.get("units_consumed") or 0),
                    "metadata": dict(slot.get("metadata") or {}),
                }
            )

        wallet_total_units = int(wallet_payload.get("balance_units") or wallet_payload.get("wallet_total_units") or 0)
        if units_today:
            usage_by_day[today_key] = max(usage_by_day.get(today_key, 0), units_today)
        today = datetime.now(UTC).date()
        daily_dates = [today - timedelta(days=offset) for offset in range(6, -1, -1)]
        daily_usage = [
            {
                "date": day.isoformat(),
                "label": day.strftime("%a"),
                "units": usage_by_day.get(day.isoformat(), 0),
            }
            for day in daily_dates
        ]
        attacks = [attack for event in audit_events or [] if (attack := self._normalize_attack_event(event)) is not None]
        attacks.sort(key=lambda attack: attack["timestamp"], reverse=True)

        return {
            "owner_key": normalized_owner,
            "wallet_total_units": wallet_total_units,
            "blocked_activity_total": len(attacks),
            "units_today": units_today,
            "units_week": units_week,
            "daily_usage": daily_usage,
            "attacks": attacks,
            "runtime_coverage": runtime_coverage,
            "install_key_slots": sorted(install_key_slots, key=lambda item: self._RUNTIME_PROGRAMS.index(item["program"])),
        }
