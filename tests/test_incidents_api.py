from __future__ import annotations

from datetime import UTC, datetime

from app.incidents.overview import (
    IncidentOwner,
    IncidentRecord,
    IncidentsOverview,
    build_incidents_overview,
    default_incidents_overview,
    incidents_overview_summary,
)
from app.incidents.triage import (
    IncidentTriage,
    build_incident_triage,
    default_incident_triage,
    incident_triage_summary,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_incident_dict(
    *,
    incident_id: str = "inc-001",
    title: str = "Prompt injection detected",
    severity: str = "critical",
    status: str = "open",
    source: str = "runtime",
    affected_surface: str = "agent",
    requires_human_review: bool = True,
    quarantined_actions: int = 2,
    blocked_actions: int = 1,
    evidence_count: int = 3,
) -> dict:
    return {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "status": status,
        "source": source,
        "affected_surface": affected_surface,
        "opened_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T10:30:00Z",
        "owner": {
            "owner_id": "owner-001",
            "display_name": "Security Team",
            "team": "soc",
        },
        "requires_human_review": requires_human_review,
        "quarantined_actions": quarantined_actions,
        "blocked_actions": blocked_actions,
        "evidence_count": evidence_count,
    }


def _make_triage_dict(
    *,
    incident_id: str = "inc-001",
    title: str = "Prompt injection detected",
    severity: str = "critical",
    status: str = "triage",
    source: str = "runtime",
    summary: str = "Suspected prompt injection via tool call chain.",
    requires_human_review: bool = True,
    containment_recommended: bool = True,
    blocked_actions: int = 1,
    quarantined_actions: int = 2,
) -> dict:
    return {
        "incident_id": incident_id,
        "title": title,
        "severity": severity,
        "status": status,
        "source": source,
        "summary": summary,
        "opened_at": "2024-01-15T10:00:00Z",
        "updated_at": "2024-01-15T10:30:00Z",
        "assignment": {
            "owner_id": "owner-001",
            "display_name": "Security Analyst",
            "queue": "incident-triage",
            "team": "soc",
        },
        "decision": {
            "decision": "quarantine",
            "confidence": "high",
            "rationale": "Tool call targeted external exfiltration endpoint.",
        },
        "evidence": [
            {
                "artifact_id": "art-001",
                "artifact_type": "tool_call_log",
                "label": "Suspicious shell invocation",
            },
            {
                "artifact_id": "art-002",
                "artifact_type": "prompt_snapshot",
                "label": "Injected instruction fragment",
            },
        ],
        "requires_human_review": requires_human_review,
        "containment_recommended": containment_recommended,
        "blocked_actions": blocked_actions,
        "quarantined_actions": quarantined_actions,
    }


# ---------------------------------------------------------------------------
# IncidentsOverview — default_incidents_overview
# ---------------------------------------------------------------------------


class TestDefaultIncidentsOverview:
    def test_returns_incidents_overview_instance(self):
        overview = default_incidents_overview()
        assert isinstance(overview, IncidentsOverview)

    def test_default_counters_are_zero(self):
        overview = default_incidents_overview()
        assert overview.total_open == 0
        assert overview.critical_open == 0
        assert overview.high_open == 0
        assert overview.under_review == 0
        assert overview.contained == 0
        assert overview.mean_time_to_contain_minutes == 0

    def test_default_incidents_tuple_is_empty(self):
        overview = default_incidents_overview()
        assert overview.incidents == ()

    def test_generated_at_is_utc_aware(self):
        overview = default_incidents_overview()
        assert overview.generated_at.tzinfo is not None


# ---------------------------------------------------------------------------
# IncidentsOverview — build_incidents_overview
# ---------------------------------------------------------------------------


class TestBuildIncidentsOverview:
    def test_builds_from_full_payload(self):
        data = {
            "total_open": 5,
            "critical_open": 2,
            "high_open": 1,
            "under_review": 3,
            "contained": 1,
            "mean_time_to_contain_minutes": 45,
            "incidents": [_make_incident_dict()],
        }
        overview = build_incidents_overview(data)
        assert overview.total_open == 5
        assert overview.critical_open == 2
        assert overview.high_open == 1
        assert overview.under_review == 3
        assert overview.contained == 1
        assert overview.mean_time_to_contain_minutes == 45
        assert len(overview.incidents) == 1

    def test_none_payload_returns_default(self):
        overview = build_incidents_overview(None)
        assert isinstance(overview, IncidentsOverview)
        assert overview.incidents == ()

    def test_empty_dict_returns_default_structure(self):
        overview = build_incidents_overview({})
        assert isinstance(overview, IncidentsOverview)

    def test_derives_total_open_from_incidents_when_absent(self):
        data = {
            "incidents": [
                _make_incident_dict(incident_id="inc-001", status="open"),
                _make_incident_dict(incident_id="inc-002", status="investigating"),
                _make_incident_dict(incident_id="inc-003", status="resolved"),
            ]
        }
        overview = build_incidents_overview(data)
        assert overview.total_open == 2

    def test_derives_critical_open_count_from_incidents(self):
        data = {
            "incidents": [
                _make_incident_dict(incident_id="inc-001", severity="critical", status="open"),
                _make_incident_dict(incident_id="inc-002", severity="critical", status="resolved"),
                _make_incident_dict(incident_id="inc-003", severity="high", status="open"),
            ]
        }
        overview = build_incidents_overview(data)
        assert overview.critical_open == 1

    def test_derives_high_open_count_from_incidents(self):
        data = {
            "incidents": [
                _make_incident_dict(incident_id="inc-001", severity="high", status="open"),
                _make_incident_dict(incident_id="inc-002", severity="high", status="closed"),
                _make_incident_dict(incident_id="inc-003", severity="critical", status="open"),
            ]
        }
        overview = build_incidents_overview(data)
        assert overview.high_open == 1

    def test_derives_under_review_from_requires_human_review_flag(self):
        data = {
            "incidents": [
                _make_incident_dict(incident_id="inc-001", status="open", requires_human_review=True),
                _make_incident_dict(incident_id="inc-002", status="open", requires_human_review=False),
            ]
        }
        overview = build_incidents_overview(data)
        assert overview.under_review >= 1

    def test_derives_contained_from_incident_status(self):
        data = {
            "incidents": [
                _make_incident_dict(incident_id="inc-001", status="contained"),
                _make_incident_dict(incident_id="inc-002", status="open"),
            ]
        }
        overview = build_incidents_overview(data)
        assert overview.contained == 1

    def test_counters_never_go_negative(self):
        data = {
            "total_open": -10,
            "critical_open": -5,
            "high_open": -1,
            "under_review": -3,
            "contained": -2,
            "mean_time_to_contain_minutes": -99,
        }
        overview = build_incidents_overview(data)
        assert overview.total_open >= 0
        assert overview.critical_open >= 0
        assert overview.high_open >= 0
        assert overview.under_review >= 0
        assert overview.contained >= 0
        assert overview.mean_time_to_contain_minutes >= 0

    def test_ignores_invalid_incident_entries_in_list(self):
        data = {
            "incidents": [
                None,
                "not-a-dict",
                42,
                {},
                _make_incident_dict(incident_id="inc-valid"),
            ]
        }
        overview = build_incidents_overview(data)
        assert len(overview.incidents) == 1
        assert overview.incidents[0].incident_id == "inc-valid"

    def test_applies_baseline_when_source_is_empty(self):
        baseline = build_incidents_overview(
            {
                "total_open": 3,
                "incidents": [_make_incident_dict()],
            }
        )
        overview = build_incidents_overview({}, baseline=baseline)
        assert overview.incidents == baseline.incidents

    def test_generated_at_is_utc_aware(self):
        overview = build_incidents_overview({"generated_at": "2024-06-01T00:00:00Z"})
        assert overview.generated_at.tzinfo is not None

    def test_generated_at_parses_iso_string(self):
        overview = build_incidents_overview({"generated_at": "2024-06-01T12:00:00Z"})
        assert overview.generated_at.year == 2024
        assert overview.generated_at.month == 6

    def test_non_list_incidents_value_preserves_baseline_incidents(self):
        baseline = build_incidents_overview({"incidents": [_make_incident_dict()]})
        overview = build_incidents_overview({"incidents": "invalid"}, baseline=baseline)
        assert overview.incidents == baseline.incidents

    def test_multiple_incidents_are_all_normalized(self):
        data = {
            "incidents": [
                _make_incident_dict(incident_id="inc-001"),
                _make_incident_dict(incident_id="inc-002"),
                _make_incident_dict(incident_id="inc-003"),
            ]
        }
        overview = build_incidents_overview(data)
        assert len(overview.incidents) == 3
        ids = {inc.incident_id for inc in overview.incidents}
        assert ids == {"inc-001", "inc-002", "inc-003"}


# ---------------------------------------------------------------------------
# IncidentRecord — to_dict contract
# ---------------------------------------------------------------------------


class TestIncidentRecordToDict:
    def setup_method(self):
        now = datetime.now(UTC)
        self.record = IncidentRecord(
            incident_id="inc-001",
            title="Prompt injection detected",
            severity="critical",
            status="open",
            source="runtime",
            affected_surface="agent",
            opened_at=now,
            updated_at=now,
            owner=IncidentOwner(owner_id="owner-001", display_name="SOC Team", team="soc"),
            requires_human_review=True,
            quarantined_actions=2,
            blocked_actions=1,
            evidence_count=3,
        )

    def test_to_dict_contains_all_required_keys(self):
        d = self.record.to_dict()
        required_keys = {
            "incident_id",
            "title",
            "severity",
            "status",
            "source",
            "affected_surface",
            "opened_at",
            "updated_at",
            "owner",
            "requires_human_review",
            "quarantined_actions",
            "blocked_actions",
            "evidence_count",
        }
        assert required_keys.issubset(d.keys())

    def test_to_dict_opened_at_is_iso_string_ending_in_z(self):
        d = self.record.to_dict()
        assert isinstance(d["opened_at"], str)
        assert d["opened_at"].endswith("Z")

    def test_to_dict_updated_at_is_iso_string_ending_in_z(self):
        d = self.record.to_dict()
        assert isinstance(d["updated_at"], str)
        assert d["updated_at"].endswith("Z")

    def test_to_dict_owner_is_dict_with_expected_keys(self):
        d = self.record.to_dict()
        assert isinstance(d["owner"], dict)
        assert "owner_id" in d["owner"]
        assert "display_name" in d["owner"]
        assert "team" in d["owner"]

    def test_to_dict_counters_match_record(self):
        d = self.record.to_dict()
        assert d["quarantined_actions"] == 2
        assert d["blocked_actions"] == 1
        assert d["evidence_count"] == 3

    def test_to_dict_severity_and_status_match_record(self):
        d = self.record.to_dict()
        assert d["severity"] == "critical"
        assert d["status"] == "open"


# ---------------------------------------------------------------------------
# IncidentsOverview — to_dict contract
# ---------------------------------------------------------------------------


class TestIncidentsOverviewToDict:
    def test_to_dict_contains_all_required_keys(self):
        overview = build_incidents_overview(
            {
                "total_open": 2,
                "critical_open": 1,
                "incidents": [_make_incident_dict()],
            }
        )
        d = overview.to_dict()
        required_keys = {
            "total_open",
            "critical_open",
            "high_open",
            "under_review",
            "contained",
            "mean_time_to_contain_minutes",
            "incidents",
            "generated_at",
        }
        assert required_keys.issubset(d.keys())

    def test_to_dict_incidents_is_list_of_dicts(self):
        overview = build_incidents_overview({"incidents": [_make_incident_dict()]})
        d = overview.to_dict()
        assert isinstance(d["incidents"], list)
        assert isinstance(d["incidents"][0], dict)

    def test_to_dict_generated_at_ends_in_z(self):
        overview = build_incidents_overview({"generated_at": "2024-06-01T00:00:00Z"})
        d = overview.to_dict()
        assert d["generated_at"].endswith("Z")

    def test_to_dict_empty_incidents_list(self):
        overview = default_incidents_overview()
        d = overview.to_dict()
        assert d["incidents"] == []


# ---------------------------------------------------------------------------
# incidents_overview_summary contract
# ---------------------------------------------------------------------------


class TestIncidentsOverviewSummary:
    def test_summary_contains_counts_block(self):
        overview = build_incidents_overview(
            {
                "total_open": 3,
                "critical_open": 1,
                "high_open": 1,
                "under_review": 2,
                "contained": 1,
                "incidents": [_make_incident_dict()],
            }
        )
        summary = incidents_overview_summary(overview)
        assert "counts" in summary
        counts = summary["counts"]
        assert counts["total_open"] == 3
        assert counts["critical_open"] == 1
        assert counts["high_open"] == 1
        assert counts["under_review"] == 2
        assert counts["contained"] == 1

    def test_summary_contains_metrics_block(self):
        overview = build_incidents_overview(
            {
                "mean_time_to_contain_minutes": 60,
                "incidents": [_make_incident_dict(quarantined_actions=2, blocked_actions=1, evidence_count=3)],
            }
        )
        summary = incidents_overview_summary(overview)
        assert "metrics" in summary
        metrics = summary["metrics"]
        assert metrics["mean_time_to_contain_minutes"] == 60
        assert metrics["total_quarantined_actions"] == 2
        assert metrics["total_blocked_actions"] == 1
        assert metrics["total_evidence"] == 3

    def test_summary_aggregates_actions_across_incidents(self):
        data = {
            "incidents": [
                _make_incident_dict(incident_id="inc-001", quarantined_actions=3, blocked_actions=2, evidence_count=5),
                _make_incident_dict(incident_id="inc-002", quarantined_actions=1, blocked_actions=0, evidence_count=2),
            ]
        }
        overview = build_incidents_overview(data)
        summary = incidents_overview_summary(overview)
        assert summary["metrics"]["total_quarantined_actions"] == 4
        assert summary["metrics"]["total_blocked_actions"] == 2
        assert summary["metrics"]["total_evidence"] == 7

    def test_summary_contains_incidents_list(self):
        overview = build_incidents_overview({"incidents": [_make_incident_dict()]})
        summary = incidents_overview_summary(overview)
        assert "incidents" in summary
        assert isinstance(summary["incidents"], list)

    def test_summary_contains_generated_at(self):
        overview = build_incidents_overview({})
        summary = incidents_overview_summary(overview)
        assert "generated_at" in summary

    def test_summary_empty_overview_has_zero_metrics(self):
        overview = default_incidents_overview()
        summary = incidents_overview_summary(overview)
        assert summary["metrics"]["total_quarantined_actions"] == 0
        assert summary["metrics"]["total_blocked_actions"] == 0
        assert summary["metrics"]["total_evidence"] == 0


# ---------------------------------------------------------------------------
# IncidentTriage — default_incident_triage
# ---------------------------------------------------------------------------


class TestDefaultIncidentTriage:
    def test_returns_incident_triage_instance(self):
        triage = default_incident_triage()
        assert isinstance(triage, IncidentTriage)

    def test_default_severity_is_medium(self):
        triage = default_incident_triage()
        assert triage.severity == "medium"

    def test_default_status_is_triage(self):
        triage = default_incident_triage()
        assert triage.status == "triage"

    def test_default_source_is_runtime(self):
        triage = default_incident_triage()
        assert triage.source == "runtime"

    def test_default_assignment_has_fallback_queue(self):
        triage = default_incident_triage()
        assert triage.assignment.queue == "incident-triage"

    def test_default_decision_is_investigate(self):
        triage = default_incident_triage()
        assert triage.decision.decision == "investigate"

    def test_default_evidence_is_empty_tuple(self):
        triage = default_incident_triage()
        assert triage.evidence == ()

    def test_default_counters_are_zero(self):
        triage = default_incident_triage()
        assert triage.blocked_actions == 0
        assert triage.quarantined_actions == 0

    def test_generated_at_is_utc_aware(self):
        triage = default_incident_triage()
        assert triage.generated_at.tzinfo is not None


# ---------------------------------------------------------------------------
# IncidentTriage — build_incident_triage
# ---------------------------------------------------------------------------


class TestBuildIncidentTriage:
    def test_builds_from_full_payload(self):
        data = _make_triage_dict()
        triage = build_incident_triage(data)
        assert triage.incident_id == "inc-001"
        assert triage.title == "Prompt injection detected"
        assert triage.severity == "critical"
        assert triage.status == "triage"
        assert triage.source == "runtime"
        assert triage.summary == "Suspected prompt injection via tool call chain."

    def test_none_payload_returns_default(self):
        triage = build_incident_triage(None)
        assert isinstance(triage, IncidentTriage)

    def test_empty_dict_returns_default_structure(self):
        triage = build_incident_triage({})
        assert isinstance(triage, IncidentTriage)

    def test_assignment_is_populated_from_payload(self):
        data = _make_triage_dict()
        triage = build_incident_triage(data)
        assert triage.assignment.owner_id == "owner-001"
        assert triage.assignment.display_name == "Security Analyst"
        assert triage.assignment.queue == "incident-triage"
        assert triage.assignment.team == "soc"

    def test_decision_is_populated_from_payload(self):
        data = _make_triage_dict()
        triage = build_incident_triage(data)
        assert triage.decision.decision == "quarantine"
        assert triage.decision.confidence == "high"
        assert "exfiltration" in triage.decision.rationale

    def test_evidence_artifacts_are_normalized(self):
        data = _make_triage_dict()
        triage = build_incident_triage(data)
        assert len(triage.evidence) == 2
        assert triage.evidence[0].artifact_id == "art-001"
        assert triage.evidence[0].artifact_type == "tool_call_log"
        assert triage.evidence[1].artifact_id == "art-002"

    def test_requires_human_review_is_true_when_set(self):
        data = _make_triage_dict(requires_human_review=True)
        triage = build_incident_triage(data)
        assert triage.requires_human_review is True

    def test_requires_human_review_is_false_when_unset(self):
        data = _make_triage_dict(requires_human_review=False)
        triage = build_incident_triage(data)
        assert triage.requires_human_review is False

    def test_containment_recommended_is_true_when_set(self):
        data = _make_triage_dict(containment_recommended=True)
        triage = build_incident_triage(data)
        assert triage.containment_recommended is True

    def test_counters_never_go_negative(self):
        data = _make_triage_dict(blocked_actions=-5, quarantined_actions=-3)
        triage = build_incident_triage(data)
        assert triage.blocked_actions >= 0
        assert triage.quarantined_actions >= 0

    def test_ignores_invalid_evidence_entries(self):
        data = _make_triage_dict()
        data["evidence"] = [None, "invalid", {}, {"artifact_id": "art-valid", "artifact_type": "log", "label": "Valid"}]
        triage = build_incident_triage(data)
        assert len(triage.evidence) == 1
        assert triage.evidence[0].artifact_id == "art-valid"

    def test_non_list_evidence_preserves_baseline_evidence(self):
        baseline_data = _make_triage_dict()
        baseline = build_incident_triage(baseline_data)
        updated_data = {"evidence": "invalid"}
        triage = build_incident_triage(updated_data, baseline=baseline)
        assert triage.evidence == baseline.evidence

    def test_applies_baseline_assignment_when_absent(self):
        baseline = build_incident_triage(_make_triage_dict())
        triage = build_incident_triage({}, baseline=baseline)
        assert triage.assignment.owner_id == baseline.assignment.owner_id

    def test_opened_at_is_utc_aware(self):
        triage = build_incident_triage(_make_triage_dict())
        assert triage.opened_at.tzinfo is not None

    def test_updated_at_is_utc_aware(self):
        triage = build_incident_triage(_make_triage_dict())
        assert triage.updated_at.tzinfo is not None

    def test_generated_at_is_utc_aware(self):
        triage = build_incident_triage({"generated_at": "2024-06-01T00:00:00Z"})
        assert triage.generated_at.tzinfo is not None

    def test_string_bool_true_coerced_for_requires_human_review(self):
        data = _make_triage_dict()
        data["requires_human_review"] = "true"
        triage = build_incident_triage(data)
        assert triage.requires_human_review is True

    def test_string_bool_false_coerced_for_containment_recommended(self):
        data = _make_triage_dict()
        data["containment_recommended"] = "false"
        triage = build_incident_triage(data)
        assert triage.containment_recommended is False

    def test_missing_assignment_key_falls_back_to_baseline(self):
        baseline = build_incident_triage(_make_triage_dict())
        data = {"incident_id": "inc-updated", "title": "Updated title"}
        triage = build_incident_triage(data, baseline=baseline)
        assert triage.assignment == baseline.assignment

    def test_missing_decision_key_falls_back_to_baseline(self):
        baseline = build_incident_triage(_make_triage_dict())
        data = {"incident_id": "inc-updated"}
        triage = build_incident_triage(data, baseline=baseline)
        assert triage.decision.decision == baseline.decision.decision


# ---------------------------------------------------------------------------
# IncidentTriage — to_dict contract
# ---------------------------------------------------------------------------


class TestIncidentTriageToDict:
    def setup_method(self):
        self.triage = build_incident_triage(_make_triage_dict())

    def test_to_dict_contains_all_required_keys(self):
        d = self.triage.to_dict()
        required_keys = {
            "incident_id",
            "title",
            "severity",
            "status",
            "source",
            "summary",
            "opened_at",
            "updated_at",
            "assignment",
            "decision",
            "evidence",
            "requires_human_review",
            "containment_recommended",
            "blocked_actions",
            "quarantined_actions",
            "generated_at",
        }
        assert required_keys.issubset(d.keys())

    def test_to_dict_opened_at_ends_in_z(self):
        d = self.triage.to_dict()
        assert d["opened_at"].endswith("Z")

    def test_to_dict_updated_at_ends_in_z(self):
        d = self.triage.to_dict()
        assert d["updated_at"].endswith("Z")

    def test_to_dict_generated_at_ends_in_z(self):
        d = self.triage.to_dict()
        assert d["generated_at"].endswith("Z")

    def test_to_dict_assignment_is_dict_with_expected_keys(self):
        d = self.triage.to_dict()
        assert isinstance(d["assignment"], dict)
        assert "owner_id" in d["assignment"]
        assert "display_name" in d["assignment"]
        assert "queue" in d["assignment"]
        assert "team" in d["assignment"]

    def test_to_dict_decision_is_dict_with_expected_keys(self):
        d = self.triage.to_dict()
        assert isinstance(d["decision"], dict)
        assert "decision" in d["decision"]
        assert "confidence" in d["decision"]
        assert "rationale" in d["decision"]

    def test_to_dict_evidence_is_list_of_dicts(self):
        d = self.triage.to_dict()
        assert isinstance(d["evidence"], list)
        for artifact in d["evidence"]:
            assert isinstance(artifact, dict)
            assert "artifact_id" in artifact
            assert "artifact_type" in artifact
            assert "label" in artifact

    def test_to_dict_bool_flags_are_python_bools(self):
        d = self.triage.to_dict()
        assert isinstance(d["requires_human_review"], bool)
        assert isinstance(d["containment_recommended"], bool)

    def test_to_dict_counters_are_integers(self):
        d = self.triage.to_dict()
        assert isinstance(d["blocked_actions"], int)
        assert isinstance(d["quarantined_actions"], int)


# ---------------------------------------------------------------------------
# incident_triage_summary contract
# ---------------------------------------------------------------------------


class TestIncidentTriageSummary:
    def setup_method(self):
        self.triage = build_incident_triage(_make_triage_dict())

    def test_summary_contains_all_top_level_keys(self):
        summary = incident_triage_summary(self.triage)
        required_keys = {
            "incident_id",
            "title",
            "severity",
            "status",
            "source",
            "summary",
            "timeline",
            "assignment",
            "decision",
            "signals",
            "evidence",
        }
        assert required_keys.issubset(summary.keys())

    def test_summary_timeline_contains_timestamps(self):
        summary = incident_triage_summary(self.triage)
        assert "opened_at" in summary["timeline"]
        assert "updated_at" in summary["timeline"]
        assert "generated_at" in summary["timeline"]

    def test_summary_timeline_timestamps_end_in_z(self):
        summary = incident_triage_summary(self.triage)
        for key in ("opened_at", "updated_at", "generated_at"):
            assert summary["timeline"][key].endswith("Z"), f"{key} does not end in Z"

    def test_summary_signals_block_is_complete(self):
        summary = incident_triage_summary(self.triage)
        signals = summary["signals"]
        assert "requires_human_review" in signals
        assert "containment_recommended" in signals
        assert "blocked_actions" in signals
        assert "quarantined_actions" in signals
        assert "evidence_count" in signals

    def test_summary_evidence_count_matches_evidence_length(self):
        summary = incident_triage_summary(self.triage)
        assert summary["signals"]["evidence_count"] == len(self.triage.evidence)

    def test_summary_assignment_matches_triage_assignment(self):
        summary = incident_triage_summary(self.triage)
        assert summary["assignment"]["owner_id"] == self.triage.assignment.owner_id
        assert summary["assignment"]["queue"] == self.triage.assignment.queue

    def test_summary_decision_matches_triage_decision(self):
        summary = incident_triage_summary(self.triage)
        assert summary["decision"]["decision"] == self.triage.decision.decision
        assert summary["decision"]["confidence"] == self.triage.decision.confidence

    def test_summary_evidence_is_list_of_dicts(self):
        summary = incident_triage_summary(self.triage)
        assert isinstance(summary["evidence"], list)
        for item in summary["evidence"]:
            assert isinstance(item, dict)

    def test_summary_incident_id_matches(self):
        summary = incident_triage_summary(self.triage)
        assert summary["incident_id"] == "inc-001"

    def test_summary_severity_matches(self):
        summary = incident_triage_summary(self.triage)
        assert summary["severity"] == "critical"

    def test_summary_with_zero_evidence(self):
        data = _make_triage_dict()
        data["evidence"] = []
        triage = build_incident_triage(data)
        summary = incident_triage_summary(triage)
        assert summary["signals"]["evidence_count"] == 0
        assert summary["evidence"] == []


# ---------------------------------------------------------------------------
# TriageAssignment / TriageDecision / TriageArtifact — fallback normalization
# ---------------------------------------------------------------------------


class TestTriageFallbackNormalization:
    def test_missing_assignment_falls_back_to_unassigned(self):
        triage = build_incident_triage({"incident_id": "inc-x"})
        assert triage.assignment.display_name == "Unassigned"
        assert triage.assignment.queue == "incident-triage"

    def test_missing_decision_falls_back_to_investigate(self):
        triage = build_incident_triage({"incident_id": "inc-x"})
        assert triage.decision.decision == "investigate"
        assert triage.decision.confidence == "medium"

    def test_invalid_assignment_dict_falls_back_gracefully(self):
        data = _make_triage_dict()
        data["assignment"] = "not-a-dict"
        triage = build_incident_triage(data)
        assert triage.assignment.display_name == "Unassigned"

    def test_invalid_decision_dict_falls_back_gracefully(self):
        data = _make_triage_dict()
        data["decision"] = 42
        triage = build_incident_triage(data)
        assert triage.decision.decision == "investigate"

    def test_artifact_missing_all_fields_is_dropped(self):
        data = _make_triage_dict()
        data["evidence"] = [{}]
        triage = build_incident_triage(data)
        assert triage.evidence == ()


# ---------------------------------------------------------------------------
# IncidentOwner — to_dict contract
# ---------------------------------------------------------------------------


class TestIncidentOwnerToDict:
    def test_to_dict_contains_expected_keys(self):
        owner = IncidentOwner(owner_id="owner-001", display_name="SOC Team", team="soc")
        d = owner.to_dict()
        assert d["owner_id"] == "owner-001"
        assert d["display_name"] == "SOC Team"
        assert d["team"] == "soc"

    def test_to_dict_empty_team_is_empty_string(self):
        owner = IncidentOwner(owner_id="owner-001", display_name="Unassigned")
        d = owner.to_dict()
        assert d["team"] == ""


# ---------------------------------------------------------------------------
# Edge cases — coercion and boundary behavior
# ---------------------------------------------------------------------------


class TestIncidentCoercionEdgeCases:
    def test_integer_requires_human_review_coerces_to_bool(self):
        data = _make_incident_dict()
        data["requires_human_review"] = 1
        overview = build_incidents_overview({"incidents": [data]})
        assert overview.incidents[0].requires_human_review is True

    def test_zero_requires_human_review_coerces_to_false(self):
        data = _make_incident_dict()
        data["requires_human_review"] = 0
        overview = build_incidents_overview({"incidents": [data]})
        assert overview.incidents[0].requires_human_review is False

    def test_negative_quarantined_actions_clamped_to_zero(self):
        data = _make_incident_dict(quarantined_actions=-5)
        overview = build_incidents_overview({"incidents": [data]})
        assert overview.incidents[0].quarantined_actions == 0

    def test_negative_blocked_actions_clamped_to_zero(self):
        data = _make_incident_dict(blocked_actions=-99)
        overview = build_incidents_overview({"incidents": [data]})
        assert overview.incidents[0].blocked_actions == 0

    def test_negative_evidence_count_clamped_to_zero(self):
        data = _make_incident_dict(evidence_count=-10)
        overview = build_incidents_overview({"incidents": [data]})
        assert overview.incidents[0].evidence_count == 0

    def test_incident_with_only_title_is_normalized(self):
        data = {"title": "Minimal incident", "opened_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
        overview = build_incidents_overview({"incidents": [data]})
        assert len(overview.incidents) == 1
        assert overview.incidents[0].title == "Minimal incident"

    def test_incident_with_only_incident_id_is_normalized(self):
        data = {"incident_id": "inc-minimal", "opened_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"}
        overview = build_incidents_overview({"incidents": [data]})
        assert len(overview.incidents) == 1
        assert overview.incidents[0].incident_id == "inc-minimal"

    def test_incident_with_neither_id_nor_title_is_dropped(self):
        data = {"severity": "high", "status": "open"}
        overview = build_incidents_overview({"incidents": [data]})
        assert len(overview.incidents) == 0

    def test_datetime_with_no_timezone_is_made_utc_aware(self):
        data = _make_triage_dict()
        data["opened_at"] = "2024-01-15T10:00:00"
        triage = build_incident_triage(data)
        assert triage.opened_at.tzinfo is not None

    def test_string_severity_is_preserved_as_is(self):
        data = _make_incident_dict(severity="low")
        overview = build_incidents_overview({"incidents": [data]})
        assert overview.incidents[0].severity == "low"

    def test_string_status_is_preserved_as_is(self):
        data = _make_incident_dict(status="investigating")
        overview = build_incidents_overview({"incidents": [data]})
        assert overview.incidents[0].status == "investigating"
