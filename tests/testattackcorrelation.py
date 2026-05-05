import pytest

from app.services.attackcorrelation import AttackCorrelationService


class FakeIncidentStore:
    def __init__(self) -> None:
        self.lookup_payloads = []
        self.saved_incidents = []

    def find_by_attack_fingerprint(self, **payload):
        self.lookup_payloads.append(payload)
        return None

    def upsert_incident(self, **payload):
        self.saved_incidents.append(payload)
        return payload


class FakeReviewQueueService:
    def __init__(self) -> None:
        self.enqueued = []

    def enqueue(self, **payload):
        self.enqueued.append(payload)
        return {"review_id": "rev-001"}


class FakeQuarantineStore:
    def __init__(self) -> None:
        self.records = []

    def create_record(self, **payload):
        self.records.append(payload)
        return {"quarantine_id": "quar-001"}


class FakePlaybookRegistry:
    def __init__(self) -> None:
        self.requests = []

    def resolve(self, **payload):
        self.requests.append(payload)
        return {"playbooks": ["critical-incident-response", "malware-containment"]}


class FakeRemediationGate:
    def __init__(self) -> None:
        self.requests = []

    def open_actions(self, **payload):
        self.requests.append(payload)
        return {
            "actions": [
                {
                    "action_id": "act-001",
                    "action": "disable-session",
                    "status": "open",
                }
            ]
        }


class FakeMalwareService:
    def __init__(self, result=None) -> None:
        self.result = result or {}
        self.requests = []

    def summarize(self, **payload):
        self.requests.append(payload)
        return self.result


class FakeDetonationService:
    def __init__(self, result=None) -> None:
        self.result = result or {}
        self.requests = []

    def summarize(self, **payload):
        self.requests.append(payload)
        return self.result


class FakeHostileContextService:
    def __init__(self, result=None) -> None:
        self.result = result or {}
        self.requests = []

    def summarize(self, **payload):
        self.requests.append(payload)
        return self.result


def test_correlate_returns_observed_incident_for_single_medium_signal():
    incident_store = FakeIncidentStore()
    service = AttackCorrelationService(incident_store=incident_store)

    result = service.correlate(
        [
            {
                "signal_id": "sig-001",
                "signal_type": "prompt_injection",
                "source": "prompt_guard",
                "severity": "medium",
                "summary": "Prompt injection attempt detected",
                "score": 45,
                "evidence": {
                    "prompt_fingerprints": ["pf-001"],
                    "tools": ["shell"],
                },
            }
        ],
        session_id="sess-001",
        actor_id="actor-001",
        organization_id="org-001",
    )

    assert result["risk_score"] == 45
    assert result["risk_band"] == "medium"
    assert result["incident"]["status"] == "observed"
    assert result["incident"]["severity"] == "medium"
    assert result["incident"]["signal_count"] == 1
    assert result["incident"]["linked_reviews"] == []
    assert result["incident"]["linked_quarantine_records"] == []
    assert result["incident"]["escalation_actions"] == []
    assert result["incident"]["indicators"]["tools"] == ["shell"]
    assert result["incident"]["indicators"]["prompt_fingerprints"] == ["pf-001"]
    assert incident_store.saved_incidents
    assert incident_store.saved_incidents[0]["incident_id"] == result["incident"]["incident_id"]


def test_correlate_enriches_with_services_and_creates_response_artifacts():
    incident_store = FakeIncidentStore()
    review_queue_service = FakeReviewQueueService()
    quarantine_store = FakeQuarantineStore()
    playbook_registry = FakePlaybookRegistry()
    remediation_gate = FakeRemediationGate()
    malware_service = FakeMalwareService(
        {
            "summary": "Known malicious payload family identified",
            "severity": "critical",
            "risk_score": 91,
            "verdict": "malicious",
            "families": ["redclaw"],
            "hashes": ["sha256:deadbeef"],
            "files": ["payload.py"],
        }
    )
    detonation_service = FakeDetonationService(
        {
            "summary": "Sandbox execution attempted outbound command and beaconing",
            "severity": "high",
            "risk_score": 88,
            "verdict": "blocked",
            "domains": ["evil.example"],
            "ips": ["10.0.0.9"],
            "hashes": ["sha256:deadbeef"],
        }
    )
    hostile_context_service = FakeHostileContextService(
        {
            "summary": "Activity overlaps with known operator cluster",
            "severity": "high",
            "risk_score": 77,
            "campaign": "night-harvest",
            "cluster": "cluster-7",
            "ttp_ids": ["T1059", "T1105"],
        }
    )

    service = AttackCorrelationService(
        incident_store=incident_store,
        review_queue_service=review_queue_service,
        quarantine_store=quarantine_store,
        playbook_registry=playbook_registry,
        remediation_gate=remediation_gate,
        malware_service=malware_service,
        detonation_service=detonation_service,
        hostile_context_service=hostile_context_service,
    )

    result = service.correlate(
        [
            {
                "signal_id": "sig-raw-001",
                "signal_type": "artifact_download",
                "source": "runtime_guard",
                "severity": "high",
                "summary": "Downloaded executable artifact during tool run",
                "score": 74,
                "evidence": {
                    "files": ["payload.py"],
                    "hashes": ["sha256:deadbeef"],
                    "tools": ["python"],
                },
            }
        ],
        session_id="sess-222",
        actor_id="actor-222",
        organization_id="org-222",
        request_id="req-222",
        metadata={"origin": "runtime"},
    )

    assert result["risk_score"] == 100
    assert result["risk_band"] == "critical"
    assert result["confidence"] >= 0.75
    assert result["linked_reviews"] == ["rev-001"]
    assert result["linked_quarantine_records"] == ["quar-001"]
    assert result["recommended_playbooks"] == ["critical-incident-response", "malware-containment"]
    assert result["incident"]["status"] == "quarantined"
    assert result["incident"]["severity"] == "critical"
    assert result["incident"]["malware_summary"]["verdict"] == "malicious"
    assert result["incident"]["detonation_summary"]["verdict"] == "blocked"
    assert result["incident"]["hostile_context"]["campaign"] == "night-harvest"
    assert result["incident"]["indicators"]["hashes"] == ["sha256:deadbeef"]
    assert result["incident"]["indicators"]["domains"] == ["evil.example"]
    assert result["incident"]["indicators"]["ips"] == ["10.0.0.9"]
    assert result["incident"]["indicators"]["campaigns"] == ["night-harvest"]
    assert result["incident"]["indicators"]["clusters"] == ["cluster-7"]
    assert result["incident"]["indicators"]["ttp_ids"] == ["T1059", "T1105"]
    assert len(result["signals"]) == 4
    assert review_queue_service.enqueued
    assert quarantine_store.records
    assert remediation_gate.requests
    assert playbook_registry.requests
    assert malware_service.requests
    assert detonation_service.requests
    assert hostile_context_service.requests


def test_correlate_uses_existing_incident_id_when_lookup_matches():
    class ExistingIncidentStore(FakeIncidentStore):
        def find_by_attack_fingerprint(self, **payload):
            self.lookup_payloads.append(payload)
            return {"incident_id": "inc-existing-123"}

    incident_store = ExistingIncidentStore()
    service = AttackCorrelationService(incident_store=incident_store)

    result = service.correlate(
        [
            {
                "signal_id": "sig-lookup-001",
                "signal_type": "prompt_injection",
                "source": "prompt_guard",
                "severity": "high",
                "summary": "Existing attack fingerprint should reuse incident",
                "score": 70,
            }
        ],
        session_id="sess-existing",
        organization_id="org-existing",
    )

    assert result["incident"]["incident_id"] == "inc-existing-123"
    assert incident_store.saved_incidents[0]["incident_id"] == "inc-existing-123"


def test_correlate_deduplicates_indicators_and_handles_missing_services():
    incident_store = FakeIncidentStore()
    service = AttackCorrelationService(incident_store=incident_store)

    result = service.correlate(
        [
            {
                "signal_id": "sig-a",
                "signal_type": "data_exfiltration",
                "source": "egress_guard",
                "severity": "high",
                "summary": "Outbound transfer detected",
                "score": 68,
                "evidence": {
                    "domains": ["dup.example", "dup.example"],
                    "ips": ["1.1.1.1", "1.1.1.1"],
                    "files": ["secret.txt", "secret.txt"],
                    "tools": ["curl", "curl"],
                },
            },
            {
                "signal_id": "sig-b",
                "signal_type": "data_exfiltration",
                "source": "egress_guard",
                "severity": "high",
                "summary": "Second transfer detected",
                "score": 68,
                "evidence": {
                    "domains": ["dup.example"],
                    "ips": ["1.1.1.1"],
                    "files": ["secret.txt"],
                    "tools": ["curl"],
                },
            },
        ]
    )

    assert result["incident"]["indicators"]["domains"] == ["dup.example"]
    assert result["incident"]["indicators"]["ips"] == ["1.1.1.1"]
    assert result["incident"]["indicators"]["files"] == ["secret.txt"]
    assert result["incident"]["indicators"]["tools"] == ["curl"]
    assert result["recommended_playbooks"] == ["exfiltration-containment"]
    assert result["incident"]["status"] == "observed"


def test_correlate_opens_review_and_actions_for_high_risk_without_quarantine():
    incident_store = FakeIncidentStore()
    review_queue_service = FakeReviewQueueService()
    remediation_gate = FakeRemediationGate()

    service = AttackCorrelationService(
        incident_store=incident_store,
        review_queue_service=review_queue_service,
        remediation_gate=remediation_gate,
    )

    result = service.correlate(
        [
            {
                "signal_id": "sig-high-001",
                "signal_type": "prompt_injection",
                "source": "prompt_guard",
                "severity": "high",
                "summary": "High-confidence tool hijack attempt",
                "score": 72,
                "evidence": {"tools": ["shell"]},
            }
        ],
        session_id="sess-high",
        actor_id="actor-high",
        organization_id="org-high",
    )

    assert result["risk_score"] == 72
    assert result["linked_reviews"] == ["rev-001"]
    assert result["linked_quarantine_records"] == []
    assert result["escalation_actions"] == [
        {
            "action_id": "act-001",
            "action": "disable-session",
            "status": "open",
        }
    ]
    assert result["incident"]["status"] == "action_required"


@pytest.mark.parametrize(
    ("severity", "expected_score"),
    [
        ("low", 20),
        ("medium", 45),
        ("high", 72),
        ("critical", 92),
    ],
)
def test_default_score_mapping_is_applied_when_signal_score_missing(severity, expected_score):
    service = AttackCorrelationService()

    result = service.correlate(
        [
            {
                "signal_id": f"sig-{severity}",
                "signal_type": "generic",
                "source": "test",
                "severity": severity,
                "summary": "Severity mapping validation",
            }
        ]
    )

    assert result["signals"][0]["score"] == expected_score