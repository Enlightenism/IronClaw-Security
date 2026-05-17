from __future__ import annotations

import re

from fastapi import FastAPI
from fastapi.testclient import TestClient
import pytest

from app.worker.remediation_worker import (
    RemediationJob,
    _next_job_id,
    _paginate_jobs,
    _simulate_execution,
    _utc_now,
    router,
)

# ---------------------------------------------------------------------------
# App fixture
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clear_job_store():
    """Wipe in-memory store and reset counter before every test."""
    import app.worker.remediation_worker as _mod

    _mod._JOBS.clear()
    _mod._JOB_COUNTER = 0
    yield
    _mod._JOBS.clear()
    _mod._JOB_COUNTER = 0


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_CREATE_PAYLOAD: dict = {
    "action_id": "action-abc",
    "kind": "configuration_change",
    "title": "Rotate SSH keys",
    "description": "Rotate all SSH keys on affected host",
    "target": "host-001",
    "requested_by": "operator@ironclaw",
    "max_attempts": 3,
    "metadata": {"incident_id": "INC-999"},
}


def _create_job(client: TestClient, overrides: dict | None = None) -> dict:
    payload = {**_VALID_CREATE_PAYLOAD, **(overrides or {})}
    resp = client.post("/worker/remediation/jobs", json=payload)
    assert resp.status_code == 201
    return resp.json()


# ---------------------------------------------------------------------------
# _utc_now
# ---------------------------------------------------------------------------


def test_utc_now_returns_iso_string():
    ts = _utc_now()
    assert isinstance(ts, str)
    # Basic ISO 8601 shape: YYYY-MM-DDTHH:MM:SS...
    assert re.match(r"\d{4}-\d{2}-\d{2}T", ts)


# ---------------------------------------------------------------------------
# _next_job_id
# ---------------------------------------------------------------------------


def test_next_job_id_increments():
    import app.worker.remediation_worker as _mod

    _mod._JOB_COUNTER = 0
    first = _next_job_id()
    second = _next_job_id()
    assert first == "job-1"
    assert second == "job-2"


# ---------------------------------------------------------------------------
# _paginate_jobs
# ---------------------------------------------------------------------------


def _make_dummy_jobs(n: int) -> list:
    jobs = []
    for i in range(n):
        jobs.append(
            RemediationJob(
                id=f"job-{i}",
                action_id=f"act-{i}",
                kind="other",
                title=f"Job {i}",
                description="desc",
                target="host-x",
                requested_by="sys",
                status="pending",
                created_at=_utc_now(),
                updated_at=_utc_now(),
            )
        )
    return jobs


def test_paginate_jobs_empty():
    result, total, pages = _paginate_jobs([], 1, 10)
    assert result == []
    assert total == 0
    assert pages == 0


def test_paginate_jobs_single_page():
    jobs = _make_dummy_jobs(5)
    result, total, pages = _paginate_jobs(jobs, 1, 10)
    assert len(result) == 5
    assert total == 5
    assert pages == 1


def test_paginate_jobs_multiple_pages():
    jobs = _make_dummy_jobs(25)
    result, total, pages = _paginate_jobs(jobs, 2, 10)
    assert len(result) == 10
    assert total == 25
    assert pages == 3


def test_paginate_jobs_last_page_partial():
    jobs = _make_dummy_jobs(22)
    result, total, pages = _paginate_jobs(jobs, 3, 10)
    assert len(result) == 2
    assert total == 22
    assert pages == 3


def test_paginate_jobs_page_clamps_to_max():
    jobs = _make_dummy_jobs(5)
    result, total, pages = _paginate_jobs(jobs, 999, 10)
    assert len(result) == 5
    assert total == 5


def test_paginate_jobs_page_clamps_to_min():
    jobs = _make_dummy_jobs(5)
    result, total, pages = _paginate_jobs(jobs, 0, 10)
    assert len(result) == 5


# ---------------------------------------------------------------------------
# RemediationJob dataclass
# ---------------------------------------------------------------------------


def test_remediation_job_to_dict_has_all_keys():
    job = RemediationJob(
        id="job-1",
        action_id="act-1",
        kind="access_control",
        title="Block IP",
        description="Block hostile IP",
        target="firewall-01",
        requested_by="analyst",
        status="pending",
        created_at="2025-01-01T00:00:00+00:00",
        updated_at="2025-01-01T00:00:00+00:00",
    )
    d = job.to_dict()
    for key in (
        "id",
        "action_id",
        "kind",
        "title",
        "description",
        "target",
        "requested_by",
        "status",
        "created_at",
        "updated_at",
        "started_at",
        "completed_at",
        "attempts",
        "max_attempts",
        "last_error",
        "metadata",
    ):
        assert key in d


def test_remediation_job_metadata_is_copy():
    job = RemediationJob(
        id="job-1",
        action_id="act-1",
        kind="other",
        title="T",
        description="D",
        target="host",
        requested_by="sys",
        status="pending",
        created_at=_utc_now(),
        updated_at=_utc_now(),
        metadata={"key": "value"},
    )
    d = job.to_dict()
    d["metadata"]["extra"] = "injected"
    assert "extra" not in job.metadata


def test_remediation_job_defaults():
    job = RemediationJob(
        id="j",
        action_id="a",
        kind="other",
        title="T",
        description="D",
        target="t",
        requested_by="r",
        status="pending",
        created_at=_utc_now(),
        updated_at=_utc_now(),
    )
    assert job.attempts == 0
    assert job.max_attempts == 3
    assert job.last_error is None
    assert job.started_at is None
    assert job.completed_at is None
    assert job.metadata == {}


# ---------------------------------------------------------------------------
# _simulate_execution
# ---------------------------------------------------------------------------


def test_simulate_execution_increments_attempts():
    job = RemediationJob(
        id="j",
        action_id="a",
        kind="other",
        title="T",
        description="D",
        target="t",
        requested_by="r",
        status="pending",
        created_at=_utc_now(),
        updated_at=_utc_now(),
    )
    before = job.attempts
    _simulate_execution(job)
    assert job.attempts == before + 1


def test_simulate_execution_sets_started_at_first_call():
    job = RemediationJob(
        id="j",
        action_id="a",
        kind="other",
        title="T",
        description="D",
        target="t",
        requested_by="r",
        status="pending",
        created_at=_utc_now(),
        updated_at=_utc_now(),
    )
    _simulate_execution(job)
    assert job.started_at is not None


def test_simulate_execution_preserves_started_at_on_retry():
    job = RemediationJob(
        id="j",
        action_id="a",
        kind="other",
        title="T",
        description="D",
        target="t",
        requested_by="r",
        status="pending",
        created_at=_utc_now(),
        updated_at=_utc_now(),
        started_at="2025-01-01T00:00:00+00:00",
    )
    _simulate_execution(job)
    assert job.started_at == "2025-01-01T00:00:00+00:00"


def test_simulate_execution_sets_terminal_status():
    job = RemediationJob(
        id="j",
        action_id="a",
        kind="other",
        title="T",
        description="D",
        target="t",
        requested_by="r",
        status="running",
        created_at=_utc_now(),
        updated_at=_utc_now(),
    )
    _simulate_execution(job)
    assert job.status in ("succeeded", "failed")
    assert job.completed_at is not None


# ---------------------------------------------------------------------------
# POST /worker/remediation/jobs — create
# ---------------------------------------------------------------------------


def test_create_job_returns_201(client):
    resp = client.post("/worker/remediation/jobs", json=_VALID_CREATE_PAYLOAD)
    assert resp.status_code == 201


def test_create_job_response_shape(client):
    data = _create_job(client)
    for key in (
        "id",
        "action_id",
        "kind",
        "title",
        "description",
        "target",
        "requested_by",
        "status",
        "created_at",
        "updated_at",
        "attempts",
        "max_attempts",
        "metadata",
    ):
        assert key in data


def test_create_job_initial_status_is_pending(client):
    data = _create_job(client)
    assert data["status"] == "pending"


def test_create_job_id_format(client):
    data = _create_job(client)
    assert data["id"].startswith("job-")


def test_create_job_attempts_zero(client):
    data = _create_job(client)
    assert data["attempts"] == 0


def test_create_job_metadata_preserved(client):
    data = _create_job(client)
    assert data["metadata"] == {"incident_id": "INC-999"}


def test_create_job_invalid_kind_422(client):
    bad = {**_VALID_CREATE_PAYLOAD, "kind": "nonexistent_kind"}
    resp = client.post("/worker/remediation/jobs", json=bad)
    assert resp.status_code == 422


def test_create_job_missing_required_field_422(client):
    bad = {k: v for k, v in _VALID_CREATE_PAYLOAD.items() if k != "title"}
    resp = client.post("/worker/remediation/jobs", json=bad)
    assert resp.status_code == 422


def test_create_job_max_attempts_boundary(client):
    data = _create_job(client, {"max_attempts": 10})
    assert data["max_attempts"] == 10


def test_create_job_max_attempts_exceeds_limit_422(client):
    bad = {**_VALID_CREATE_PAYLOAD, "max_attempts": 11}
    resp = client.post("/worker/remediation/jobs", json=bad)
    assert resp.status_code == 422


def test_create_job_max_attempts_below_min_422(client):
    bad = {**_VALID_CREATE_PAYLOAD, "max_attempts": 0}
    resp = client.post("/worker/remediation/jobs", json=bad)
    assert resp.status_code == 422


def test_create_multiple_jobs_unique_ids(client):
    ids = [_create_job(client)["id"] for _ in range(5)]
    assert len(set(ids)) == 5


# ---------------------------------------------------------------------------
# GET /worker/remediation/jobs — list
# ---------------------------------------------------------------------------


def test_list_jobs_empty(client):
    resp = client.get("/worker/remediation/jobs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total_items"] == 0


def test_list_jobs_returns_created(client):
    _create_job(client)
    _create_job(client)
    resp = client.get("/worker/remediation/jobs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_items"] == 2
    assert len(data["items"]) == 2


def test_list_jobs_pagination_shape(client):
    resp = client.get("/worker/remediation/jobs")
    data = resp.json()
    for key in ("items", "page", "page_size", "total_items", "total_pages", "generated_at"):
        assert key in data


def test_list_jobs_filter_by_status(client):
    _create_job(client)
    resp = client.get("/worker/remediation/jobs?status=pending")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_items"] == 1
    assert all(i["status"] == "pending" for i in data["items"])


def test_list_jobs_filter_status_no_match(client):
    _create_job(client)
    resp = client.get("/worker/remediation/jobs?status=succeeded")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_items"] == 0


def test_list_jobs_filter_by_action_id(client):
    _create_job(client, {"action_id": "target-action"})
    _create_job(client, {"action_id": "other-action"})
    resp = client.get("/worker/remediation/jobs?action_id=target-action")
    data = resp.json()
    assert data["total_items"] == 1
    assert data["items"][0]["action_id"] == "target-action"


def test_list_jobs_pagination_page_2(client):
    for _ in range(15):
        _create_job(client)
    resp = client.get("/worker/remediation/jobs?page=2&page_size=10")
    data = resp.json()
    assert len(data["items"]) == 5
    assert data["page"] == 2
    assert data["total_pages"] == 2


def test_list_jobs_page_size_clamp(client):
    resp = client.get("/worker/remediation/jobs?page_size=101")
    assert resp.status_code == 422


def test_list_jobs_page_size_zero_422(client):
    resp = client.get("/worker/remediation/jobs?page_size=0")
    assert resp.status_code == 422


# ---------------------------------------------------------------------------
# GET /worker/remediation/jobs/{job_id} — get single
# ---------------------------------------------------------------------------


def test_get_job_existing(client):
    created = _create_job(client)
    resp = client.get(f"/worker/remediation/jobs/{created['id']}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == created["id"]


def test_get_job_not_found_404(client):
    resp = client.get("/worker/remediation/jobs/job-does-not-exist")
    assert resp.status_code == 404


def test_get_job_response_matches_create(client):
    created = _create_job(client)
    fetched = client.get(f"/worker/remediation/jobs/{created['id']}").json()
    assert fetched["action_id"] == created["action_id"]
    assert fetched["kind"] == created["kind"]
    assert fetched["title"] == created["title"]
    assert fetched["target"] == created["target"]


# ---------------------------------------------------------------------------
# POST /worker/remediation/jobs/{job_id}/execute — execute
# ---------------------------------------------------------------------------


def test_execute_job_returns_200(client):
    created = _create_job(client)
    resp = client.post(f"/worker/remediation/jobs/{created['id']}/execute")
    assert resp.status_code == 200


def test_execute_job_status_is_terminal(client):
    created = _create_job(client)
    data = client.post(f"/worker/remediation/jobs/{created['id']}/execute").json()
    assert data["status"] in ("succeeded", "failed")


def test_execute_job_increments_attempts(client):
    created = _create_job(client)
    data = client.post(f"/worker/remediation/jobs/{created['id']}/execute").json()
    assert data["attempts"] == 1


def test_execute_job_sets_completed_at(client):
    created = _create_job(client)
    data = client.post(f"/worker/remediation/jobs/{created['id']}/execute").json()
    assert data["completed_at"] is not None


def test_execute_job_not_found_404(client):
    resp = client.post("/worker/remediation/jobs/job-ghost/execute")
    assert resp.status_code == 404


def test_execute_job_invalid_status_400(client):
    created = _create_job(client)
    # Force status to running manually, then try to execute
    import app.worker.remediation_worker as _mod

    _mod._JOBS[created["id"]].status = "running"
    resp = client.post(f"/worker/remediation/jobs/{created['id']}/execute")
    assert resp.status_code == 400


def test_execute_job_succeeds_status_400(client):
    created = _create_job(client)
    import app.worker.remediation_worker as _mod

    _mod._JOBS[created["id"]].status = "succeeded"
    resp = client.post(f"/worker/remediation/jobs/{created['id']}/execute")
    assert resp.status_code == 400


def test_execute_job_cancelled_status_400(client):
    created = _create_job(client)
    import app.worker.remediation_worker as _mod

    _mod._JOBS[created["id"]].status = "cancelled"
    resp = client.post(f"/worker/remediation/jobs/{created['id']}/execute")
    assert resp.status_code == 400


def test_execute_job_max_attempts_exceeded_400(client):
    created = _create_job(client, {"max_attempts": 1})
    import app.worker.remediation_worker as _mod

    job = _mod._JOBS[created["id"]]
    job.attempts = 1
    resp = client.post(f"/worker/remediation/jobs/{created['id']}/execute")
    assert resp.status_code == 400


def test_execute_failed_job_can_retry(client):
    created = _create_job(client, {"max_attempts": 3})
    import app.worker.remediation_worker as _mod

    job = _mod._JOBS[created["id"]]
    job.status = "failed"
    job.attempts = 1
    resp = client.post(f"/worker/remediation/jobs/{created['id']}/execute")
    assert resp.status_code == 200


def test_execute_job_started_at_set(client):
    created = _create_job(client)
    data = client.post(f"/worker/remediation/jobs/{created['id']}/execute").json()
    assert data["started_at"] is not None


# ---------------------------------------------------------------------------
# PATCH /worker/remediation/jobs/{job_id}/status — update status
# ---------------------------------------------------------------------------


def test_patch_status_to_running(client):
    created = _create_job(client)
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "running"},
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == "running"


def test_patch_status_to_succeeded(client):
    created = _create_job(client)
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "succeeded"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "succeeded"
    assert data["completed_at"] is not None


def test_patch_status_to_failed_with_error(client):
    created = _create_job(client)
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "failed", "last_error": "timeout on host-001"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "failed"
    assert data["last_error"] == "timeout on host-001"
    assert data["completed_at"] is not None


def test_patch_status_to_cancelled(client):
    created = _create_job(client)
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "cancelled"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "cancelled"
    assert data["completed_at"] is not None


def test_patch_status_not_found_404(client):
    resp = client.patch(
        "/worker/remediation/jobs/ghost-job/status",
        json={"status": "running"},
    )
    assert resp.status_code == 404


def test_patch_status_invalid_value_422(client):
    created = _create_job(client)
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "unknown_status"},
    )
    assert resp.status_code == 422


def test_patch_status_running_sets_started_at(client):
    created = _create_job(client)
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "running"},
    )
    assert resp.json()["started_at"] is not None


def test_patch_status_running_preserves_started_at(client):
    created = _create_job(client)
    import app.worker.remediation_worker as _mod

    _mod._JOBS[created["id"]].started_at = "2025-01-01T00:00:00+00:00"
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "running"},
    )
    assert resp.json()["started_at"] == "2025-01-01T00:00:00+00:00"


def test_patch_status_clears_last_error_when_none(client):
    created = _create_job(client)
    import app.worker.remediation_worker as _mod

    _mod._JOBS[created["id"]].last_error = "previous error"
    resp = client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "succeeded", "last_error": None},
    )
    assert resp.json()["last_error"] is None


# ---------------------------------------------------------------------------
# All remediation kinds accepted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "kind",
    [
        "configuration_change",
        "access_control",
        "network_control",
        "detection_rule",
        "data_protection",
        "process_runbook",
        "other",
    ],
)
def test_create_job_all_valid_kinds(client, kind):
    data = _create_job(client, {"kind": kind})
    assert data["kind"] == kind


# ---------------------------------------------------------------------------
# Persistence integrity — jobs survive across reads
# ---------------------------------------------------------------------------


def test_job_persists_after_create_and_get(client):
    created = _create_job(client)
    fetched = client.get(f"/worker/remediation/jobs/{created['id']}").json()
    assert fetched["id"] == created["id"]
    assert fetched["action_id"] == created["action_id"]


def test_job_state_reflects_execute(client):
    created = _create_job(client)
    executed = client.post(f"/worker/remediation/jobs/{created['id']}/execute").json()
    fetched = client.get(f"/worker/remediation/jobs/{created['id']}").json()
    assert fetched["status"] == executed["status"]
    assert fetched["attempts"] == executed["attempts"]


def test_job_state_reflects_patch(client):
    created = _create_job(client)
    client.patch(
        f"/worker/remediation/jobs/{created['id']}/status",
        json={"status": "cancelled"},
    )
    fetched = client.get(f"/worker/remediation/jobs/{created['id']}").json()
    assert fetched["status"] == "cancelled"
