from __future__ import annotations

from app.orchestrator.checkpoint_store import CheckpointBundle, CheckpointManifest
from app.orchestrator.operations_dashboard import build_operations_dashboard
from app.orchestrator.supervisor import SupervisorSnapshot


def test_build_operations_dashboard_accepts_checkpoint_bundle() -> None:
    supervisor = SupervisorSnapshot(
        supervisor_id="sup-1",
        project_root="/tmp",
        status="healthy",
        created_at="2026-08-29T00:00:00Z",
        updated_at="2026-08-29T00:05:00Z",
        active_sessions={},
        execution_history=[],
        escalations=[],
    )

    checkpoint = CheckpointBundle(
        manifest=CheckpointManifest(
            checkpoint_id="ckpt-001",
            created_at="2026-08-29T00:04:00Z",
            status="open",
            project_root="/tmp",
            supervisor_id="sup-1",
            session_count=2,
            execution_count=1,
            escalation_count=0,
            trace_count=3,
            label="nightly-snapshot",
            notes="demo",
        ),
        supervisor=supervisor.to_dict(),
        sessions=[],
        traces=[],
        metadata={},
    )

    snapshot = build_operations_dashboard(
        supervisor=supervisor,
        checkpoints=[checkpoint],
        replay_reports=[],
        gate_reports=[],
        audit_entries=[],
    )

    assert snapshot.status in {"healthy", "degraded", "critical"}
    assert snapshot.sections[0].section_id == "checkpoints"
    assert snapshot.sections[0].rows[0]["checkpoint_id"] == "ckpt-001"
    assert snapshot.headline_metrics[3].label == "Checkpoints"
