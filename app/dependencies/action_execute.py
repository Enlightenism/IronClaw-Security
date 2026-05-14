from __future__ import annotations

from app.orchestrator.secure_runtime_pipeline import (
    SecureRuntimePipeline,
    initialize_secure_runtime_pipeline,
)

_pipeline: SecureRuntimePipeline | None = None


def set_action_execute_pipeline(pipeline: SecureRuntimePipeline) -> None:
    global _pipeline
    _pipeline = pipeline


def reset_action_execute_pipeline() -> None:
    global _pipeline
    _pipeline = None


def get_action_execute_pipeline() -> SecureRuntimePipeline:
    global _pipeline

    if _pipeline is None:
        _pipeline = initialize_secure_runtime_pipeline()

    return _pipeline
