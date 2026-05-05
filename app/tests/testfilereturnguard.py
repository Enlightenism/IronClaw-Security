from __future__ import annotations

from typing import Any

from app.runtime.filereturnguard import build_file_return_guard


class _Decision:
    def __init__(
        self,
        *,
        verdict: str = "allow",
        allowed: bool = True,
        should_review: bool = False,
        should_block: bool = False,
        should_quarantine: bool = False,
        reasons: list[dict[str, Any]] | None = None,
        risk_delta: int = 0,
    ) -> None:
        self.verdict = verdict
        self.allowed = allowed
        self.should_review = should_review
        self.should_block = should_block
        self.should_quarantine = should_quarantine
        self.reasons = reasons if reasons is not None else [{"label": verdict}]
        self.risk_delta = risk_delta

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "shouldreview": self.should_review,
            "shouldblock": self.should_block,
            "shouldquarantine": self.should_quarantine,
            "reasons": list(self.reasons),
            "riskdelta": self.risk_delta,
        }


class _PolicyEngineStub:
    def __init__(self, decision: _Decision) -> None:
        self.decision = decision
        self.calls: list[dict[str, Any]] = []

    def evaluate(self, **kwargs: Any) -> _Decision:
        self.calls.append(kwargs)
        return self.decision


def test_file_return_guard_builds() -> None:
    guard = build_file_return_guard()
    assert guard is not None


def test_file_return_guard_allows_safe_text_file() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="allow",
            allowed=True,
            reasons=[{"label": "safe-text-output"}],
            risk_delta=2,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/report.txt",
        file_name="report.txt",
        media_type="text/plain",
        tool_name="execute_code",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
        metadata={"size_bytes": 2048, "contains_secrets": False},
    )

    assert result.verdict == "allow"
    assert result.allowed is True
    assert result.should_block is False
    assert len(policy_engine.calls) == 1


def test_file_return_guard_reviews_unknown_binary_file() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[{"label": "unknown-binary-output"}],
            risk_delta=38,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/blob.bin",
        file_name="blob.bin",
        media_type="application/octet-stream",
        tool_name="bash",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
        metadata={"size_bytes": 8192},
    )

    assert result.verdict == "review"
    assert result.allowed is True
    assert result.should_review is True


def test_file_return_guard_blocks_sensitive_file_exfiltration() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="block",
            allowed=False,
            should_block=True,
            reasons=[{"label": "sensitive-file-output"}],
            risk_delta=92,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/customer_keys.csv",
        file_name="customer_keys.csv",
        media_type="text/csv",
        tool_name="execute_code",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
        metadata={
            "contains_secrets": True,
            "contains_credentials": True,
            "size_bytes": 1024,
        },
    )

    assert result.verdict == "block"
    assert result.allowed is False
    assert result.should_block is True


def test_file_return_guard_quarantines_malicious_artifact() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="quarantine",
            allowed=False,
            should_block=True,
            should_quarantine=True,
            reasons=[{"label": "malicious-artifact"}],
            risk_delta=100,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/payload.exe",
        file_name="payload.exe",
        media_type="application/vnd.microsoft.portable-executable",
        tool_name="bash",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
        metadata={
            "threatintel_match": True,
            "contains_executable": True,
            "size_bytes": 65536,
        },
    )

    assert result.verdict == "quarantine"
    assert result.allowed is False
    assert result.should_block is True
    assert result.should_quarantine is True


def test_file_return_guard_passes_context_to_policy_engine() -> None:
    policy_engine = _PolicyEngineStub(_Decision())
    guard = build_file_return_guard(policy_engine=policy_engine)

    guard.evaluate(
        file_path="output/summary.json",
        file_name="summary.json",
        media_type="application/json",
        tool_name="execute_code",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
        metadata={
            "trace_id": "trace-77",
            "request_id": "req-9",
            "size_bytes": 512,
            "producer": "runtime",
        },
    )

    assert len(policy_engine.calls) == 1
    call = policy_engine.calls[0]
    assert call["file_path"] == "output/summary.json"
    assert call["file_name"] == "summary.json"
    assert call["media_type"] == "application/json"
    assert call["tool_name"] == "execute_code"
    assert call["actiontype"] == "file_return"
    assert call["target"] == "user_download"
    assert call["environment_scope"] == "sandbox"
    assert call["metadata"]["trace_id"] == "trace-77"
    assert call["metadata"]["size_bytes"] == 512


def test_file_return_guard_handles_missing_file_path() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[{"label": "missing-file-path"}],
            risk_delta=18,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path=None,
        file_name="report.txt",
        media_type="text/plain",
        tool_name="execute_code",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
    )

    assert result.verdict in {"review", "block"}
    assert result.reasons


def test_file_return_guard_handles_blank_file_path() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[{"label": "blank-file-path"}],
            risk_delta=18,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="   ",
        file_name="report.txt",
        media_type="text/plain",
        tool_name="execute_code",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
    )

    assert result.verdict in {"review", "block"}
    assert result.reasons


def test_file_return_guard_handles_missing_file_name() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[{"label": "missing-file-name"}],
            risk_delta=12,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/unnamed",
        file_name=None,
        media_type="application/octet-stream",
        tool_name="bash",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
    )

    assert result.verdict in {"review", "block", "allow"}
    assert result.reasons


def test_file_return_guard_handles_missing_tool_name() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="review",
            allowed=True,
            should_review=True,
            reasons=[{"label": "missing-tool-name"}],
            risk_delta=14,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/result.txt",
        file_name="result.txt",
        media_type="text/plain",
        tool_name=None,
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
    )

    assert result.verdict in {"review", "block"}
    assert result.reasons


def test_file_return_guard_inserts_default_reason_when_policy_has_none() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="allow",
            allowed=True,
            reasons=None,
            risk_delta=0,
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/ok.json",
        file_name="ok.json",
        media_type="application/json",
        tool_name="execute_code",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
    )

    assert isinstance(result.reasons, list)
    assert result.reasons


def test_file_return_guard_accepts_nested_metadata() -> None:
    policy_engine = _PolicyEngineStub(
        _Decision(
            verdict="allow",
            allowed=True,
            reasons=[{"label": "nested-metadata-ok"}],
        )
    )
    guard = build_file_return_guard(policy_engine=policy_engine)

    result = guard.evaluate(
        file_path="output/archive.zip",
        file_name="archive.zip",
        media_type="application/zip",
        tool_name="bash",
        actiontype="file_return",
        target="user_download",
        environment_scope="sandbox",
        metadata={
            "archive": {"entries": 4, "contains_executable": False},
            "scanner": {"verdict": "clean", "engine": "internal"},
        },
    )

    assert result.verdict == "allow"
    assert result.allowed is True