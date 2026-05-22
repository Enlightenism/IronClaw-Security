from __future__ import annotations

from dataclasses import asdict
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.orchestrator.agent_profile import (
    AgentProfile,
    _autonomy_for_descriptor,
    _escalation_for_descriptor,
    _fetch_baseline_state,
    _focus_for_descriptor,
    _role_for_descriptor,
    _system_prompt_for_descriptor,
    build_agent_profile,
)
from app.orchestrator.agent_registry import (
    AgentDescriptor,
    AgentRegistry,
    _hash_file,
    _infer_language,
    _protected_actions_for,
    _stable_agent_id,
    _tags_for,
    _threat_profile_for,
    build_agent_descriptor,
    discover_agents,
    get_agent_by_id,
    get_agent_by_path,
    save_registry,
)

# ---------------------------------------------------------------------------
# Helpers / shared fixtures
# ---------------------------------------------------------------------------


def _make_descriptor(
    *,
    threat_profile: str = "standard",
    language: str = "python",
    tags: list[str] | None = None,
    relative_path: str = "app/service.py",
    protected_actions: list[str] | None = None,
    agent_id: str = "ic-agent-testid00000001",
) -> AgentDescriptor:
    return AgentDescriptor(
        agent_id=agent_id,
        relative_path=relative_path,
        absolute_path=f"/project/{relative_path}",
        language=language,  # type: ignore[arg-type]
        threat_profile=threat_profile,  # type: ignore[arg-type]
        protected_actions=list(protected_actions or []),
        exists=True,
        size_bytes=512,
        file_hash="abc123",
        last_modified_ts=1_700_000_000.0,
        tags=list(tags or ["python"]),
        baseline_status="active",
    )


def _make_store(
    *,
    baseline_status: str = "active",
    drift_severity: str = "none",
    baseline_exists: bool = True,
) -> MagicMock:
    store = MagicMock()
    if baseline_exists:
        store.get_baseline.return_value = SimpleNamespace(status=baseline_status)
    else:
        store.get_baseline.return_value = None
    store.compute_drift.return_value = SimpleNamespace(overall_severity=drift_severity)
    return store


# ---------------------------------------------------------------------------
# agent_registry — _stable_agent_id
# ---------------------------------------------------------------------------


class TestStableAgentId:
    def test_deterministic(self):
        a = _stable_agent_id("app/services/guard.py")
        b = _stable_agent_id("app/services/guard.py")
        assert a == b

    def test_prefix(self):
        assert _stable_agent_id("app/foo.py").startswith("ic-agent-")

    def test_different_paths_differ(self):
        assert _stable_agent_id("app/foo.py") != _stable_agent_id("app/bar.py")

    def test_length(self):
        # "ic-agent-" (9) + 16 hex chars = 25
        assert len(_stable_agent_id("app/foo.py")) == 25

    def test_matches_sha256_first16(self):
        path = "app/some/file.py"
        expected = "ic-agent-" + hashlib.sha256(path.encode()).hexdigest()[:16]
        assert _stable_agent_id(path) == expected


# ---------------------------------------------------------------------------
# agent_registry — _infer_language
# ---------------------------------------------------------------------------


class TestInferLanguage:
    @pytest.mark.parametrize(
        "suffix, expected",
        [
            (".py", "python"),
            (".js", "javascript"),
            (".jsx", "javascript"),
            (".ts", "typescript"),
            (".tsx", "typescript"),
            (".json", "json"),
            (".yml", "yaml"),
            (".yaml", "yaml"),
            (".md", "markdown"),
            (".html", "html"),
            (".css", "css"),
            (".sh", "shell"),
            (".ps1", "powershell"),
            (".rb", "unknown"),
            (".exe", "unknown"),
        ],
    )
    def test_extensions(self, tmp_path, suffix, expected):
        f = tmp_path / f"file{suffix}"
        f.touch()
        assert _infer_language(f) == expected


# ---------------------------------------------------------------------------
# agent_registry — _threat_profile_for
# ---------------------------------------------------------------------------


class TestThreatProfileFor:
    def _path(self, name: str) -> Path:
        return Path(f"/project/{name}")

    def test_security_critical_by_path(self):
        assert _threat_profile_for(self._path("app/security/guard.py"), "python", "") == "security_critical"

    def test_security_critical_orchestrator(self):
        assert _threat_profile_for(self._path("app/orchestrator/scanner.py"), "python", "") == "security_critical"

    def test_security_critical_behavioral_baseline(self):
        assert _threat_profile_for(self._path("app/services/behavioral_baseline.py"), "python", "") == "security_critical"

    def test_execution_capable_subprocess(self):
        assert _threat_profile_for(self._path("app/worker.py"), "python", "import subprocess") == "execution_capable"

    def test_execution_capable_token(self):
        assert _threat_profile_for(self._path("app/foo.py"), "python", "secret = token_hex()") == "execution_capable"

    def test_execution_capable_requests(self):
        assert _threat_profile_for(self._path("app/foo.py"), "python", "requests.get(url)") == "execution_capable"

    def test_sensitive_by_auth_path(self):
        assert _threat_profile_for(self._path("app/auth/login.py"), "python", "") == "sensitive"

    def test_sensitive_by_service_path(self):
        assert _threat_profile_for(self._path("app/api/service.py"), "python", "") in {
            "sensitive",
            "security_critical",
        }

    def test_standard_python(self):
        assert _threat_profile_for(self._path("app/utils.py"), "python", "x = 1") == "standard"

    def test_low_risk_markdown(self):
        assert _threat_profile_for(self._path("docs/readme.md"), "markdown", "# Hello") == "low_risk"


# ---------------------------------------------------------------------------
# agent_registry — _protected_actions_for
# ---------------------------------------------------------------------------


class TestProtectedActionsFor:
    def test_always_has_file_edit(self):
        actions = _protected_actions_for("python", Path("app/foo.py"), "")
        assert "file_edit" in actions

    def test_shell_script_adds_shell_command_and_file_write(self):
        actions = _protected_actions_for("shell", Path("deploy.sh"), "")
        assert "shell_command" in actions
        assert "file_write" in actions

    def test_subprocess_in_content_adds_shell_command(self):
        actions = _protected_actions_for("python", Path("app/runner.py"), "subprocess.run(['ls'])")
        assert "shell_command" in actions

    def test_requests_in_content_adds_network_request(self):
        actions = _protected_actions_for("python", Path("app/client.py"), "requests.get(url)")
        assert "network_request" in actions

    def test_httpx_adds_network_request(self):
        actions = _protected_actions_for("python", Path("app/client.py"), "httpx.get(url)")
        assert "network_request" in actions

    def test_git_in_content_adds_git_operation(self):
        actions = _protected_actions_for("python", Path("app/foo.py"), "git commit")
        assert "git_operation" in actions

    def test_file_write_token_in_content(self):
        actions = _protected_actions_for("python", Path("app/foo.py"), "path.write_text('x')")
        assert "file_write" in actions

    def test_guard_path_adds_tool_call(self):
        actions = _protected_actions_for("python", Path("app/guard_service.py"), "")
        assert "tool_call" in actions

    def test_result_is_sorted(self):
        actions = _protected_actions_for("shell", Path("app/deploy.sh"), "git commit && requests.get(url)")
        assert actions == sorted(actions)


# ---------------------------------------------------------------------------
# agent_registry — _tags_for
# ---------------------------------------------------------------------------


class TestTagsFor:
    def test_language_always_included(self):
        tags = _tags_for(Path("app/foo.py"), "python", "")
        assert "python" in tags

    def test_security_tag_from_path(self):
        tags = _tags_for(Path("app/security/scanner.py"), "python", "")
        assert "security" in tags

    def test_network_tag_from_content(self):
        tags = _tags_for(Path("app/foo.py"), "python", "requests.get(url)")
        assert "network" in tags

    def test_telemetry_tag_from_content(self):
        tags = _tags_for(Path("app/foo.py"), "python", "telemetry.emit(event)")
        assert "telemetry" in tags

    def test_behavioral_baseline_tag(self):
        tags = _tags_for(Path("app/services/behavioral_baseline.py"), "python", "")
        assert "behavioral_baseline" in tags

    def test_api_tag_from_content(self):
        tags = _tags_for(Path("app/foo.py"), "python", "app = FastAPI()")
        assert "api" in tags

    def test_result_is_sorted(self):
        tags = _tags_for(Path("app/security/scanner.py"), "python", "requests.get(url) telemetry.emit(event)")
        assert tags == sorted(tags)


# ---------------------------------------------------------------------------
# agent_registry — _hash_file
# ---------------------------------------------------------------------------


class TestHashFile:
    def test_returns_hex_string(self, tmp_path):
        f = tmp_path / "file.py"
        f.write_text("hello world", encoding="utf-8")
        result = _hash_file(f)
        assert result is not None
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)

    def test_returns_none_on_missing_file(self, tmp_path):
        assert _hash_file(tmp_path / "nonexistent.py") is None

    def test_deterministic(self, tmp_path):
        f = tmp_path / "file.py"
        f.write_text("deterministic", encoding="utf-8")
        assert _hash_file(f) == _hash_file(f)

    def test_different_content_different_hash(self, tmp_path):
        f1 = tmp_path / "a.py"
        f2 = tmp_path / "b.py"
        f1.write_text("aaa", encoding="utf-8")
        f2.write_text("bbb", encoding="utf-8")
        assert _hash_file(f1) != _hash_file(f2)


# ---------------------------------------------------------------------------
# agent_registry — build_agent_descriptor
# ---------------------------------------------------------------------------


class TestBuildAgentDescriptor:
    def test_basic_fields(self, tmp_path):
        f = tmp_path / "app" / "foo.py"
        f.parent.mkdir()
        f.write_text("x = 1", encoding="utf-8")

        with patch(
            "app.orchestrator.agent_registry._fetch_baseline_status",
            return_value="unknown",
        ):
            desc = build_agent_descriptor(tmp_path, f)

        assert desc.relative_path == "app/foo.py"
        assert desc.language == "python"
        assert desc.exists is True
        assert desc.size_bytes > 0
        assert desc.file_hash is not None
        assert desc.last_modified_ts is not None
        assert desc.agent_id.startswith("ic-agent-")

    def test_agent_id_is_stable(self, tmp_path):
        f = tmp_path / "stable.py"
        f.write_text("pass", encoding="utf-8")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            d1 = build_agent_descriptor(tmp_path, f)
            d2 = build_agent_descriptor(tmp_path, f)

        assert d1.agent_id == d2.agent_id

    def test_nonexistent_file(self, tmp_path):
        f = tmp_path / "ghost.py"

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            desc = build_agent_descriptor(tmp_path, f)

        assert desc.exists is False
        assert desc.size_bytes == 0
        assert desc.file_hash is None

    def test_baseline_status_populated(self, tmp_path):
        f = tmp_path / "svc.py"
        f.write_text("pass", encoding="utf-8")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="active"):
            desc = build_agent_descriptor(tmp_path, f)

        assert desc.baseline_status == "active"

    def test_threat_profile_security_critical_for_guard_path(self, tmp_path):
        f = tmp_path / "guard_service.py"
        f.write_text("pass", encoding="utf-8")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            desc = build_agent_descriptor(tmp_path, f)

        assert desc.threat_profile == "security_critical"


# ---------------------------------------------------------------------------
# agent_registry — discover_agents
# ---------------------------------------------------------------------------


class TestDiscoverAgents:
    def _write(self, root: Path, rel: str, content: str = "pass") -> Path:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return p

    def test_discovers_python_files(self, tmp_path):
        self._write(tmp_path, "app/foo.py")
        self._write(tmp_path, "app/bar.py")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            reg = discover_agents(tmp_path)

        paths = {item.relative_path for item in reg.items}
        assert "app/foo.py" in paths
        assert "app/bar.py" in paths
        assert reg.count == len(reg.items)

    def test_excludes_venv_dir(self, tmp_path):
        self._write(tmp_path, "app/real.py")
        self._write(tmp_path, "venv/lib/site.py")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            reg = discover_agents(tmp_path)

        paths = {item.relative_path for item in reg.items}
        assert "app/real.py" in paths
        assert not any("venv" in p for p in paths)

    def test_excludes_pycache(self, tmp_path):
        self._write(tmp_path, "app/real.py")
        self._write(tmp_path, "app/__pycache__/cached.py")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            reg = discover_agents(tmp_path)

        paths = {item.relative_path for item in reg.items}
        assert not any("__pycache__" in p for p in paths)

    def test_excludes_unsupported_extension(self, tmp_path):
        self._write(tmp_path, "app/foo.py")
        self._write(tmp_path, "app/ignored.rb")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            reg = discover_agents(tmp_path)

        paths = {item.relative_path for item in reg.items}
        assert "app/ignored.rb" not in paths

    def test_custom_include_extensions(self, tmp_path):
        self._write(tmp_path, "app/foo.py")
        self._write(tmp_path, "config/settings.ini")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            reg = discover_agents(tmp_path, include_extensions={".ini"})

        paths = {item.relative_path for item in reg.items}
        assert "config/settings.ini" in paths
        assert "app/foo.py" not in paths

    def test_items_sorted_by_relative_path(self, tmp_path):
        self._write(tmp_path, "zzz/z.py")
        self._write(tmp_path, "aaa/a.py")
        self._write(tmp_path, "mmm/m.py")

        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            reg = discover_agents(tmp_path)

        paths = [item.relative_path for item in reg.items]
        assert paths == sorted(paths)

    def test_empty_project_returns_empty_registry(self, tmp_path):
        with patch("app.orchestrator.agent_registry._fetch_baseline_status", return_value="unknown"):
            reg = discover_agents(tmp_path)
        assert reg.count == 0
        assert reg.items == []


# ---------------------------------------------------------------------------
# agent_registry — get_agent_by_path / get_agent_by_id
# ---------------------------------------------------------------------------


class TestRegistryLookups:
    def _registry(self) -> AgentRegistry:
        d1 = _make_descriptor(relative_path="app/foo.py", agent_id="ic-agent-aaaaaaaabbbbbbbb")
        d2 = _make_descriptor(relative_path="app/bar.py", agent_id="ic-agent-ccccccccdddddddd")
        return AgentRegistry(project_root="/project", count=2, items=[d1, d2])

    def test_get_by_path_found(self):
        reg = self._registry()
        assert get_agent_by_path(reg, "app/foo.py") is not None

    def test_get_by_path_not_found(self):
        reg = self._registry()
        assert get_agent_by_path(reg, "app/missing.py") is None

    def test_get_by_path_normalizes_backslash(self):
        reg = self._registry()
        assert get_agent_by_path(reg, "app\\foo.py") is not None

    def test_get_by_id_found(self):
        reg = self._registry()
        assert get_agent_by_id(reg, "ic-agent-aaaaaaaabbbbbbbb") is not None

    def test_get_by_id_not_found(self):
        reg = self._registry()
        assert get_agent_by_id(reg, "ic-agent-doesnotexist0000") is None


# ---------------------------------------------------------------------------
# agent_registry — save_registry / to_dict
# ---------------------------------------------------------------------------


class TestSaveRegistry:
    def test_save_creates_file(self, tmp_path):
        d = _make_descriptor()
        reg = AgentRegistry(project_root="/p", count=1, items=[d])
        out = tmp_path / "out" / "registry.json"
        save_registry(reg, out)
        assert out.exists()

    def test_save_valid_json(self, tmp_path):
        d = _make_descriptor()
        reg = AgentRegistry(project_root="/p", count=1, items=[d])
        out = tmp_path / "registry.json"
        save_registry(reg, out)
        data = json.loads(out.read_text())
        assert data["count"] == 1
        assert isinstance(data["items"], list)

    def test_to_dict_round_trip(self):
        d = _make_descriptor()
        reg = AgentRegistry(project_root="/p", count=1, items=[d])
        data = reg.to_dict()
        assert data["project_root"] == "/p"
        assert data["count"] == 1
        assert data["items"][0]["agent_id"] == d.agent_id

    def test_descriptor_asdict_contains_all_fields(self):
        d = _make_descriptor()
        result = asdict(d)
        expected_keys = {
            "agent_id",
            "relative_path",
            "absolute_path",
            "language",
            "threat_profile",
            "protected_actions",
            "exists",
            "size_bytes",
            "file_hash",
            "last_modified_ts",
            "tags",
            "baseline_status",
        }
        assert expected_keys.issubset(result.keys())


# ---------------------------------------------------------------------------
# agent_registry — _fetch_baseline_status (registry-level, baseline wiring)
# ---------------------------------------------------------------------------


class TestRegistryFetchBaselineStatus:
    def test_returns_active_when_baseline_exists(self):
        from app.orchestrator.agent_registry import _fetch_baseline_status

        store = _make_store(baseline_status="active")
        with patch(
            "app.orchestrator.agent_registry.get_behavioral_baseline_store",
            return_value=store,
        ):
            assert _fetch_baseline_status("ic-agent-test") == "active"

    def test_returns_learning_when_no_baseline(self):
        from app.orchestrator.agent_registry import _fetch_baseline_status

        store = _make_store(baseline_exists=False)
        with patch(
            "app.orchestrator.agent_registry.get_behavioral_baseline_store",
            return_value=store,
        ):
            assert _fetch_baseline_status("ic-agent-test") == "learning"

    def test_falls_back_to_unknown_on_exception(self):
        from app.orchestrator.agent_registry import _fetch_baseline_status

        with patch(
            "app.orchestrator.agent_registry.get_behavioral_baseline_store",
            side_effect=RuntimeError("db down"),
        ):
            assert _fetch_baseline_status("ic-agent-test") == "unknown"


# ---------------------------------------------------------------------------
# agent_profile — role derivation
# ---------------------------------------------------------------------------


class TestRoleForDescriptor:
    def test_security_critical_returns_security_sentinel(self):
        d = _make_descriptor(threat_profile="security_critical")
        assert _role_for_descriptor(d) == "security_sentinel"

    def test_execution_capable_returns_execution_watcher(self):
        d = _make_descriptor(threat_profile="execution_capable")
        assert _role_for_descriptor(d) == "execution_watcher"

    def test_api_tag_returns_integration_monitor(self):
        d = _make_descriptor(threat_profile="standard", tags=["api", "python"])
        assert _role_for_descriptor(d) == "integration_monitor"

    def test_integration_tag_returns_integration_monitor(self):
        d = _make_descriptor(threat_profile="standard", tags=["integration"])
        assert _role_for_descriptor(d) == "integration_monitor"

    def test_markdown_language_returns_documentation_observer(self):
        d = _make_descriptor(threat_profile="standard", language="markdown", tags=["markdown"])
        assert _role_for_descriptor(d) == "documentation_observer"

    def test_yaml_language_returns_documentation_observer(self):
        d = _make_descriptor(threat_profile="low_risk", language="yaml", tags=["yaml"])
        assert _role_for_descriptor(d) == "documentation_observer"

    def test_standard_python_returns_file_guardian(self):
        d = _make_descriptor(threat_profile="standard", language="python", tags=["python"])
        assert _role_for_descriptor(d) == "file_guardian"

    def test_sensitive_returns_file_guardian(self):
        d = _make_descriptor(threat_profile="sensitive", language="python", tags=["python"])
        assert _role_for_descriptor(d) == "file_guardian"


# ---------------------------------------------------------------------------
# agent_profile — autonomy derivation
# ---------------------------------------------------------------------------


class TestAutonomyForDescriptor:
    def test_security_critical_isolated_quarantine(self):
        d = _make_descriptor(threat_profile="security_critical")
        assert _autonomy_for_descriptor(d) == "isolated_quarantine_only"

    def test_execution_capable_restricted_execution(self):
        d = _make_descriptor(threat_profile="execution_capable")
        assert _autonomy_for_descriptor(d) == "restricted_execution"

    def test_sensitive_review_before_action(self):
        d = _make_descriptor(threat_profile="sensitive")
        assert _autonomy_for_descriptor(d) == "review_before_action"

    def test_standard_observe_only(self):
        d = _make_descriptor(threat_profile="standard")
        assert _autonomy_for_descriptor(d) == "observe_only"

    def test_low_risk_observe_only(self):
        d = _make_descriptor(threat_profile="low_risk")
        assert _autonomy_for_descriptor(d) == "observe_only"


# ---------------------------------------------------------------------------
# agent_profile — escalation derivation
# ---------------------------------------------------------------------------


class TestEscalationForDescriptor:
    def test_security_critical_automatic_quarantine(self):
        d = _make_descriptor(threat_profile="security_critical")
        assert _escalation_for_descriptor(d) == "automatic_quarantine"

    def test_execution_capable_security_review(self):
        d = _make_descriptor(threat_profile="execution_capable")
        assert _escalation_for_descriptor(d) == "security_review"

    def test_sensitive_security_review(self):
        d = _make_descriptor(threat_profile="sensitive")
        assert _escalation_for_descriptor(d) == "security_review"

    def test_standard_operator_review(self):
        d = _make_descriptor(threat_profile="standard")
        assert _escalation_for_descriptor(d) == "operator_review"

    def test_low_risk_operator_review(self):
        d = _make_descriptor(threat_profile="low_risk")
        assert _escalation_for_descriptor(d) == "operator_review"


# ---------------------------------------------------------------------------
# agent_profile — focus derivation
# ---------------------------------------------------------------------------


class TestFocusForDescriptor:
    def test_security_critical_with_api_tag_integration_control(self):
        d = _make_descriptor(threat_profile="security_critical", tags=["api", "security"])
        assert _focus_for_descriptor(d) == "integration_control"

    def test_security_critical_without_api_tag_code_integrity(self):
        d = _make_descriptor(threat_profile="security_critical", tags=["security"])
        assert _focus_for_descriptor(d) == "code_integrity"

    def test_execution_capable_execution_safety(self):
        d = _make_descriptor(threat_profile="execution_capable")
        assert _focus_for_descriptor(d) == "execution_safety"

    def test_network_tag_network_boundary(self):
        d = _make_descriptor(threat_profile="standard", tags=["network", "python"])
        assert _focus_for_descriptor(d) == "network_boundary"

    def test_markdown_documentation_integrity(self):
        d = _make_descriptor(threat_profile="low_risk", language="markdown", tags=["markdown"])
        assert _focus_for_descriptor(d) == "documentation_integrity"

    def test_default_code_integrity(self):
        d = _make_descriptor(threat_profile="standard", language="python", tags=["python"])
        assert _focus_for_descriptor(d) == "code_integrity"


# ---------------------------------------------------------------------------
# agent_profile — system prompt
# ---------------------------------------------------------------------------


class TestSystemPromptForDescriptor:
    def test_contains_agent_id_path(self):
        d = _make_descriptor(relative_path="app/guard.py")
        role = _role_for_descriptor(d)
        autonomy = _autonomy_for_descriptor(d)
        focus = _focus_for_descriptor(d)
        prompt = _system_prompt_for_descriptor(d, role, autonomy, focus)
        assert "app/guard.py" in prompt

    def test_contains_role(self):
        d = _make_descriptor(threat_profile="security_critical")
        role = _role_for_descriptor(d)
        autonomy = _autonomy_for_descriptor(d)
        focus = _focus_for_descriptor(d)
        prompt = _system_prompt_for_descriptor(d, role, autonomy, focus)
        assert role in prompt

    def test_contains_autonomy_level(self):
        d = _make_descriptor(threat_profile="execution_capable")
        role = _role_for_descriptor(d)
        autonomy = _autonomy_for_descriptor(d)
        focus = _focus_for_descriptor(d)
        prompt = _system_prompt_for_descriptor(d, role, autonomy, focus)
        assert autonomy in prompt

    def test_protected_actions_listed(self):
        d = _make_descriptor(protected_actions=["file_write", "shell_command"])
        role = _role_for_descriptor(d)
        autonomy = _autonomy_for_descriptor(d)
        focus = _focus_for_descriptor(d)
        prompt = _system_prompt_for_descriptor(d, role, autonomy, focus)
        assert "file_write" in prompt
        assert "shell_command" in prompt

    def test_no_protected_actions_shows_none(self):
        d = _make_descriptor(protected_actions=[], tags=["python"])
        role = _role_for_descriptor(d)
        autonomy = _autonomy_for_descriptor(d)
        focus = _focus_for_descriptor(d)
        prompt = _system_prompt_for_descriptor(d, role, autonomy, focus)
        assert "none" in prompt

    def test_prompt_is_nonempty_string(self):
        d = _make_descriptor()
        role = _role_for_descriptor(d)
        autonomy = _autonomy_for_descriptor(d)
        focus = _focus_for_descriptor(d)
        prompt = _system_prompt_for_descriptor(d, role, autonomy, focus)
        assert isinstance(prompt, str)
        assert len(prompt) > 50


# ---------------------------------------------------------------------------
# agent_profile — _fetch_baseline_state (profile-level, baseline wiring)
# ---------------------------------------------------------------------------


class TestFetchBaselineState:
    def test_active_baseline_returns_status_and_drift(self):
        store = _make_store(baseline_status="active", drift_severity="low")
        with patch(
            "app.orchestrator.agent_profile.get_behavioral_baseline_store",
            return_value=store,
        ):
            status, severity = _fetch_baseline_state("ic-agent-test")
        assert status == "active"
        assert severity == "low"

    def test_no_baseline_returns_learning_no_drift(self):
        store = _make_store(baseline_exists=False)
        with patch(
            "app.orchestrator.agent_profile.get_behavioral_baseline_store",
            return_value=store,
        ):
            status, severity = _fetch_baseline_state("ic-agent-test")
        assert status == "learning"
        assert severity == "none"

    def test_exception_returns_unknown_none(self):
        with patch(
            "app.orchestrator.agent_profile.get_behavioral_baseline_store",
            side_effect=ConnectionError("store unavailable"),
        ):
            status, severity = _fetch_baseline_state("ic-agent-test")
        assert status == "unknown"
        assert severity == "none"

    def test_compute_drift_called_with_agent_id(self):
        store = _make_store(baseline_status="active", drift_severity="high")
        with patch(
            "app.orchestrator.agent_profile.get_behavioral_baseline_store",
            return_value=store,
        ):
            _fetch_baseline_state("ic-agent-specific")
        store.compute_drift.assert_called_once_with("ic-agent-specific")

    def test_get_baseline_not_called_when_store_raises(self):
        with patch(
            "app.orchestrator.agent_profile.get_behavioral_baseline_store",
            side_effect=RuntimeError("boom"),
        ):
            result = _fetch_baseline_state("ic-agent-x")
        assert result == ("unknown", "none")


# ---------------------------------------------------------------------------
# agent_profile — build_agent_profile (full field validation)
# ---------------------------------------------------------------------------


class TestBuildAgentProfile:
    def _build(
        self,
        *,
        threat_profile: str = "standard",
        language: str = "python",
        tags: list[str] | None = None,
        baseline_status: str = "active",
        drift_severity: str = "none",
        baseline_exists: bool = True,
    ) -> AgentProfile:
        descriptor = _make_descriptor(
            threat_profile=threat_profile,
            language=language,
            tags=tags or ["python"],
        )
        store = _make_store(
            baseline_status=baseline_status,
            drift_severity=drift_severity,
            baseline_exists=baseline_exists,
        )
        with patch(
            "app.orchestrator.agent_profile.get_behavioral_baseline_store",
            return_value=store,
        ):
            return build_agent_profile(descriptor)

    def test_returns_agent_profile_instance(self):
        assert isinstance(self._build(), AgentProfile)

    def test_agent_id_matches_descriptor(self):
        p = self._build()
        assert p.agent_id == "ic-agent-testid00000001"

    def test_file_path_matches_descriptor(self):
        p = self._build()
        assert p.file_path == "app/service.py"

    def test_must_use_guard_api_always_true(self):
        assert self._build().must_use_guard_api is True

    def test_must_log_all_actions_always_true(self):
        assert self._build().must_log_all_actions is True

    def test_quarantine_on_uncertainty_always_true(self):
        assert self._build().quarantine_on_uncertainty is True

    def test_can_propose_changes_always_true(self):
        assert self._build().can_propose_changes is True

    def test_owner_scope_is_page_of_code(self):
        assert self._build().owner_scope == "page_of_code"

    def test_can_execute_directly_false_for_security_critical(self):
        p = self._build(threat_profile="security_critical")
        assert p.can_execute_directly is False

    def test_can_execute_directly_true_for_restricted_execution(self):
        p = self._build(threat_profile="execution_capable")
        assert p.can_execute_directly is True

    def test_can_execute_directly_false_for_observe_only(self):
        p = self._build(threat_profile="standard")
        assert p.can_execute_directly is False

    def test_baseline_status_populated(self):
        p = self._build(baseline_status="active")
        assert p.baseline_status == "active"

    def test_drift_severity_populated(self):
        p = self._build(drift_severity="medium")
        assert p.drift_severity == "medium"

    def test_notes_is_list_of_strings(self):
        p = self._build()
        assert isinstance(p.notes, list)
        assert all(isinstance(n, str) for n in p.notes)

    def test_notes_contains_ironclaw_mention(self):
        p = self._build()
        assert any("IronClaw" in n for n in p.notes)

    def test_high_sensitivity_note_for_security_critical(self):
        p = self._build(threat_profile="security_critical")
        assert any("High-sensitivity" in n for n in p.notes)

    def test_high_sensitivity_note_for_execution_capable(self):
        p = self._build(threat_profile="execution_capable")
        assert any("High-sensitivity" in n for n in p.notes)

    def test_no_high_sensitivity_note_for_standard(self):
        p = self._build(threat_profile="standard")
        assert not any("High-sensitivity" in n for n in p.notes)

    def test_learning_note_injected(self):
        p = self._build(baseline_exists=False)
        assert any("learning" in n for n in p.notes)

    def test_stale_note_injected(self):
        p = self._build(baseline_status="stale")
        assert any("stale" in n for n in p.notes)

    def test_suspended_note_injected(self):
        p = self._build(baseline_status="suspended")
        assert any("suspended" in n.lower() for n in p.notes)

    def test_active_high_drift_note_injected(self):
        p = self._build(baseline_status="active", drift_severity="high")
        assert any("drift" in n.lower() for n in p.notes)

    def test_active_critical_drift_note_injected(self):
        p = self._build(baseline_status="active", drift_severity="critical")
        assert any("critical" in n.lower() or "drift" in n.lower() for n in p.notes)

    def test_active_no_drift_no_drift_note(self):
        p = self._build(baseline_status="active", drift_severity="none")
        assert not any("drift" in n.lower() for n in p.notes)

    def test_to_dict_returns_dict(self):
        p = self._build()
        d = p.to_dict()
        assert isinstance(d, dict)

    def test_to_dict_contains_expected_keys(self):
        p = self._build()
        d = p.to_dict()
        for key in [
            "agent_id",
            "file_path",
            "role",
            "autonomy_level",
            "escalation_mode",
            "primary_focus",
            "system_prompt",
            "protected_actions",
            "risk_tags",
            "owner_scope",
            "can_propose_changes",
            "can_execute_directly",
            "must_use_guard_api",
            "must_log_all_actions",
            "quarantine_on_uncertainty",
            "baseline_status",
            "drift_severity",
            "notes",
        ]:
            assert key in d, f"Missing key: {key}"

    def test_role_is_valid_literal(self):
        import typing

        from app.orchestrator.agent_profile import AgentRole

        valid = set(typing.get_args(AgentRole))
        p = self._build()
        assert p.role in valid

    def test_autonomy_level_is_valid_literal(self):
        import typing

        from app.orchestrator.agent_profile import AutonomyLevel

        valid = set(typing.get_args(AutonomyLevel))
        p = self._build()
        assert p.autonomy_level in valid

    def test_escalation_mode_is_valid_literal(self):
        import typing

        from app.orchestrator.agent_profile import EscalationMode

        valid = set(typing.get_args(EscalationMode))
        p = self._build()
        assert p.escalation_mode in valid

    def test_primary_focus_is_valid_literal(self):
        import typing

        from app.orchestrator.agent_profile import ProfileFocus

        valid = set(typing.get_args(ProfileFocus))
        p = self._build()
        assert p.primary_focus in valid

    def test_system_prompt_nonempty(self):
        p = self._build()
        assert isinstance(p.system_prompt, str) and len(p.system_prompt) > 20

    def test_unknown_baseline_injects_no_spurious_notes(self):
        """'unknown' baseline_status should not inject any status-specific note."""
        p = self._build(baseline_status="unknown", drift_severity="none")
        status_notes = [n for n in p.notes if any(kw in n.lower() for kw in ("stale", "suspended", "learning", "drift"))]
        assert status_notes == []

    def test_build_is_repeatable(self):
        """Same inputs must produce identical profiles (no random state)."""
        p1 = self._build(threat_profile="sensitive", baseline_status="active", drift_severity="low")
        p2 = self._build(threat_profile="sensitive", baseline_status="active", drift_severity="low")
        assert p1.to_dict() == p2.to_dict()
