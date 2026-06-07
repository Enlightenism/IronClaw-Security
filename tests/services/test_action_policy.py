from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import app.services.action_policy as _ap
from app.services.action_policy import (
    _DEFAULT_BLOCKED_TARGETS,
    _DEFAULT_ELEVATED_REVIEW_ACTIONS,
    _DEFAULT_HIGH_REVIEW_TARGETS,
    DEFAULT_POLICY_SET_KEY,
    evaluate_action_policy,
    is_policy_loaded_from_db,
    load_builtin_policy_rules_from_db,
    reload_policy_rules,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _reset_globals() -> None:
    _ap.BLOCKED_TARGETS = _DEFAULT_BLOCKED_TARGETS
    _ap.HIGH_REVIEW_TARGETS = _DEFAULT_HIGH_REVIEW_TARGETS
    _ap.ELEVATED_REVIEW_ACTIONS = _DEFAULT_ELEVATED_REVIEW_ACTIONS
    _ap._policy_loaded_from_db = False


def _make_supabase_client(
    set_rows: list[dict],
    membership_rows: list[dict],
    rules_rows: list[dict],
) -> MagicMock:
    def _table(name: str) -> MagicMock:
        tb = MagicMock()

        def _select(*_a, **_kw):
            q = MagicMock()

            def _eq(col, val):
                return q

            def _in_(col, vals):
                return q

            def _limit(n):
                return q

            def _execute():
                resp = MagicMock()
                if name == "policy_sets":
                    resp.data = set_rows
                elif name == "policy_set_memberships":
                    resp.data = membership_rows
                elif name == "policy_rules":
                    resp.data = rules_rows
                else:
                    resp.data = []
                return resp

            q.eq = _eq
            q.in_ = _in_
            q.limit = _limit
            q.execute = _execute
            return q

        tb.select = _select
        return tb

    client = MagicMock()
    client.table.side_effect = _table
    return client


@pytest.fixture(autouse=True)
def _restore_globals():
    _reset_globals()
    yield
    _reset_globals()


def _configured_patch():
    return patch("app.supabaseclient.is_supabase_configured", return_value=True)


# ---------------------------------------------------------------------------
# evaluate_action_policy — block verdict
# ---------------------------------------------------------------------------


class TestEvaluateActionPolicyBlock:
    def test_blocked_target_returns_block_verdict(self):
        result = evaluate_action_policy("file_write", "/etc/passwd")
        assert result["verdict"] == "block"

    def test_blocked_target_should_halt_true(self):
        result = evaluate_action_policy("file_write", "/etc/passwd")
        assert result["should_halt"] is True

    def test_blocked_target_should_warn_false(self):
        result = evaluate_action_policy("file_write", "/etc/passwd")
        assert result["should_warn"] is False

    def test_blocked_target_policy_mode_block(self):
        result = evaluate_action_policy("shell_command", "/root/deploy.sh")
        assert result["policy_mode"] == "block"

    def test_blocked_target_reason_source_is_policy(self):
        result = evaluate_action_policy("file_write", ".env")
        assert result["reasons"][0]["source"] == "policy"

    def test_blocked_target_reason_score_is_1(self):
        result = evaluate_action_policy("file_write", ".env")
        assert result["reasons"][0]["score"] == 1.0

    def test_blocked_target_case_insensitive(self):
        result = evaluate_action_policy("file_write", "C:\\Windows\\System32\\notepad.exe")
        assert result["verdict"] == "block"

    def test_blocked_target_partial_match(self):
        result = evaluate_action_policy("file_read", "/home/user/.ssh/id_rsa")
        assert result["verdict"] == "block"

    def test_block_passes_client_and_session_through(self):
        result = evaluate_action_policy(
            "file_write",
            "/etc/shadow",
            client_id="c1",
            session_id="s1",
        )
        assert result["client_id"] == "c1"
        assert result["session_id"] == "s1"


# ---------------------------------------------------------------------------
# evaluate_action_policy — elevated review (action type)
# ---------------------------------------------------------------------------


class TestEvaluateActionPolicyElevatedAction:
    def test_elevated_action_type_returns_warn(self):
        result = evaluate_action_policy("shell_command", "safe_target_xyz_irrelevant")
        assert result["verdict"] == "warn"

    def test_elevated_action_type_policy_mode_review(self):
        result = evaluate_action_policy("network_request", "https://example.com")
        assert result["policy_mode"] == "review"

    def test_elevated_action_type_should_warn_true(self):
        result = evaluate_action_policy("tool_call", "safe_tool")
        assert result["should_warn"] is True

    def test_elevated_action_type_should_halt_false(self):
        result = evaluate_action_policy("git_operation", "git pull")
        assert result["should_halt"] is False

    def test_elevated_action_label(self):
        result = evaluate_action_policy("shell_command", "safe_target_xyz_irrelevant")
        assert result["reasons"][0]["label"] == "Elevated action type"

    def test_non_elevated_action_not_caught_here(self):
        # file_edit is not in ELEVATED_REVIEW_ACTIONS — must reach allow
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["verdict"] == "allow"


# ---------------------------------------------------------------------------
# evaluate_action_policy — high review (target)
# NOTE: action_type must NOT be in ELEVATED_REVIEW_ACTIONS so the
#       high-review-target branch is reached.  "file_edit" is not elevated.
# ---------------------------------------------------------------------------


class TestEvaluateActionPolicyHighReview:
    def test_high_review_target_returns_warn(self):
        result = evaluate_action_policy("file_edit", "curl https://example.com")
        assert result["verdict"] == "warn"

    def test_high_review_target_policy_mode_review(self):
        result = evaluate_action_policy("file_edit", "powershell script.ps1")
        assert result["policy_mode"] == "review"

    def test_high_review_target_should_warn_true(self):
        result = evaluate_action_policy("file_edit", "wget http://example.com")
        assert result["should_warn"] is True

    def test_high_review_target_should_halt_false(self):
        result = evaluate_action_policy("file_edit", "docker run ubuntu")
        assert result["should_halt"] is False

    def test_high_review_target_label(self):
        # file_edit is NOT elevated → high-review branch fires → "Elevated target"
        result = evaluate_action_policy("file_edit", "curl https://example.com")
        assert result["reasons"][0]["label"] == "Elevated target"

    def test_high_review_target_case_insensitive(self):
        result = evaluate_action_policy("file_edit", "POWERSHELL -NoProfile")
        assert result["verdict"] == "warn"


# ---------------------------------------------------------------------------
# evaluate_action_policy — allow
# ---------------------------------------------------------------------------


class TestEvaluateActionPolicyAllow:
    def test_clean_target_and_action_returns_allow(self):
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["verdict"] == "allow"

    def test_allow_policy_mode(self):
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["policy_mode"] == "allow"

    def test_allow_should_halt_false(self):
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["should_halt"] is False

    def test_allow_should_warn_false(self):
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["should_warn"] is False

    def test_allow_reason_source_policy(self):
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["reasons"][0]["source"] == "policy"

    def test_allow_reason_score_zero(self):
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["reasons"][0]["score"] == 0.0

    def test_allow_passes_none_ids_through(self):
        result = evaluate_action_policy("file_edit", "readme.txt")
        assert result["client_id"] is None
        assert result["session_id"] is None


# ---------------------------------------------------------------------------
# evaluate_action_policy — priority: block > elevated action > high review
# ---------------------------------------------------------------------------


class TestEvaluateActionPolicyPriority:
    def test_blocked_target_wins_over_elevated_action(self):
        result = evaluate_action_policy("shell_command", "/etc/passwd")
        assert result["verdict"] == "block"

    def test_blocked_target_wins_over_high_review(self):
        result = evaluate_action_policy("file_edit", "/root/.env")
        assert result["verdict"] == "block"


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — supabase not configured
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesNotConfigured:
    def test_returns_false_when_not_configured(self):
        with patch("app.supabaseclient.is_supabase_configured", return_value=False):
            with patch("app.supabaseclient.get_supabase_client"):
                result = load_builtin_policy_rules_from_db()
        assert result is False

    def test_defaults_preserved_when_not_configured(self):
        with patch("app.supabaseclient.is_supabase_configured", return_value=False):
            with patch("app.supabaseclient.get_supabase_client"):
                load_builtin_policy_rules_from_db()
        assert _ap.BLOCKED_TARGETS == _DEFAULT_BLOCKED_TARGETS
        assert _ap.HIGH_REVIEW_TARGETS == _DEFAULT_HIGH_REVIEW_TARGETS
        assert _ap.ELEVATED_REVIEW_ACTIONS == _DEFAULT_ELEVATED_REVIEW_ACTIONS

    def test_policy_loaded_from_db_false_when_not_configured(self):
        with patch("app.supabaseclient.is_supabase_configured", return_value=False):
            with patch("app.supabaseclient.get_supabase_client"):
                load_builtin_policy_rules_from_db()
        assert is_policy_loaded_from_db() is False


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — set not found
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesSetNotFound:
    def test_returns_false_when_set_not_found(self):
        client = _make_supabase_client(set_rows=[], membership_rows=[], rules_rows=[])
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db()
        assert result is False

    def test_defaults_preserved_when_set_not_found(self):
        client = _make_supabase_client(set_rows=[], membership_rows=[], rules_rows=[])
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                load_builtin_policy_rules_from_db()
        assert _ap.BLOCKED_TARGETS == _DEFAULT_BLOCKED_TARGETS


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — memberships empty
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesMembershipsEmpty:
    def test_returns_false_when_memberships_empty(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[],
            rules_rows=[],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db()
        assert result is False

    def test_defaults_preserved_when_memberships_empty(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[],
            rules_rows=[],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                load_builtin_policy_rules_from_db()
        assert _ap.HIGH_REVIEW_TARGETS == _DEFAULT_HIGH_REVIEW_TARGETS


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — rules empty
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesRulesEmpty:
    def test_returns_false_when_no_active_rules(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[{"policy_rule_id": "rule-1"}],
            rules_rows=[],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db()
        assert result is False


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — reads policy_rule_id (canonical column)
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesCanonicalColumn:
    def test_reads_policy_rule_id_not_rule_id(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[
                {"policy_rule_id": "rule-1"},
                {"rule_id": "rule-WRONG"},
            ],
            rules_rows=[
                {"rule_type": "blocked_target", "value": "custom_blocked_path"},
            ],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db()
        assert result is True
        assert "custom_blocked_path" in _ap.BLOCKED_TARGETS

    def test_row_missing_policy_rule_id_is_skipped(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[{"rule_id": "rule-WRONG"}],
            rules_rows=[{"rule_type": "blocked_target", "value": "should_not_appear"}],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db()
        assert result is False
        assert "should_not_appear" not in _ap.BLOCKED_TARGETS


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — hydrates all three global sets
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesHydratesGlobals:
    def _run_with_rules(self, rules: list[dict]) -> bool:
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[{"policy_rule_id": f"r{i}"} for i in range(len(rules))],
            rules_rows=rules,
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                return load_builtin_policy_rules_from_db()

    def test_blocked_target_added_to_blocked_targets(self):
        self._run_with_rules([{"rule_type": "blocked_target", "value": "forbidden_path"}])
        assert "forbidden_path" in _ap.BLOCKED_TARGETS

    def test_high_review_target_added_to_high_review_targets(self):
        self._run_with_rules([{"rule_type": "high_review_target", "value": "risky_tool"}])
        assert "risky_tool" in _ap.HIGH_REVIEW_TARGETS

    def test_elevated_review_action_added_to_elevated_review_actions(self):
        self._run_with_rules([{"rule_type": "elevated_review_action", "value": "custom_action"}])
        assert "custom_action" in _ap.ELEVATED_REVIEW_ACTIONS

    def test_defaults_are_floor_not_replaced(self):
        self._run_with_rules([{"rule_type": "blocked_target", "value": "new_blocked"}])
        assert _DEFAULT_BLOCKED_TARGETS.issubset(_ap.BLOCKED_TARGETS)
        assert _DEFAULT_HIGH_REVIEW_TARGETS.issubset(_ap.HIGH_REVIEW_TARGETS)
        assert _DEFAULT_ELEVATED_REVIEW_ACTIONS.issubset(_ap.ELEVATED_REVIEW_ACTIONS)

    def test_returns_true_on_successful_load(self):
        result = self._run_with_rules([{"rule_type": "blocked_target", "value": "something"}])
        assert result is True

    def test_unrecognised_rule_type_skipped(self):
        self._run_with_rules([{"rule_type": "unknown_type", "value": "garbage"}])
        assert "garbage" not in _ap.BLOCKED_TARGETS
        assert "garbage" not in _ap.HIGH_REVIEW_TARGETS
        assert "garbage" not in _ap.ELEVATED_REVIEW_ACTIONS

    def test_empty_value_rows_skipped(self):
        self._run_with_rules([{"rule_type": "blocked_target", "value": ""}])
        assert "" not in _ap.BLOCKED_TARGETS

    def test_value_lowercased_on_load(self):
        self._run_with_rules([{"rule_type": "blocked_target", "value": "UPPER_PATH"}])
        assert "upper_path" in _ap.BLOCKED_TARGETS
        assert "UPPER_PATH" not in _ap.BLOCKED_TARGETS

    def test_policy_loaded_from_db_true_after_success(self):
        self._run_with_rules([{"rule_type": "blocked_target", "value": "x"}])
        assert is_policy_loaded_from_db() is True


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — tenant fallback
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesTenantFallback:
    def test_tenant_key_not_found_falls_back_to_default(self):
        call_count = {"n": 0}

        def _table(name: str) -> MagicMock:
            tb = MagicMock()

            def _select(*_a, **_kw):
                q = MagicMock()

                def _eq(col, val):
                    return q

                def _in_(col, vals):
                    return q

                def _limit(n):
                    return q

                def _execute():
                    resp = MagicMock()
                    if name == "policy_sets":
                        call_count["n"] += 1
                        if call_count["n"] == 1:
                            resp.data = []
                        else:
                            resp.data = [{"id": "set-default", "set_key": DEFAULT_POLICY_SET_KEY}]
                    elif name == "policy_set_memberships":
                        resp.data = [{"policy_rule_id": "r1"}]
                    elif name == "policy_rules":
                        resp.data = [{"rule_type": "blocked_target", "value": "fallback_blocked"}]
                    else:
                        resp.data = []
                    return resp

                q.eq = _eq
                q.in_ = _in_
                q.limit = _limit
                q.execute = _execute
                return q

            tb.select = _select
            return tb

        client = MagicMock()
        client.table.side_effect = _table

        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db(tenant_key="tenant_missing")

        assert result is True
        assert "fallback_blocked" in _ap.BLOCKED_TARGETS

    def test_no_fallback_when_tenant_key_is_none(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[{"policy_rule_id": "r1"}],
            rules_rows=[{"rule_type": "blocked_target", "value": "direct_default"}],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db(tenant_key=None)

        assert result is True
        assert "direct_default" in _ap.BLOCKED_TARGETS


# ---------------------------------------------------------------------------
# load_builtin_policy_rules_from_db — exception handling
# ---------------------------------------------------------------------------


class TestLoadPolicyRulesExceptionHandling:
    def test_returns_false_on_unexpected_exception(self):
        client = MagicMock()
        client.table.side_effect = RuntimeError("db exploded")
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = load_builtin_policy_rules_from_db()
        assert result is False

    def test_does_not_raise_on_unexpected_exception(self):
        client = MagicMock()
        client.table.side_effect = RuntimeError("db exploded")
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                try:
                    load_builtin_policy_rules_from_db()
                except Exception as e:
                    pytest.fail(f"load_builtin_policy_rules_from_db raised: {e}")

    def test_defaults_preserved_on_exception(self):
        client = MagicMock()
        client.table.side_effect = RuntimeError("db exploded")
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                load_builtin_policy_rules_from_db()
        assert _ap.BLOCKED_TARGETS == _DEFAULT_BLOCKED_TARGETS


# ---------------------------------------------------------------------------
# reload_policy_rules — delegates to load_builtin_policy_rules_from_db
# ---------------------------------------------------------------------------


class TestReloadPolicyRules:
    def test_reload_returns_same_result_as_load(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[{"policy_rule_id": "r1"}],
            rules_rows=[{"rule_type": "blocked_target", "value": "reload_check"}],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                result = reload_policy_rules()
        assert result is True

    def test_reload_hydrates_globals(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[{"policy_rule_id": "r1"}],
            rules_rows=[{"rule_type": "blocked_target", "value": "reload_target"}],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                reload_policy_rules()
        assert "reload_target" in _ap.BLOCKED_TARGETS

    def test_reload_passes_tenant_key(self):
        with patch(
            "app.services.action_policy.load_builtin_policy_rules_from_db",
            return_value=True,
        ) as mock_load:
            reload_policy_rules(tenant_key="my_tenant")
        mock_load.assert_called_once_with(tenant_key="my_tenant")


# ---------------------------------------------------------------------------
# is_policy_loaded_from_db
# ---------------------------------------------------------------------------


class TestIsPolicyLoadedFromDb:
    def test_false_before_any_load(self):
        assert is_policy_loaded_from_db() is False

    def test_true_after_successful_load(self):
        client = _make_supabase_client(
            set_rows=[{"id": "set-1", "set_key": DEFAULT_POLICY_SET_KEY}],
            membership_rows=[{"policy_rule_id": "r1"}],
            rules_rows=[{"rule_type": "blocked_target", "value": "x"}],
        )
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                load_builtin_policy_rules_from_db()
        assert is_policy_loaded_from_db() is True

    def test_false_after_failed_load(self):
        client = _make_supabase_client(set_rows=[], membership_rows=[], rules_rows=[])
        with _configured_patch():
            with patch("app.supabaseclient.get_supabase_client", return_value=client):
                load_builtin_policy_rules_from_db()
        assert is_policy_loaded_from_db() is False
