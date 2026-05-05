import app.orchestrator.supervisor as supervisor_module


def test_supervisor_initialize_function_exists():
    assert hasattr(supervisor_module, "initialize_supervisor")


def test_supervisor_summary_function_exists_if_exported():
    assert hasattr(supervisor_module, "summarize_supervisor")


def test_supervisor_snapshot_type_exists_if_exported():
    public_names = set(name for name in dir(supervisor_module) if not name.startswith("_"))
    assert "SupervisorSnapshot" in public_names


def test_supervisor_request_type_exists_if_exported():
    public_names = set(name for name in dir(supervisor_module) if not name.startswith("_"))
    assert "SessionExecutionRequest" in public_names


def test_supervisor_record_type_exists_if_exported():
    public_names = set(name for name in dir(supervisor_module) if not name.startswith("_"))
    assert "SessionExecutionRecord" in public_names


def test_supervisor_escalation_type_exists_if_exported():
    public_names = set(name for name in dir(supervisor_module) if not name.startswith("_"))
    assert "SupervisorEscalation" in public_names


def test_supervisor_status_alias_exists_if_exported():
    public_names = set(name for name in dir(supervisor_module) if not name.startswith("_"))
    assert "SupervisorStatus" in public_names


def test_supervisor_initialize_and_summarize_are_callable():
    assert callable(supervisor_module.initialize_supervisor)
    assert callable(supervisor_module.summarize_supervisor)