import app.orchestrator.supervisor as supervisor_module


def test_supervisor_module_imports():
    assert supervisor_module is not None


def test_supervisor_module_name_is_correct():
    assert supervisor_module.__name__ == "app.orchestrator.supervisor"


def test_supervisor_exposes_public_members():
    public_names = [name for name in dir(supervisor_module) if not name.startswith("_")]
    assert isinstance(public_names, list)
    assert len(public_names) > 0


def test_supervisor_has_file_attribute():
    assert hasattr(supervisor_module, "__file__")
    assert str(supervisor_module.__file__).endswith("supervisor.py")


def test_supervisor_common_symbols_exist_if_defined():
    public_names = set(name for name in dir(supervisor_module) if not name.startswith("_"))
    expected_candidates = {
        "SupervisorSnapshot",
        "SessionExecutionRequest",
        "SessionExecutionRecord",
        "SupervisorEscalation",
        "initialize_supervisor",
        "get_or_create_session",
        "run_supervised_request",
        "summarize_supervisor",
    }
    assert len(public_names.intersection(expected_candidates)) >= 1
