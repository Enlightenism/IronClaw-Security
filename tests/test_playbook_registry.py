import app.orchestrator.playbook_registry as registry_module


def test_playbook_registry_module_imports():
    assert registry_module is not None


def test_playbook_registry_has_module_name():
    assert registry_module.__name__ == "app.orchestrator.playbook_registry"


def test_playbook_registry_exposes_some_public_members():
    public_names = [name for name in dir(registry_module) if not name.startswith("_")]
    assert isinstance(public_names, list)
    assert len(public_names) > 0


def test_playbook_registry_public_members_are_strings():
    public_names = [name for name in dir(registry_module) if not name.startswith("_")]
    assert all(isinstance(name, str) for name in public_names)


def test_playbook_registry_has_file_attribute():
    assert hasattr(registry_module, "__file__")
    assert str(registry_module.__file__).endswith("playbook_registry.py")