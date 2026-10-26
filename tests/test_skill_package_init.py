from __future__ import annotations

import importlib

import pytest


def test_package_exposes_expected_public_metadata() -> None:
    package = importlib.import_module("ironclawskill")

    assert package.__package_name__ == "ironclawskill"
    assert isinstance(package.__version__, str)
    assert package.__version__


def test_package_dir_includes_expected_public_modules() -> None:
    package = importlib.import_module("ironclawskill")

    names = dir(package)

    for expected in (
        "adapterguard",
        "adapterclaude",
        "adapteropenclaw",
        "billing",
        "cli",
        "config",
        "context",
        "contracts",
        "errors",
        "middleware",
        "router",
        "runtime",
        "__package_name__",
        "__version__",
    ):
        assert expected in names


@pytest.mark.parametrize(
    "module_name",
    [
        "adapterguard",
        "adapterclaude",
        "adapteropenclaw",
        "billing",
        "cli",
        "config",
        "context",
        "contracts",
        "errors",
        "middleware",
        "router",
        "runtime",
    ],
)
def test_package_lazy_loads_public_submodules(module_name: str) -> None:
    package = importlib.import_module("ironclawskill")

    module = getattr(package, module_name)

    assert module is importlib.import_module(f"ironclawskill.{module_name}")
    assert getattr(package, module_name) is module


def test_package_rejects_unknown_attribute_access() -> None:
    package = importlib.import_module("ironclawskill")

    with pytest.raises(AttributeError):
        _ = package.does_not_exist


def test_package_all_exports_match_public_contract() -> None:
    package = importlib.import_module("ironclawskill")

    assert "__package_name__" in package.__all__
    assert "__version__" in package.__all__

    expected_modules = {
        "adapterguard",
        "adapterclaude",
        "adapteropenclaw",
        "billing",
        "cli",
        "config",
        "context",
        "contracts",
        "errors",
        "middleware",
        "router",
        "runtime",
    }
    assert expected_modules.issubset(set(package.__all__))


def test_package_exports_guard_adapter_symbols() -> None:
    package = importlib.import_module("ironclawskill")

    for expected in (
        "GuardAdapter",
        "GuardSkillAdapter",
        "adaptguardrequest",
        "adaptguardresponse",
    ):
        assert expected in package.__all__
        assert getattr(package, expected) is not None
