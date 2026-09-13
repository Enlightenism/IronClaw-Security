from __future__ import annotations

from pathlib import Path

import cli.uninstall as uninstall_cli


def test_uninstall_uses_same_default_install_root_semantics_as_other_clis() -> None:
    plan = uninstall_cli.build_uninstall_plan(dry_run=True)
    default_root = uninstall_cli._default_install_root().resolve()

    assert Path(plan.install_root) == default_root
    assert Path(plan.config_root) == (default_root / "config.json").resolve()
    assert Path(plan.data_root) == (default_root / "data").resolve()
