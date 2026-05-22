from app.cli.install import (
    build_install_parser,
    handle_install_args,
    run_install_command,
)
from app.cli.install import main as install_main
from app.cli.main import main, run_cli
from app.cli.package import (
    build_package_parser,
    handle_package_args,
    run_package_command,
)
from app.cli.package import main as package_main
from app.cli.uninstall import (
    build_uninstall_parser,
    handle_uninstall_args,
    run_uninstall_command,
)
from app.cli.uninstall import main as uninstall_main
from app.cli.update import (
    build_update_parser,
    handle_update_args,
    run_update_command,
)
from app.cli.update import main as update_main
from app.cli.verify import (
    build_verify_parser,
    handle_verify_args,
    run_verify_command,
)
from app.cli.verify import main as verify_main

__all__ = [
    "build_install_parser",
    "build_package_parser",
    "build_uninstall_parser",
    "build_update_parser",
    "build_verify_parser",
    "handle_install_args",
    "handle_package_args",
    "handle_uninstall_args",
    "handle_update_args",
    "handle_verify_args",
    "install_main",
    "main",
    "package_main",
    "run_cli",
    "run_install_command",
    "run_package_command",
    "run_uninstall_command",
    "run_update_command",
    "run_verify_command",
    "uninstall_main",
    "update_main",
    "verify_main",
]
