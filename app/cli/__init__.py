from app.cli.install import (
    build_install_parser,
    handle_install_args,
    run_install_command,
)
from app.cli.install import (
    main as install_main,
)
from app.cli.package import (
    build_package_parser,
    handle_package_args,
    run_package_command,
)
from app.cli.package import (
    main as package_main,
)
from app.cli.uninstall import (
    build_uninstall_parser,
    handle_uninstall_args,
    run_uninstall_command,
)
from app.cli.uninstall import (
    main as uninstall_main,
)
from app.cli.update import (
    build_update_parser,
    handle_update_args,
    run_update_command,
)
from app.cli.update import (
    main as update_main,
)
from app.cli.verify import (
    build_verify_parser,
    handle_verify_args,
    run_verify_command,
)
from app.cli.verify import (
    main as verify_main,
)

__all__ = [
    "build_install_parser",
    "handle_install_args",
    "install_main",
    "run_install_command",
    "build_package_parser",
    "handle_package_args",
    "package_main",
    "run_package_command",
    "build_uninstall_parser",
    "handle_uninstall_args",
    "uninstall_main",
    "run_uninstall_command",
    "build_update_parser",
    "handle_update_args",
    "update_main",
    "run_update_command",
    "build_verify_parser",
    "handle_verify_args",
    "verify_main",
    "run_verify_command",
]