from __future__ import annotations

from app.api.router import CANONICAL_BILLING_MODULE, OPTIONAL_API_MODULES


def test_router_inventory_keeps_single_canonical_billing_module() -> None:
    billing_modules = [module for module in OPTIONAL_API_MODULES if module.endswith("billing")]

    assert billing_modules.count(CANONICAL_BILLING_MODULE) == 1
    assert all(module == CANONICAL_BILLING_MODULE for module in billing_modules)
    assert "app.api.billing" not in OPTIONAL_API_MODULES
