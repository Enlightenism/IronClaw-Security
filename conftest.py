from __future__ import annotations

import asyncio
import inspect
import os

# Hard-set all required env vars before ANY app module is imported.
# setdefault is insufficient — CI may have these unset or empty string.
os.environ["IRONCLAW_PERSISTENCE_MODE"] = "memory"
os.environ["ENVIRONMENT"] = "test"
os.environ["AUTH_REQUIRED"] = "true"
os.environ["IRONCLAW_API_KEY"] = "test-api-key"
os.environ["SUPABASE_URL"] = os.environ.get("SUPABASE_URL") or ""
os.environ["SUPABASE_SERVICE_ROLE_KEY"] = os.environ.get("SUPABASE_SERVICE_ROLE_KEY") or ""
os.environ["SUPABASE_KEY"] = os.environ.get("SUPABASE_KEY") or ""
os.environ["SUPABASE_ANON_KEY"] = os.environ.get("SUPABASE_ANON_KEY") or ""

import pytest


def pytest_pyfunc_call(pyfuncitem: pytest.Function) -> bool | None:
    testfunction = pyfuncitem.obj
    if not inspect.iscoroutinefunction(testfunction):
        return None

    kwargs = {name: pyfuncitem.funcargs[name] for name in pyfuncitem._fixtureinfo.argnames if name in pyfuncitem.funcargs}
    asyncio.run(testfunction(**kwargs))
    return True
