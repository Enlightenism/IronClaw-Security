from __future__ import annotations

from typing import Annotated

from fastapi import Depends

from repositories.release_policy_repository import (
    ReleasePolicyRepository,
    release_policy_repository,
)
from services.release_policy_decision_store import (
    ReleasePolicyDecisionStore,
    release_policy_decision_store,
)
from services.release_policy_service import (
    ReleasePolicyService,
    release_policy_service,
)


def get_release_policy_repository() -> ReleasePolicyRepository:
    return release_policy_repository


def get_release_policy_service() -> ReleasePolicyService:
    return release_policy_service


def get_release_policy_decision_store() -> ReleasePolicyDecisionStore:
    return release_policy_decision_store


ReleasePolicyRepositoryDep = Annotated[
    ReleasePolicyRepository,
    Depends(get_release_policy_repository),
]

ReleasePolicyServiceDep = Annotated[
    ReleasePolicyService,
    Depends(get_release_policy_service),
]

ReleasePolicyDecisionStoreDep = Annotated[
    ReleasePolicyDecisionStore,
    Depends(get_release_policy_decision_store),
]