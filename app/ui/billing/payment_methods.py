from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter
from pydantic import BaseModel, Field

router = APIRouter(
    prefix="/ui/billing",
    tags=["billing-payment-methods"],
)

_MAX_METHODS = 4

_STATUS_COLOR: dict[str, str] = {
    "active": "success",
    "expired": "warning",
    "revoked": "error",
}

_BRAND_DISPLAY: dict[str, str] = {
    "visa": "Visa",
    "mastercard": "Mastercard",
    "amex": "American Express",
    "discover": "Discover",
    "bank_account": "Bank Account",
}


class BillingPaymentMethodView(BaseModel):
    methodid: str
    type: str
    brand: str
    branddisplay: str
    last4: str
    expmonth: int
    expyear: int
    expdisplay: str
    isdefault: bool
    status: str
    statuscolor: str
    createdat: str
    organizationid: str


class BillingPaymentMethodsResponse(BaseModel):
    generatedat: str
    environment: str
    organizationid: str
    defaultmethodid: str | None
    methods: list[BillingPaymentMethodView] = Field(default_factory=list)
    methodcount: int
    canaddnew: bool
    maxmethods: int
    notes: list[str] = Field(default_factory=list)


class BillingPaymentMethodsNotFoundResponse(BaseModel):
    status: str
    organizationid: str
    message: str
    generatedat: str
    environment: str


def _utc_iso(year: int, month: int, day: int, hour: int, minute: int = 0) -> str:
    return datetime(year, month, day, hour, minute, 0, tzinfo=UTC).isoformat()


def _status_color(status: str) -> str:
    return _STATUS_COLOR.get(status, "neutral")


def _brand_display(brand: str) -> str:
    return _BRAND_DISPLAY.get(brand, brand.title())


def _exp_display(expmonth: int, expyear: int) -> str:
    return f"{expmonth:02d}/{expyear}"


def _build_method(
    methodid: str,
    type: str,
    brand: str,
    last4: str,
    expmonth: int,
    expyear: int,
    isdefault: bool,
    status: str,
    createdat: str,
    organizationid: str,
) -> BillingPaymentMethodView:
    return BillingPaymentMethodView(
        methodid=methodid,
        type=type,
        brand=brand,
        branddisplay=_brand_display(brand),
        last4=last4,
        expmonth=expmonth,
        expyear=expyear,
        expdisplay=_exp_display(expmonth, expyear),
        isdefault=isdefault,
        status=status,
        statuscolor=_status_color(status),
        createdat=createdat,
        organizationid=organizationid,
    )


_ORG_METHODS: dict[str, list[BillingPaymentMethodView]] = {
    "org-001": [
        _build_method(
            methodid="pm-001",
            type="card",
            brand="visa",
            last4="4242",
            expmonth=9,
            expyear=2027,
            isdefault=True,
            status="active",
            createdat=_utc_iso(2026, 1, 15, 10, 0),
            organizationid="org-001",
        ),
        _build_method(
            methodid="pm-004",
            type="card",
            brand="mastercard",
            last4="1234",
            expmonth=2,
            expyear=2026,
            isdefault=False,
            status="expired",
            createdat=_utc_iso(2025, 6, 10, 9, 30),
            organizationid="org-001",
        ),
        _build_method(
            methodid="pm-005",
            type="card",
            brand="amex",
            last4="7890",
            expmonth=12,
            expyear=2028,
            isdefault=False,
            status="active",
            createdat=_utc_iso(2026, 3, 22, 14, 15),
            organizationid="org-001",
        ),
    ],
    "org-002": [
        _build_method(
            methodid="pm-002",
            type="card",
            brand="mastercard",
            last4="5555",
            expmonth=3,
            expyear=2026,
            isdefault=True,
            status="expired",
            createdat=_utc_iso(2025, 9, 5, 11, 0),
            organizationid="org-002",
        ),
        _build_method(
            methodid="pm-006",
            type="card",
            brand="visa",
            last4="9999",
            expmonth=8,
            expyear=2027,
            isdefault=False,
            status="active",
            createdat=_utc_iso(2026, 4, 1, 8, 45),
            organizationid="org-002",
        ),
    ],
    "org-003": [
        _build_method(
            methodid="pm-003",
            type="card",
            brand="amex",
            last4="0005",
            expmonth=11,
            expyear=2027,
            isdefault=True,
            status="active",
            createdat=_utc_iso(2025, 11, 20, 16, 0),
            organizationid="org-003",
        ),
        _build_method(
            methodid="pm-007",
            type="card",
            brand="visa",
            last4="3333",
            expmonth=5,
            expyear=2025,
            isdefault=False,
            status="revoked",
            createdat=_utc_iso(2025, 3, 14, 9, 0),
            organizationid="org-003",
        ),
        _build_method(
            methodid="pm-008",
            type="card",
            brand="mastercard",
            last4="6677",
            expmonth=1,
            expyear=2029,
            isdefault=False,
            status="active",
            createdat=_utc_iso(2026, 2, 28, 13, 0),
            organizationid="org-003",
        ),
    ],
}

_VALID_ORG_IDS: frozenset[str] = frozenset(_ORG_METHODS.keys())


def _resolve_default_method_id(methods: list[BillingPaymentMethodView]) -> str | None:
    for method in methods:
        if method.isdefault:
            return method.methodid
    return None


@router.get(
    "/payment-methods",
    response_model=BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse,
)
def get_payment_methods(
    organizationid: str = "org-001",
) -> BillingPaymentMethodsResponse | BillingPaymentMethodsNotFoundResponse:
    if organizationid not in _VALID_ORG_IDS:
        return BillingPaymentMethodsNotFoundResponse(
            status="not_found",
            organizationid=organizationid,
            message=f"Organization '{organizationid}' was not found. Valid sample IDs are: org-001, org-002, org-003.",
            generatedat=datetime.now(UTC).isoformat(),
            environment="local",
        )

    methods = _ORG_METHODS[organizationid]
    methodcount = len(methods)
    defaultmethodid = _resolve_default_method_id(methods)
    canaddnew = methodcount < _MAX_METHODS

    active_count = sum(1 for m in methods if m.status == "active")
    expired_count = sum(1 for m in methods if m.status == "expired")
    revoked_count = sum(1 for m in methods if m.status == "revoked")

    notes = [
        f"Organization '{organizationid}' has {methodcount} payment method(s) on file.",
        f"Active: {active_count}. Expired: {expired_count}. Revoked: {revoked_count}.",
        f"Maximum allowed payment methods per organization is {_MAX_METHODS}.",
        f"canaddnew is {'true' if canaddnew else 'false'} — organization {'can' if canaddnew else 'cannot'} add new payment methods.",
        "statuscolor maps payment method status to a UI hint: success (active), warning (expired), error (revoked).",
        "All values are placeholder UI contract data for the current local-first Gen1 build.",
        "This page is ready to be wired to a live payment provider such as Stripe.",
    ]

    if expired_count > 0:
        notes.append("One or more payment methods are expired. Prompt the user to update billing details.")
    if revoked_count > 0:
        notes.append("One or more payment methods have been revoked and cannot be used for future charges.")

    return BillingPaymentMethodsResponse(
        generatedat=datetime.now(UTC).isoformat(),
        environment="local",
        organizationid=organizationid,
        defaultmethodid=defaultmethodid,
        methods=methods,
        methodcount=methodcount,
        canaddnew=canaddnew,
        maxmethods=_MAX_METHODS,
        notes=notes,
    )
