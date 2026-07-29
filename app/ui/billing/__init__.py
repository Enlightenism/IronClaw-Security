from __future__ import annotations

from app.ui.billing.invoice_detail import (
    BillingCurrencyAmountView as InvoiceDetailCurrencyAmountView,
)
from app.ui.billing.invoice_detail import (
    BillingInvoiceDetailResponse,
    BillingInvoiceLineItem,
    BillingInvoiceNotFoundResponse,
    BillingPackageSnapshotView,
    BillingPaymentMethodSnapshotView,
    get_invoice_detail,
)
from app.ui.billing.invoice_detail import (
    BillingUsageBucketView as InvoiceDetailUsageBucketView,
)
from app.ui.billing.invoice_detail import (
    router as invoice_detail_router,
)
from app.ui.billing.invoices import (
    BillingCurrencyAmountView as InvoicesCurrencyAmountView,
)
from app.ui.billing.invoices import (
    BillingInvoiceDownloadResponse,
    BillingInvoiceListFilters,
    BillingInvoiceListItem,
    BillingInvoiceListResponse,
    get_billing_invoices,
    get_invoice_download,
)
from app.ui.billing.invoices import (
    BillingInvoiceStatusCount as InvoicesStatusCount,
)
from app.ui.billing.invoices import (
    router as invoices_router,
)
from app.ui.billing.overview import (
    BillingCurrencyAmountView as OverviewCurrencyAmountView,
)
from app.ui.billing.overview import (
    BillingInvoiceStatusCount as OverviewInvoiceStatusCount,
)
from app.ui.billing.overview import (
    BillingInvoiceView,
    BillingKpiView,
    BillingOverviewResponse,
    BillingPackageView,
    BillingPlanCount,
    get_billing_overview,
)
from app.ui.billing.overview import (
    BillingUsageBucketView as OverviewUsageBucketView,
)
from app.ui.billing.overview import (
    router as overview_router,
)
from app.ui.billing.package import (
    BillingCurrencyAmountView as PackageCurrencyAmountView,
)
from app.ui.billing.package import (
    BillingPackageListFilters,
    BillingPackageListItem,
    BillingPackageListResponse,
    BillingPackagePlanCount,
    BillingPackageStatusCount,
    get_billing_packages,
)
from app.ui.billing.package import (
    BillingUsageBucketView as PackageUsageBucketView,
)
from app.ui.billing.package import (
    router as package_router,
)
from app.ui.billing.payment_methods import (
    PACKAGE_CATALOGUE,
    BillingPaymentMethodsNotFoundResponse,
    BillingPaymentMethodsResponse,
    BillingPaymentMethodStatusCount,
    BillingPaymentMethodView,
    DeletePaymentMethodResponse,
    PackageCatalogueEntry,
    SetDefaultPaymentMethodResponse,
    get_payment_methods,
)
from app.ui.billing.payment_methods import (
    router as payment_methods_router,
)
from app.ui.billing.plan_change import (
    BillingCurrencyAmountView as PlanChangeCurrencyAmountView,
)
from app.ui.billing.plan_change import (
    BillingPlanChangeNotFoundResponse,
    BillingPlanChangePreviewView,
    BillingPlanChangeResponse,
    BillingPlanOptionView,
    get_plan_change,
)
from app.ui.billing.plan_change import (
    router as plan_change_router,
)

BILLING_ROUTERS = [
    overview_router,
    invoices_router,
    invoice_detail_router,
    payment_methods_router,
    plan_change_router,
    package_router,
]

__all__ = [
    # routers
    "BILLING_ROUTERS",
    "overview_router",
    "invoices_router",
    "invoice_detail_router",
    "payment_methods_router",
    "plan_change_router",
    "package_router",
    # overview
    "BillingKpiView",
    "BillingPlanCount",
    "BillingOverviewResponse",
    "BillingPackageView",
    "BillingInvoiceView",
    "OverviewCurrencyAmountView",
    "OverviewUsageBucketView",
    "OverviewInvoiceStatusCount",
    "get_billing_overview",
    # invoices
    "BillingInvoiceListItem",
    "BillingInvoiceListFilters",
    "BillingInvoiceListResponse",
    "BillingInvoiceDownloadResponse",
    "InvoicesStatusCount",
    "InvoicesCurrencyAmountView",
    "get_billing_invoices",
    "get_invoice_download",
    # invoice detail
    "BillingInvoiceDetailResponse",
    "BillingInvoiceNotFoundResponse",
    "BillingInvoiceLineItem",
    "BillingPackageSnapshotView",
    "BillingPaymentMethodSnapshotView",
    "InvoiceDetailCurrencyAmountView",
    "InvoiceDetailUsageBucketView",
    "get_invoice_detail",
    # payment methods
    "PACKAGE_CATALOGUE",
    "PackageCatalogueEntry",
    "BillingPaymentMethodView",
    "BillingPaymentMethodStatusCount",
    "BillingPaymentMethodsResponse",
    "BillingPaymentMethodsNotFoundResponse",
    "SetDefaultPaymentMethodResponse",
    "DeletePaymentMethodResponse",
    "get_payment_methods",
    # plan change
    "BillingPlanOptionView",
    "BillingPlanChangePreviewView",
    "BillingPlanChangeResponse",
    "BillingPlanChangeNotFoundResponse",
    "PlanChangeCurrencyAmountView",
    "get_plan_change",
    # packages
    "BillingPackageListItem",
    "BillingPackageListFilters",
    "BillingPackageListResponse",
    "BillingPackageStatusCount",
    "BillingPackagePlanCount",
    "PackageUsageBucketView",
    "PackageCurrencyAmountView",
    "get_billing_packages",
]
