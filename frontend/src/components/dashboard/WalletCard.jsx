/* global process */
import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  Wallet,
  CreditCard,
  Loader2,
  Zap,
  ShieldCheck,
  Trash2,
  Star,
  AlertTriangle,
} from "lucide-react";
import { useCountUp } from "@/hooks/useCountUp";
import api, { paymentMethods } from "@/lib/api";
import { toast } from "sonner";

const paymentMethodCache = new Map();

const normalizeBillingPackages = (data) => {
  const packages = data?.packages;
  if (!packages || typeof packages !== "object" || Array.isArray(packages)) {
    throw new Error("Billing catalogue did not include a package map.");
  }

  const tiers = Object.values(packages).map((packageInfo) => {
    const unitCount = Number(packageInfo?.units);
    const priceUsd = Number(packageInfo?.price_usd);
    const tokensPerUnit = Number(packageInfo?.tokens_per_unit);
    const tokenCoverage = Number(packageInfo?.token_coverage);
    const id =
      typeof packageInfo?.package_id === "string"
        ? packageInfo.package_id.trim()
        : "";
    const name =
      typeof packageInfo?.label === "string" ? packageInfo.label.trim() : "";

    if (
      !id ||
      !name ||
      !Number.isSafeInteger(unitCount) ||
      unitCount <= 0 ||
      !Number.isFinite(priceUsd) ||
      priceUsd <= 0 ||
      !Number.isSafeInteger(tokensPerUnit) ||
      tokensPerUnit <= 0 ||
      tokenCoverage !== unitCount * tokensPerUnit
    ) {
      throw new Error("Billing catalogue contains an invalid package.");
    }

    return {
      id,
      name,
      units: unitCount.toLocaleString(),
      unitCount,
      price: `$${priceUsd.toLocaleString("en-US", {
        maximumFractionDigits: 2,
      })}`,
      priceUsd,
      tokensPerUnit,
      tokenCoverage,
    };
  });

  if (!tiers.length) {
    throw new Error("Billing catalogue contains no packages.");
  }

  const highestPricedTier = tiers.reduce((highest, tier) =>
    tier.priceUsd > highest.priceUsd ? tier : highest,
  );

  return tiers.map((tier) => ({
    ...tier,
    bestDeal: tier.id === highestPricedTier.id,
  }));
};

const getStripePublishableKey = () =>
  process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY ?? "";

const getStripeMode = (publishableKey = "") => {
  if (publishableKey.startsWith("pk_live_")) return "live";
  if (publishableKey.startsWith("pk_test_")) return "test";
  return "unconfigured";
};

const getFirstString = (...values) => {
  for (const value of values) {
    if (typeof value === "string" && value.trim()) return value.trim();
  }
  return "";
};

const getFirstNumber = (...values) => {
  for (const value of values) {
    if (typeof value === "number" && Number.isFinite(value)) return value;
    if (typeof value === "string" && value.trim() !== "") {
      const parsed = Number(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return null;
};

const normalizePaymentMethod = (method, fallbackDefaultId = "") => {
  const methodId = getFirstString(
    method?.methodid,
    method?.paymentmethodid,
    method?.id,
  );

  const expMonth = getFirstNumber(
    method?.expmonth,
    method?.expMonth,
    method?.card?.exp_month,
  );
  const expYear = getFirstNumber(
    method?.expyear,
    method?.expYear,
    method?.card?.exp_year,
  );

  const brand = getFirstString(
    method?.brand_display,
    method?.branddisplay,
    method?.brand,
    method?.card?.brand,
  );

  const expDisplay = getFirstString(method?.exp_display, method?.expdisplay);
  const last4 = getFirstString(method?.last4, method?.card?.last4);
  const status = getFirstString(method?.status);
  const inferredDefault =
    method?.isdefault === true ||
    method?.is_default === true ||
    method?.default === true ||
    (methodId && fallbackDefaultId && methodId === fallbackDefaultId);

  const maskedSnapshot = {
    methodid: methodId,
    type: getFirstString(method?.type, method?.payment_method_type, "card"),
    brand,
    brandDisplay: brand,
    last4,
    expmonth: expMonth,
    expyear: expYear,
    expDisplay:
      expDisplay ||
      (expMonth && expYear
        ? `${String(expMonth).padStart(2, "0")}/${String(expYear).slice(-2)}`
        : ""),
    status,
    isDefault: inferredDefault,
  };

  return {
    ...maskedSnapshot,
    raw: maskedSnapshot,
  };
};

const normalizePaymentMethodsResponse = (data) => {
  const rawMethods = Array.isArray(data?.methods)
    ? data.methods
    : Array.isArray(data?.paymentmethods)
      ? data.paymentmethods
      : Array.isArray(data?.results)
        ? data.results
        : [];

  const defaultId = getFirstString(
    data?.defaultmethodid,
    data?.default_method_id,
    data?.defaultpaymentmethodid,
  );

  const methods = rawMethods
    .map((method) => normalizePaymentMethod(method, defaultId))
    .filter((method) => method.methodid);

  const resolvedDefaultId =
    defaultId || methods.find((method) => method.isDefault)?.methodid || "";

  return {
    methods: methods.map((method) => ({
      ...method,
      isDefault: resolvedDefaultId
        ? method.methodid === resolvedDefaultId
        : method.isDefault,
    })),
    defaultId: resolvedDefaultId || null,
  };
};

const EnterpriseBadge = () => (
  <div className="flex justify-center">
    <span
      className="relative inline-flex items-center gap-1 rounded-full border border-[#FFD700]/50 bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-3 py-0.5 text-[9px] font-bold uppercase tracking-[0.18em] text-black shadow-[0_0_12px_rgba(255,215,0,0.45)]"
      style={{ animation: "ic-badge-pulse 2.4s ease-in-out infinite" }}
    >
      <span
        className="absolute inset-0 rounded-full"
        style={{ animation: "ic-badge-shimmer 2.4s ease-in-out infinite" }}
      />
      ★ Best Deal
    </span>
    <style>{`
      @keyframes ic-badge-pulse {
        0%, 100% { box-shadow: 0 0 10px rgba(255,215,0,0.40); }
        50%      { box-shadow: 0 0 22px rgba(255,215,0,0.75), 0 0 6px rgba(255,215,0,0.30); }
      }
      @keyframes ic-badge-shimmer {
        0%   { background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.18) 50%, transparent 100%); background-size: 200% 100%; background-position: -100% 0; }
        60%  { background-position: 200% 0; }
        100% { background-position: 200% 0; }
      }
    `}</style>
  </div>
);

const StripeModeTag = ({ stripeMode }) => {
  if (stripeMode === "unconfigured") {
    return (
      <span
        className="ml-2 rounded-full border border-[#F59E0B]/40 bg-[#F59E0B]/10 px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest text-[#F59E0B]"
        title="Stripe publishable key is not configured in the frontend build"
      >
        Stripe unavailable
      </span>
    );
  }

  const isLive = stripeMode === "live";
  return (
    <span
      className={`ml-2 rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest ${
        isLive
          ? "border border-[#22C55E]/40 bg-[#22C55E]/10 text-[#22C55E]"
          : "border border-[#38BDF8]/40 bg-[#38BDF8]/10 text-[#38BDF8]"
      }`}
      title={`Stripe ${stripeMode} mode`}
    >
      Stripe {stripeMode}
    </span>
  );
};

const StripeKeyWarning = ({ stripeMode }) => {
  if (stripeMode !== "unconfigured") return null;

  return (
    <div className="mb-4 flex items-start gap-2 rounded-lg border border-[#F59E0B]/30 bg-[#F59E0B]/10 px-3 py-2 text-xs text-[#FDE68A]">
      <AlertTriangle size={13} className="mt-0.5 shrink-0 text-[#F59E0B]" />
      <span>
        Stripe publishable key is not present in the frontend build. Billing
        actions may fail until
        <strong className="ml-1 text-white">
          REACT_APP_STRIPE_PUBLISHABLE_KEY
        </strong>
        is set in the deployed frontend environment.
      </span>
    </div>
  );
};

const PaymentMethodPanel = ({
  organizationId,
  onAddPaymentMethod,
  addingPaymentMethod = false,
}) => {
  const cachedEntry = useMemo(
    () =>
      organizationId ? (paymentMethodCache.get(organizationId) ?? null) : null,
    [organizationId],
  );

  const [methods, setMethods] = useState(() => cachedEntry?.methods ?? []);
  const [defaultId, setDefaultId] = useState(
    () => cachedEntry?.defaultId ?? null,
  );
  const [loadingMethods, setLoadingMethods] = useState(
    () => !cachedEntry && !!organizationId,
  );
  const [methodsError, setMethodsError] = useState("");
  const [actionId, setActionId] = useState(null);
  const hasFetchedRef = useRef(!!cachedEntry);

  const syncCache = useCallback(
    (nextMethods, nextDefaultId) => {
      if (!organizationId) return;
      paymentMethodCache.set(organizationId, {
        methods: nextMethods,
        defaultId: nextDefaultId,
      });
    },
    [organizationId],
  );

  const fetchMethods = useCallback(
    async ({ force = false } = {}) => {
      if (!organizationId) return;
      if (!force && hasFetchedRef.current) return;

      setLoadingMethods(true);
      try {
        const { data } = await paymentMethods.list(organizationId);
        const normalized = normalizePaymentMethodsResponse(data);
        setMethods(normalized.methods);
        setDefaultId(normalized.defaultId);
        setMethodsError("");
        syncCache(normalized.methods, normalized.defaultId);
        hasFetchedRef.current = true;
      } catch (error) {
        setMethods([]);
        setDefaultId(null);
        setMethodsError(
          typeof error?.response?.data?.detail === "string"
            ? error.response.data.detail
            : "Saved payment methods could not be loaded. Try again.",
        );
        hasFetchedRef.current = false;
      } finally {
        setLoadingMethods(false);
      }
    },
    [organizationId, syncCache],
  );

  useEffect(() => {
    if (!organizationId) return;

    const nextCachedEntry = paymentMethodCache.get(organizationId) ?? null;
    if (nextCachedEntry) {
      setMethods(nextCachedEntry.methods ?? []);
      setDefaultId(nextCachedEntry.defaultId ?? null);
      setLoadingMethods(false);
      hasFetchedRef.current = true;
      return;
    }

    hasFetchedRef.current = false;
    setMethods([]);
    setDefaultId(null);
    setMethodsError("");
    setLoadingMethods(true);
    fetchMethods();
  }, [organizationId, fetchMethods]);

  const refreshMethods = useCallback(async () => {
    hasFetchedRef.current = false;
    await fetchMethods({ force: true });
  }, [fetchMethods]);

  const addPaymentMethodButton = (
    <button
      type="button"
      onClick={onAddPaymentMethod}
      disabled={
        !organizationId ||
        typeof onAddPaymentMethod !== "function" ||
        addingPaymentMethod
      }
      data-testid="add-payment-method"
      className="self-start rounded-md border border-[#FFD700]/30 px-3 py-1.5 text-xs font-semibold text-[#FFD700] transition hover:bg-[#FFD700]/10 disabled:cursor-not-allowed disabled:opacity-50"
    >
      {addingPaymentMethod ? (
        <span className="inline-flex items-center gap-2">
          <Loader2 size={12} className="animate-spin" />
          Opening secure setup…
        </span>
      ) : (
        "Add card securely"
      )}
    </button>
  );

  const handleSetDefault = async (methodId) => {
    if (!organizationId || !methodId) return;

    setActionId(methodId);
    try {
      await paymentMethods.setDefault(methodId, organizationId);
      toast.success("Default payment method updated.");
      await refreshMethods();
    } catch (error) {
      toast.error(
        error?.response?.data?.detail ?? "Could not update default method.",
      );
    } finally {
      setActionId(null);
    }
  };

  const handleDelete = async (methodId) => {
    if (!organizationId || !methodId) return;

    setActionId(methodId);
    try {
      await paymentMethods.delete(methodId, organizationId);
      toast.success("Payment method removed.");
      await refreshMethods();
    } catch (error) {
      toast.error(
        error?.response?.data?.detail ?? "Could not remove payment method.",
      );
    } finally {
      setActionId(null);
    }
  };

  if (loadingMethods) {
    return (
      <div className="flex flex-col items-start gap-2">
        <div className="flex items-center gap-2 py-2 text-xs text-[#737373]">
          <Loader2 size={13} className="animate-spin" /> Loading saved methods…
        </div>
        {addPaymentMethodButton}
      </div>
    );
  }

  if (methodsError) {
    return (
      <div className="flex flex-col items-start gap-2">
        <div
          className="flex items-center justify-between gap-3 text-xs text-[#FCA5A5]"
          role="alert"
        >
          <span>{methodsError}</span>
          <button
            type="button"
            onClick={refreshMethods}
            className="rounded-md border border-white/15 px-2 py-1 text-[#BFC1C2] hover:text-white"
          >
            Retry
          </button>
        </div>
        {addPaymentMethodButton}
      </div>
    );
  }

  if (methods.length === 0) {
    return (
      <div className="flex flex-col items-start gap-2">
        <div className="flex items-center gap-2 text-xs text-[#737373]">
          <Zap size={14} className="text-[#FFD700]" />
          No saved card yet. Add one securely without making a purchase.
        </div>
        {addPaymentMethodButton}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2">
      {methods.map((m) => {
        const isDefault = m.methodid === defaultId || m.isDefault;
        const busy = actionId === m.methodid;

        return (
          <div
            key={m.methodid}
            className={`flex items-center justify-between rounded-lg border px-3 py-2 text-xs transition ${
              isDefault
                ? "border-[#FFD700]/40 bg-[#FFD700]/5"
                : "border-white/10 bg-white/5"
            }`}
            data-testid={`payment-method-row-${m.methodid}`}
          >
            <div className="flex items-center gap-3">
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-md border ${
                  isDefault
                    ? "border-[#22C55E]/30 bg-[#22C55E]/10"
                    : "border-white/10 bg-white/5"
                }`}
              >
                {isDefault ? (
                  <ShieldCheck size={14} className="text-[#22C55E]" />
                ) : (
                  <CreditCard size={14} className="text-[#BFC1C2]" />
                )}
              </div>
              <div>
                <div className="font-tech text-sm text-white">
                  {m.brandDisplay || "Card"} {m.last4 ? `····${m.last4}` : ""}
                  {isDefault && (
                    <span className="ml-1.5 rounded-full border border-[#FFD700]/40 bg-[#FFD700]/10 px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-[#FFD700]">
                      default
                    </span>
                  )}
                </div>
                <div className="text-[#737373]">
                  {m.expDisplay
                    ? `Expires ${m.expDisplay}`
                    : m.expmonth && m.expyear
                      ? `Expires ${String(m.expmonth).padStart(2, "0")}/${String(m.expyear).slice(-2)}`
                      : "Expiration unavailable"}
                  {m.status && m.status !== "active" && (
                    <span className="ml-2 capitalize text-[#EF4444]">
                      {m.status}
                    </span>
                  )}
                </div>
              </div>
            </div>

            <div className="flex items-center gap-1.5">
              {!isDefault && (
                <button
                  type="button"
                  onClick={() => handleSetDefault(m.methodid)}
                  disabled={!!actionId}
                  data-testid={`set-default-${m.methodid}`}
                  title="Set as default"
                  className="flex h-7 w-7 items-center justify-center rounded-md border border-white/10 text-[#737373] transition hover:border-[#FFD700]/40 hover:text-[#FFD700] disabled:opacity-50"
                >
                  {busy ? (
                    <Loader2 size={11} className="animate-spin" />
                  ) : (
                    <Star size={11} />
                  )}
                </button>
              )}
              <button
                type="button"
                onClick={() => handleDelete(m.methodid)}
                disabled={!!actionId}
                data-testid={`delete-method-${m.methodid}`}
                title="Remove method"
                className="flex h-7 w-7 items-center justify-center rounded-md border border-white/10 text-[#737373] transition hover:border-[#EF4444]/40 hover:text-[#EF4444] disabled:opacity-50"
              >
                {busy ? (
                  <Loader2 size={11} className="animate-spin" />
                ) : (
                  <Trash2 size={11} />
                )}
              </button>
            </div>
          </div>
        );
      })}
      {addPaymentMethodButton}
    </div>
  );
};

const WalletCard = ({
  balance = 0,
  lastPayment,
  walletHistory = [],
  hasPaid,
  onPurchase,
  purchasingId,
  onAddPaymentMethod,
  addingPaymentMethod = false,
  organizationId = "",
}) => {
  const animated = useCountUp(balance, 1500, [balance]);
  const recentWalletHistory = Array.isArray(walletHistory) ? walletHistory : [];
  const stripePublishableKey = getStripePublishableKey();
  const stripeMode = getStripeMode(stripePublishableKey);
  const [tiers, setTiers] = useState([]);
  const [catalogueLoading, setCatalogueLoading] = useState(true);
  const [catalogueError, setCatalogueError] = useState(false);

  const packageIds = useMemo(
    () => new Set(tiers.map((tier) => tier.id)),
    [tiers],
  );
  useEffect(() => {
    let active = true;

    const loadCatalogue = async () => {
      try {
        const { data } = await api.get("/billing/catalogue");
        const nextTiers = normalizeBillingPackages(data);
        if (active) {
          setTiers(nextTiers);
          setCatalogueError(false);
        }
      } catch {
        if (active) {
          setCatalogueError(true);
          toast.error("Billing packages could not be loaded.");
        }
      } finally {
        if (active) {
          setCatalogueLoading(false);
        }
      }
    };

    loadCatalogue();
    return () => {
      active = false;
    };
  }, []);

  const handleCheckoutPurchase = useCallback(
    (tierId) => {
      if (!packageIds.has(tierId)) {
        toast.error("Invalid package selected.");
        return;
      }

      if (typeof onPurchase !== "function") {
        toast.error("Purchase action is unavailable.");
        return;
      }

      onPurchase(tierId);
    },
    [onPurchase, packageIds],
  );

  return (
    <div className="glass-platinum rounded-2xl p-7" data-testid="wallet-card">
      <div className="mb-6 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Wallet size={18} className="text-[#E5E4E2]" />
          <h2 className="font-tech text-sm font-semibold uppercase tracking-[0.25em] text-[#E5E4E2]">
            Unit Wallet
          </h2>
        </div>
        <span className="rounded-full border border-[#22C55E]/30 bg-[#22C55E]/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-[#22C55E]">
          Active
        </span>
      </div>

      <StripeKeyWarning stripeMode={stripeMode} />

      <div className="mb-1 text-xs uppercase tracking-widest text-[#BFC1C2]">
        Available balance
      </div>
      <div className="mb-1 flex items-end gap-2">
        <span
          className="font-tech text-5xl font-bold leading-none text-white"
          data-testid="wallet-balance"
        >
          {animated.toLocaleString()}
        </span>
        <span className="mb-1 text-sm text-[#BFC1C2]">units</span>
      </div>
      <p className="mb-6 text-xs text-[#737373]">
        Pay only for what you use. No subscription, no recurring charge.
      </p>

      {recentWalletHistory.length > 0 && (
        <section
          className="mb-6 rounded-xl border border-white/10 bg-black/30 p-4"
          data-testid="wallet-history"
          aria-label="Recent wallet activity"
        >
          <h3 className="mb-3 text-xs uppercase tracking-widest text-[#BFC1C2]">
            Recent activity
          </h3>
          <div className="flex flex-col gap-2">
            {recentWalletHistory.slice(0, 5).map((entry, index) => {
              const units = Number(entry?.units);
              const safeUnits = Number.isFinite(units) ? Math.abs(units) : 0;
              const isDebit =
                String(entry?.entry_type).toLowerCase() === "debit";
              const balanceAfter = Number(entry?.balance_after);
              return (
                <div
                  key={`${entry?.created_at ?? "wallet-entry"}-${index}`}
                  className="flex items-center justify-between gap-3 text-xs"
                >
                  <div className="min-w-0">
                    <div className="truncate text-white">
                      {entry?.label || "Wallet activity"}
                    </div>
                    <div className="text-[#737373]">
                      {entry?.created_at || ""}
                      {Number.isFinite(balanceAfter) &&
                        ` · balance ${balanceAfter.toLocaleString()}`}
                    </div>
                  </div>
                  <span
                    className={
                      isDebit
                        ? "shrink-0 text-[#BFC1C2]"
                        : "shrink-0 text-[#22C55E]"
                    }
                  >
                    {isDebit ? "−" : "+"}
                    {safeUnits.toLocaleString()} units
                  </span>
                </div>
              );
            })}
          </div>
        </section>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {catalogueLoading && (
          <div className="text-xs text-[#BFC1C2]" role="status">
            Loading protection packages…
          </div>
        )}
        {catalogueError && (
          <div className="text-xs text-[#FCA5A5]" role="alert">
            Billing packages are unavailable. Refresh the page to try again.
          </div>
        )}
        {!catalogueLoading &&
          !catalogueError &&
          tiers.map((t) => (
            <div key={t.id} className="flex flex-col">
              {t.bestDeal ? (
                <div className="mb-1.5">
                  <EnterpriseBadge />
                </div>
              ) : (
                <div className="mb-1.5 h-[22px]" />
              )}
              <button
                type="button"
                onClick={() => handleCheckoutPurchase(t.id)}
                disabled={!!purchasingId}
                data-testid={`purchase-${t.id}`}
                title={
                  stripeMode === "unconfigured"
                    ? "Stripe publishable key is missing from the frontend build, but purchase will still be attempted through the configured checkout flow."
                    : undefined
                }
                className="btn-shimmer flex flex-col items-center justify-center rounded-xl border border-[#E5E4E2]/25 bg-white/5 px-3 py-4 text-center transition hover:border-[#FFD700]/60 hover:bg-white/[0.08] disabled:opacity-60"
              >
                <span className="font-tech text-[11px] font-semibold uppercase tracking-widest text-[#BFC1C2]">
                  {t.name}
                </span>
                <span className="font-tech text-base font-bold text-white">
                  {t.units}
                </span>
                <span className="text-[11px] text-[#BFC1C2]">units</span>
                <span className="mt-1 text-[10px] text-[#737373]">
                  {t.tokensPerUnit.toLocaleString()} tokens / unit
                </span>
                <span className="mt-2 flex items-center gap-1 text-lg font-semibold text-[#FFD700]">
                  {purchasingId === t.id ? (
                    <Loader2 size={16} className="animate-spin" />
                  ) : (
                    t.price
                  )}
                </span>
              </button>
            </div>
          ))}
      </div>

      <div
        className="mt-6 rounded-xl border border-white/10 bg-black/30 p-4"
        data-testid="saved-payment-method"
      >
        <div className="mb-3 flex items-center gap-2 text-xs uppercase tracking-widest text-[#BFC1C2]">
          <CreditCard size={14} /> Payment method
          <StripeModeTag stripeMode={stripeMode} />
        </div>

        {hasPaid && lastPayment && (
          <div className="mb-3 flex items-center gap-2 rounded-lg border border-[#22C55E]/20 bg-[#22C55E]/5 px-3 py-2 text-xs">
            <ShieldCheck size={13} className="text-[#22C55E]" />
            <span className="text-[#22C55E]">
              Last purchase:{" "}
              <span className="font-semibold">{lastPayment.label}</span> · $
              {Number(lastPayment.amount).toFixed(2)}
            </span>
          </div>
        )}

        <PaymentMethodPanel
          organizationId={organizationId}
          onAddPaymentMethod={onAddPaymentMethod}
          addingPaymentMethod={addingPaymentMethod}
        />
      </div>
    </div>
  );
};

export default WalletCard;
