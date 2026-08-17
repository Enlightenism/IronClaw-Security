/* global process */
import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import {
  Wallet,
  CreditCard,
  Loader2,
  Zap,
  ShieldCheck,
  PlusCircle,
  Trash2,
  Star,
  AlertTriangle,
} from "lucide-react";
import { useCountUp } from "@/hooks/useCountUp";
import api, { payments, paymentMethods } from "@/lib/api";
import { ensureFrontEndHasFreshSession } from "@/context/AuthContext";
import { toast } from "sonner";


const TOKENS_PER_UNIT = 25_000;


const TIERS = [
  {
    id: "pkg5000",
    name: "Starter",
    units: "5,000",
    unitCount: 5000,
    price: "$20",
    priceUsd: 20,
    tokensPerUnit: TOKENS_PER_UNIT,
  },
  {
    id: "pkg25000",
    name: "Team",
    units: "25,000",
    unitCount: 25000,
    price: "$90",
    priceUsd: 90,
    tokensPerUnit: TOKENS_PER_UNIT,
  },
  {
    id: "pkg60000",
    name: "Enterprise",
    units: "60,000",
    unitCount: 60000,
    price: "$180",
    priceUsd: 180,
    bestDeal: true,
    tokensPerUnit: TOKENS_PER_UNIT,
  },
];


const DEFAULT_ADD_CARD_PACKAGE_ID = "pkg5000";
const VALID_PACKAGE_IDS = new Set(TIERS.map((t) => t.id));
const paymentMethodCache = new Map();


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


  return {
    raw: method,
    methodid: methodId,
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


const isValidHttpUrl = (value) => {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
};


const buildCheckoutPayload = ({
  packageId,
  priceId,
  mode,
  quantity,
  unitCredits,
  organizationId,
}) => {
  const normalizedMode = (mode || "payment").toString().trim();
  if (!["payment", "subscription", "setup"].includes(normalizedMode)) {
    throw new Error("Invalid mode");
  }

  const qty = Number(quantity) || 1;
  if (!Number.isFinite(qty) || qty < 1) throw new Error("Quantity must be >= 1");

  const hasPackage = !!(packageId && String(packageId).trim());
  const hasPrice = !!(priceId && String(priceId).trim());
  if (hasPackage && hasPrice) throw new Error("Send either packageId or priceId, not both");
  if (!hasPackage && !hasPrice) throw new Error("Either packageId or priceId is required");

  const payload = {
    mode: normalizedMode,
    quantity: qty,
    successUrl: `${window.location.origin}/billing/success`,
    cancelUrl: `${window.location.origin}/billing/cancel`,
    organizationId: organizationId || "",
    metadata: {},
  };

  if (hasPackage) {
    payload.packageId = String(packageId).trim();
  } else {
    payload.priceId = String(priceId).trim();
    const uc = Number(unitCredits) || 0;
    if (!Number.isFinite(uc) || uc <= 0) throw new Error("unitCredits must be > 0 when using priceId");
    payload.unitCredits = uc;
  }

  if (!isValidHttpUrl(payload.successUrl) || !isValidHttpUrl(payload.cancelUrl)) {
    throw new Error("Invalid success or cancel URL");
  }

  if (!payload.organizationId) throw new Error("Organization ID is required");

  return payload;
};


const PaymentMethodPanel = ({
  organizationId,
  onPurchase,
  onAddCard,
  purchasingId,
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
        syncCache(normalized.methods, normalized.defaultId);
        hasFetchedRef.current = true;
      } catch {
        setMethods([]);
        setDefaultId(null);
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
    setLoadingMethods(true);
    fetchMethods();
  }, [organizationId, fetchMethods]);


  const refreshMethods = useCallback(async () => {
    hasFetchedRef.current = false;
    await fetchMethods({ force: true });
  }, [fetchMethods]);


  const handleSetDefault = async (methodId) => {
    if (!organizationId || !methodId) return;


    setActionId(methodId);
    try {
      await paymentMethods.setDefault(methodId, organizationId);
      toast.success("Default payment method updated.");
      await refreshMethods();
    } catch (e) {
      try {
        await api.post(
          `/billing/payment-methods/${encodeURIComponent(methodId)}/set-default?organizationid=${encodeURIComponent(organizationId)}`,
        );
        toast.success("Default payment method updated.");
        await refreshMethods();
      } catch (fallbackError) {
        toast.error(
          fallbackError?.response?.data?.detail ??
            e?.response?.data?.detail ??
            "Could not update default method.",
        );
      }
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
    } catch (e) {
      try {
        await api.post(
          `/billing/payment-methods/${encodeURIComponent(methodId)}/detach?organizationid=${encodeURIComponent(organizationId)}`,
        );
        toast.success("Payment method removed.");
        await refreshMethods();
      } catch (fallbackError) {
        toast.error(
          fallbackError?.response?.data?.detail ??
            e?.response?.data?.detail ??
            "Could not remove payment method.",
        );
      }
    } finally {
      setActionId(null);
    }
  };


  if (loadingMethods) {
    return (
      <div className="flex items-center gap-2 py-2 text-xs text-[#737373]">
        <Loader2 size={13} className="animate-spin" /> Loading saved methods…
      </div>
    );
  }


  if (methods.length === 0) {
    return (
      <div className="flex items-center gap-2 text-xs text-[#737373]">
        <Zap size={14} className="text-[#FFD700]" />
        No payment method on file yet. Complete a purchase to securely save one
        with Stripe.
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


      <button
        type="button"
        onClick={() => {
          if (onAddCard) {
            onAddCard();
          } else if (VALID_PACKAGE_IDS.has(DEFAULT_ADD_CARD_PACKAGE_ID)) {
            onPurchase(DEFAULT_ADD_CARD_PACKAGE_ID);
          }
        }}
        disabled={!!purchasingId}
        data-testid="add-new-card-btn"
        className="flex items-center gap-1.5 self-end rounded-lg border border-[#E5E4E2]/20 px-3 py-1.5 text-xs text-[#BFC1C2] transition hover:border-[#FFD700]/50 hover:text-white disabled:opacity-50"
      >
        <PlusCircle size={12} /> Add new card
      </button>
    </div>
  );
};


const WalletCard = ({
  balance = 0,
  lastPayment,
  hasPaid,
  onPurchase,
  purchasingId,
  organizationId = "org-001",
}) => {
  const animated = useCountUp(balance, 1500, [balance]);
  const stripePublishableKey = getStripePublishableKey();
  const stripeMode = getStripeMode(stripePublishableKey);


  const handleTierPurchase = useCallback(
    (tierId) => {
      if (!VALID_PACKAGE_IDS.has(tierId)) {
        toast.error("Invalid package selected.");
        return;
      }


      if (typeof onPurchase !== "function") {
        toast.error("Purchase action is unavailable.");
        return;
      }


      onPurchase(tierId);
    },
    [onPurchase],
  );


  const handleCheckoutPurchase = useCallback(
    async (tierId) => {
      if (!VALID_PACKAGE_IDS.has(tierId)) {
        toast.error("Invalid package selected.");
        return;
      }


      if (typeof onPurchase !== "function") {
        toast.error("Purchase action is unavailable.");
        return;
      }


      const tier = TIERS.find((t) => t.id === tierId);
      if (!tier) {
        toast.error("Package not found.");
        return;
      }


      try {
        await ensureFrontEndHasFreshSession();
      } catch {
        // Continue even if refresh fails; backend will surface token errors
      }


      try {
        const payload = buildCheckoutPayload({
          packageId: tierId,
          mode: "payment",
          quantity: 1,
          organizationId: organizationId || "org-001",
        });

        const { data } = await payments.createCheckout(payload);
        const redirectUrl = data?.checkout_url || data?.url;
        if (!redirectUrl) {
          throw new Error("Missing checkout URL.");
        }
        onPurchase(tierId);
        if (typeof window.location.assign === "function") {
          window.location.assign(redirectUrl);
        } else {
          window.location.href = redirectUrl;
        }
      } catch (error) {
        const backendDetail =
          error?.response?.data?.detail?.error ||
          error?.response?.data?.detail ||
          error?.response?.data ||
          error?.message ||
          "Checkout failed. Please try again.";


        toast.error(
          typeof backendDetail === "string"
            ? backendDetail
            : "Checkout failed. Please try again.",
        );
      }
    },
    [onPurchase, organizationId],
  );


  const handleAddCardClick = useCallback(() => {
    if (VALID_PACKAGE_IDS.has(DEFAULT_ADD_CARD_PACKAGE_ID)) {
      onPurchase(DEFAULT_ADD_CARD_PACKAGE_ID);
    }
  }, [onPurchase]);


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


      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        {TIERS.map((t) => (
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
              onClick={() => handleTierPurchase(t.id)}
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
          onPurchase={handleCheckoutPurchase}
          onAddCard={handleAddCardClick}
          purchasingId={purchasingId}
        />
      </div>
    </div>
  );
};


export default WalletCard;
