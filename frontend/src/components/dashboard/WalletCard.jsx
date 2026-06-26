/* global process */
import { useState, useEffect, useCallback } from "react";
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
import api from "@/lib/api";
import { toast } from "sonner";

// ---------------------------------------------------------------------------
// Stripe publishable key — read from env at module load.
// Required for any future Stripe Elements/PaymentIntent flow.
// The current flow uses Checkout redirect (no Elements needed), but the key
// is validated here so misconfiguration is caught at render time, not at
// checkout attempt.
// ---------------------------------------------------------------------------
const STRIPE_PK = process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY ?? "";

const STRIPE_MODE = STRIPE_PK.startsWith("pk_live_")
  ? "live"
  : STRIPE_PK.startsWith("pk_test_")
    ? "test"
    : null;

// ---------------------------------------------------------------------------
// Package catalogue — single source of truth for this component.
// Starter    : pkg_5000  —  5,000 units — $20   — 25,000 tokens / unit
// Team       : pkg_25000 — 25,000 units — $90   — 25,000 tokens / unit
// Enterprise : pkg_60000 — 60,000 units — $180  — 25,000 tokens / unit
//
// Each protection unit covers up to TOKENS_PER_UNIT (25,000) tokens.
// Any request exceeding the boundary consumes one additional unit per
// additional 25,000-token chunk (ceiling division).
// ---------------------------------------------------------------------------

const TOKENS_PER_UNIT = 25_000;

const TIERS = [
  {
    id: "pkg_5000",
    name: "Starter",
    units: "5,000",
    price: "$20",
    priceUsd: 20,
    tokensPerUnit: TOKENS_PER_UNIT,
  },
  {
    id: "pkg_25000",
    name: "Team",
    units: "25,000",
    price: "$90",
    priceUsd: 90,
    tokensPerUnit: TOKENS_PER_UNIT,
  },
  {
    id: "pkg_60000",
    name: "Enterprise",
    units: "60,000",
    price: "$180",
    priceUsd: 180,
    bestDeal: true,
    tokensPerUnit: TOKENS_PER_UNIT,
  },
];

// Valid package IDs — must exactly match backend PackageCatalogueEntry keys
// and Dashboard.jsx handlePurchase guard.
const VALID_PACKAGE_IDS = new Set(TIERS.map((t) => t.id));

// ---------------------------------------------------------------------------
// EnterpriseBadge — floats above the Enterprise card, never inside it.
// Gold shimmer pulse matching IronClaw brand style.
// ---------------------------------------------------------------------------
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
        50%       { box-shadow: 0 0 22px rgba(255,215,0,0.75), 0 0 6px rgba(255,215,0,0.30); }
      }
      @keyframes ic-badge-shimmer {
        0%   { background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.18) 50%, transparent 100%); background-size: 200% 100%; background-position: -100% 0; }
        60%  { background-position: 200% 0; }
        100% { background-position: 200% 0; }
      }
    `}</style>
  </div>
);

// ---------------------------------------------------------------------------
// StripeModeTag — rendered in the payment method panel header when a key
// is configured. Signals live vs. test mode to the operator at a glance.
// ---------------------------------------------------------------------------
const StripeModeTag = () => {
  if (!STRIPE_MODE) return null;
  const isLive = STRIPE_MODE === "live";
  return (
    <span
      className={`ml-2 rounded-full px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest ${
        isLive
          ? "border border-[#22C55E]/40 bg-[#22C55E]/10 text-[#22C55E]"
          : "border border-[#38BDF8]/40 bg-[#38BDF8]/10 text-[#38BDF8]"
      }`}
      title={`Stripe ${STRIPE_MODE} mode`}
    >
      Stripe {STRIPE_MODE}
    </span>
  );
};

// ---------------------------------------------------------------------------
// StripeKeyWarning — shown when no publishable key is configured so the
// operator knows payment processing is not ready.
// ---------------------------------------------------------------------------
const StripeKeyWarning = () => {
  if (STRIPE_MODE !== null) return null;
  return (
    <div className="mb-4 flex items-center gap-2 rounded-lg border border-[#EF4444]/30 bg-[#EF4444]/10 px-3 py-2 text-xs text-[#EF4444]">
      <AlertTriangle size={13} />
      <span>
        <strong>REACT_APP_STRIPE_PUBLISHABLE_KEY</strong> is not set. Payment
        processing is unavailable.
      </span>
    </div>
  );
};

// ---------------------------------------------------------------------------
// PaymentMethodPanel — fetches and displays saved payment methods for the
// organization via GET /ui/billing/payment-methods, and allows the user to
// set a default or remove a method.
// ---------------------------------------------------------------------------
const PaymentMethodPanel = ({ organizationId, onPurchase, purchasingId }) => {
  const [methods, setMethods] = useState([]);
  const [defaultId, setDefaultId] = useState(null);
  const [loadingMethods, setLoadingMethods] = useState(false);
  const [actionId, setActionId] = useState(null);

  const fetchMethods = useCallback(async () => {
    if (!organizationId) return;
    setLoadingMethods(true);
    try {
      const { data } = await api.get(
        `/ui/billing/payment-methods?organizationid=${encodeURIComponent(organizationId)}`,
      );
      if (data?.status === "ok") {
        setMethods(data.methods ?? []);
        setDefaultId(data.defaultmethodid ?? null);
      }
    } catch {
      // silently fail — payment method list is non-critical UI
    } finally {
      setLoadingMethods(false);
    }
  }, [organizationId]);

  useEffect(() => {
    fetchMethods();
  }, [fetchMethods]);

  const handleSetDefault = async (methodId) => {
    setActionId(methodId);
    try {
      await api.patch(
        `/ui/billing/payment-methods/${encodeURIComponent(methodId)}/default?organizationid=${encodeURIComponent(organizationId)}`,
      );
      toast.success("Default payment method updated.");
      await fetchMethods();
    } catch (e) {
      toast.error(e?.response?.data?.detail ?? "Could not update default method.");
    } finally {
      setActionId(null);
    }
  };

  const handleDelete = async (methodId) => {
    setActionId(methodId);
    try {
      await api.delete(
        `/ui/billing/payment-methods/${encodeURIComponent(methodId)}?organizationid=${encodeURIComponent(organizationId)}`,
      );
      toast.success("Payment method removed.");
      await fetchMethods();
    } catch (e) {
      toast.error(e?.response?.data?.detail ?? "Could not remove payment method.");
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
        const isDefault = m.methodid === defaultId;
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
                  {m.brand_display ?? m.brand} ····{m.last4}
                  {isDefault && (
                    <span className="ml-1.5 rounded-full border border-[#FFD700]/40 bg-[#FFD700]/10 px-1.5 py-0.5 text-[9px] uppercase tracking-wider text-[#FFD700]">
                      default
                    </span>
                  )}
                </div>
                <div className="text-[#737373]">
                  Expires {m.exp_display ?? `${m.expmonth}/${m.expyear}`}
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
          if (VALID_PACKAGE_IDS.has("pkg_5000")) onPurchase("pkg_5000");
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

// ---------------------------------------------------------------------------
// WalletCard
// ---------------------------------------------------------------------------

const WalletCard = ({
  balance = 0,
  lastPayment,
  hasPaid,
  onPurchase,
  purchasingId,
  organizationId = "org-001",
}) => {
  const animated = useCountUp(balance, 1500, [balance]);

  // Guard: onPurchase must only ever be called with a valid package ID.
  const handleTierPurchase = useCallback(
    (tierId) => {
      if (!VALID_PACKAGE_IDS.has(tierId)) {
        toast.error("Invalid package selected.");
        return;
      }
      if (typeof onPurchase === "function") onPurchase(tierId);
    },
    [onPurchase],
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

      <StripeKeyWarning />

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
              /* Reserve same vertical space so all three cards align */
              <div className="mb-1.5 h-[22px]" />
            )}
            <button
              type="button"
              onClick={() => handleTierPurchase(t.id)}
              disabled={!!purchasingId || STRIPE_MODE === null}
              data-testid={`purchase-${t.id}`}
              title={
                STRIPE_MODE === null
                  ? "Payment processing unavailable — Stripe key not configured"
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

      {/* ------------------------------------------------------------------ */}
      {/* Payment method panel                                                */}
      {/* ------------------------------------------------------------------ */}
      <div
        className="mt-6 rounded-xl border border-white/10 bg-black/30 p-4"
        data-testid="saved-payment-method"
      >
        <div className="mb-3 flex items-center gap-2 text-xs uppercase tracking-widest text-[#BFC1C2]">
          <CreditCard size={14} /> Payment method
          <StripeModeTag />
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
          onPurchase={handleTierPurchase}
          purchasingId={purchasingId}
        />
      </div>
    </div>
  );
};

export default WalletCard;
