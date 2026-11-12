/* global process */
import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Wallet,
  Loader2,
  AlertTriangle,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useCountUp } from "@/hooks/useCountUp";
import api from "@/lib/api";
import { toast } from "sonner";

const normalizeBillingPackages = (data) => {
  const packages = data?.packages;
  if (!packages || typeof packages !== "object" || Array.isArray(packages)) {
    throw new Error("Billing catalogue did not include a package map.");
  }

  const tiers = Object.values(packages)
    .map((packageInfo) => {
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
    })
    .sort((a, b) => a.priceUsd - b.priceUsd);

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

const WalletCard = ({
  balance = 0,
  walletStatus = "unavailable",
  onPurchase,
  purchasingId,
}) => {
  const animated = useCountUp(balance, 1500, [balance]);
  const stripePublishableKey = getStripePublishableKey();
  const stripeMode = getStripeMode(stripePublishableKey);
  const [tiers, setTiers] = useState([]);
  const [catalogueLoading, setCatalogueLoading] = useState(true);
  const [catalogueError, setCatalogueError] = useState(false);
  const [packageState, setPackageState] = useState({ index: 0, step: 1 });

  const packageIds = useMemo(
    () => new Set(tiers.map((tier) => tier.id)),
    [tiers],
  );
  const turnPackage = useCallback(
    (step) => {
      setPackageState((current) => {
        const lastIndex = Math.max(tiers.length - 1, 0);
        const from = Math.min(current.index, lastIndex);
        return {
          index: Math.min(Math.max(from + step, 0), lastIndex),
          step,
        };
      });
    },
    [tiers.length],
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

  const normalizedWalletStatus = [
    "active",
    "empty",
    "not_created",
    "unavailable",
  ].includes(walletStatus)
    ? walletStatus
    : "unavailable";
  const walletHealth = {
    active: {
      label: "Funded",
      classes: "border-[#22C55E]/30 bg-[#22C55E]/10 text-[#22C55E]",
    },
    empty: {
      label: "No funds",
      classes: "border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#F59E0B]",
    },
    not_created: {
      label: "Not funded",
      classes: "border-white/15 bg-white/5 text-[#BFC1C2]",
    },
    unavailable: {
      label: "Status unavailable",
      classes: "border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#F59E0B]",
    },
  }[normalizedWalletStatus] || {
    label: "Status unavailable",
    classes: "border-[#F59E0B]/30 bg-[#F59E0B]/10 text-[#F59E0B]",
  };

  const lastPackageIndex = Math.max(tiers.length - 1, 0);
  const activePackageIndex = Math.min(packageState.index, lastPackageIndex);
  const tabStep =
    activePackageIndex === 0
      ? 1
      : activePackageIndex === lastPackageIndex
        ? -1
        : packageState.step;

  return (
    <div data-testid="wallet-card" className="wallet-body">
      <section
        className="wallet-leather rounded-2xl p-7"
        aria-label="Wallet balance"
        data-testid="wallet-front"
      >
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Wallet size={18} className="text-[#FFD700]" />
            <h2 className="font-tech text-sm font-semibold uppercase tracking-[0.25em] text-gold-gradient">
              Unit Wallet
            </h2>
          </div>
          <span
            className={`rounded-full border px-3 py-1 text-[10px] font-semibold uppercase tracking-wider ${walletHealth.classes}`}
            data-testid="wallet-health"
            data-wallet-status={normalizedWalletStatus}
          >
            {walletHealth.label}
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
        <p className="text-xs text-[#737373]">
          Pay only for what you use. No subscription, no recurring charge. For
          security reasons we do not save card information.
        </p>
      </section>

      <div className="wallet-seam" aria-hidden="true" />

      <div className="mt-6">
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
        {!catalogueLoading && !catalogueError && tiers.length > 0 && (
          <div
            data-testid="wallet-deck"
            role="group"
            aria-label="Protection packages"
            className="wallet-deck mx-auto grid w-full max-w-md"
          >
            {tiers.map((t, index) => {
              const depth = Math.abs(index - activePackageIndex);
              let deckState = "passed";
              if (index === activePackageIndex) {
                deckState = "top";
              } else if (index > activePackageIndex) {
                deckState = "stacked";
              }
              const isTop = deckState === "top";
              return (
                <div
                  key={t.id}
                  data-testid={`deck-page-${t.id}`}
                  data-deck-state={deckState}
                  aria-hidden={!isTop}
                  inert={isTop ? undefined : ""}
                  style={{
                    zIndex:
                      deckState === "passed"
                        ? 50 + index
                        : deckState === "top"
                          ? 40
                          : 30 - depth,
                    "--deck-depth": depth,
                  }}
                  className="wallet-deck-page flex flex-col p-3"
                >
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
                    <span className="metal-gold-text font-tech text-sm uppercase">
                      {t.name} Package
                    </span>
                    <span className="font-tech text-base font-bold text-white">
                      {t.units}
                    </span>
                    <span className="text-[11px] text-white">units</span>
                    <span
                      data-testid={`package-detail-${t.id}`}
                      className="mt-1 max-w-[16rem] text-center text-[11px] leading-snug text-white"
                    >
                      {`${t.unitCount.toLocaleString("en-US")} units = ${t.tokensPerUnit.toLocaleString("en-US")} tokens per unit = ${t.tokenCoverage.toLocaleString("en-US")} tokens protected by IronClaw-Security.`}
                    </span>
                    <span className="mt-2 flex items-center gap-1 text-lg font-semibold text-[#FFD700]">
                      {purchasingId === t.id ? (
                        <Loader2 size={16} className="animate-spin" />
                      ) : (
                        t.price
                      )}
                    </span>
                  </button>
                  {isTop && (
                    <button
                      type="button"
                      onClick={() => turnPackage(tabStep)}
                      data-testid="wallet-deck-tab"
                      className="wallet-deck-tab"
                    >
                      {tabStep > 0 ? (
                        <ChevronRight size={14} aria-hidden="true" />
                      ) : (
                        <ChevronLeft size={14} aria-hidden="true" />
                      )}
                      {tabStep > 0 ? "Next Package" : "Previous Package"}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

export default WalletCard;
