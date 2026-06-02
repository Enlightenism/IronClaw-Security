import { Wallet, CreditCard, Loader2, Zap, ShieldCheck } from "lucide-react";
import { useCountUp } from "@/hooks/useCountUp";

const TIERS = [
  { id: "tier_20k", units: "20,000", price: "$20" },
  { id: "tier_100k", units: "100,000", price: "$90", popular: true },
  { id: "tier_200k", units: "200,000", price: "$150" },
];

const WalletCard = ({
  balance = 0,
  lastPayment,
  hasPaid,
  onPurchase,
  purchasingId,
}) => {
  const animated = useCountUp(balance, 1500, [balance]);

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
          <button
            key={t.id}
            onClick={() => onPurchase(t.id)}
            disabled={!!purchasingId}
            data-testid={`purchase-${t.id}`}
            className="btn-shimmer relative flex flex-col items-center justify-center rounded-xl border border-[#E5E4E2]/25 bg-white/5 px-3 py-4 text-center transition hover:border-[#FFD700]/60 hover:bg-white/[0.08] disabled:opacity-60"
          >
            {t.popular && (
              <span className="absolute -top-2 rounded-full bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-2 py-0.5 text-[9px] font-bold uppercase tracking-wide text-black">
                Best value
              </span>
            )}
            <span className="font-tech text-base font-bold text-white">
              {t.units}
            </span>
            <span className="text-[11px] text-[#BFC1C2]">units</span>
            <span className="mt-2 flex items-center gap-1 text-lg font-semibold text-[#FFD700]">
              {purchasingId === t.id ? (
                <Loader2 size={16} className="animate-spin" />
              ) : (
                t.price
              )}
            </span>
          </button>
        ))}
      </div>

      <div
        className="mt-6 rounded-xl border border-white/10 bg-black/30 p-4"
        data-testid="saved-payment-method"
      >
        <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-widest text-[#BFC1C2]">
          <CreditCard size={14} /> Payment method
        </div>
        {hasPaid && lastPayment ? (
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-md border border-[#22C55E]/30 bg-[#22C55E]/10">
                <ShieldCheck size={16} className="text-[#22C55E]" />
              </div>
              <div>
                <div className="font-tech text-sm text-white">
                  Securely saved with Stripe
                </div>
                <div className="text-xs text-[#737373]">
                  Last purchase: {lastPayment.label} &middot; $
                  {Number(lastPayment.amount).toFixed(2)}
                </div>
              </div>
            </div>
            <button
              onClick={() => onPurchase("tier_20k")}
              data-testid="update-card-btn"
              className="rounded-lg border border-[#E5E4E2]/25 px-3 py-1.5 text-xs text-[#E5E4E2] transition hover:border-[#FFD700]/50 hover:text-white"
            >
              Update card
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs text-[#737373]">
            <Zap size={14} className="text-[#FFD700]" />
            No payment method on file yet. Complete a purchase to securely save
            one with Stripe.
          </div>
        )}
      </div>
    </div>
  );
};

export default WalletCard;
