import { useEffect, useRef, useState } from "react";
import { Check } from "lucide-react";
import "./PackageCarousel.css";

const HOLD_MS = 5000;
const DISSOLVE_MS = 1000;
const APPEAR_CLASSES = [
  "package-appear-shimmer",
  "package-appear-spin",
  "package-appear-sparkle",
];

const PACKAGE_BENEFITS = [
  "No subscription",
  "No recurring charge",
  "Idle months cost nothing",
  "Scale instantly",
  "Full spend control",
  "Transparent per-unit pricing",
];

const PACKAGE_TIERS = [
  {
    key: "starter",
    label: "Starter Package",
    price: "$20",
    units: "5,000 units",
    summary:
      "5,000 units = 5,000 agent calls protected up to 25,000 tokens each, against multiple layers of unsafe behavior. That is up to 125,000,000 tokens protected by IronClaw-Security python defense. No subscription. No recurring charge. Idle time cost nothing per month. Scale instantly.",
    testId: "credits-section",
    summaryTestId: "agents-protected-line",
  },
  {
    key: "team",
    label: "Team Package",
    price: "$90",
    units: "25,000 units",
    summary:
      "25,000 units = 25,000 agent calls protected up to 25,000 tokens each, against multiple layers of unsafe behavior. That is up to 625,000,000 tokens protected by IronClaw-Security python defense. No subscription. No recurring charge. Idle time cost nothing per month. Scale instantly.",
    testId: "team-package-section",
    summaryTestId: "team-agents-protected-line",
  },
  {
    key: "enterprise",
    label: "Enterprise Package",
    price: "$180",
    units: "60,000 units",
    summary:
      "60,000 units = 60,000 agent calls protected up to 25,000 tokens each, against multiple layers of unsafe behavior. That is up to 1,500,000,000 tokens protected by IronClaw-Security python defense. No subscription. No recurring charge. Idle time cost nothing per month. Scale instantly.",
    testId: "enterprise-package-section",
    summaryTestId: "enterprise-agents-protected-line",
    badge: true,
  },
];

function PackageCard({ tier }) {
  return (
    <div
      className="glass-platinum overflow-hidden rounded-3xl p-10 text-center sm:p-14"
      data-testid={tier.testId}
    >
      <div className="mb-3 inline-block rounded-full border border-[#E5E4E2]/30 bg-white/5 px-4 py-1 font-tech text-xs uppercase tracking-[0.3em] text-[#E5E4E2]">
        {tier.label}
      </div>
      <h2 className="text-3xl font-bold tracking-tight sm:text-5xl">
        <span className="text-gold-gradient">{tier.price}</span>{" "}
        <span className="text-[#BFC1C2]">=</span>{" "}
        <span className="text-platinum-gradient">{tier.units}</span>
      </h2>
      <p className="mt-3 text-lg text-[#BFC1C2]">Pay only for what you use.</p>
      <p
        className="mt-2 font-tech text-sm text-[#FFD700]"
        data-testid={tier.summaryTestId}
      >
        {tier.summary}
      </p>

      <div className="mx-auto mt-8 grid max-w-2xl grid-cols-1 gap-3 text-left sm:grid-cols-2">
        {PACKAGE_BENEFITS.map((b) => (
          <div
            key={b}
            className="flex items-center gap-2 text-sm text-white/90"
          >
            <Check size={16} className="text-[#FFD700]" /> {b}
          </div>
        ))}
      </div>
    </div>
  );
}

export default function PackageCarousel() {
  const [active, setActive] = useState(0);
  const [dissolving, setDissolving] = useState(false);
  const [started, setStarted] = useState(false);
  const sectionRef = useRef(null);

  useEffect(() => {
    const node = sectionRef.current;
    if (started || !node) {
      return undefined;
    }
    if (typeof IntersectionObserver === "undefined") {
      setStarted(true);
      return undefined;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setStarted(true);
          observer.disconnect();
        }
      },
      { threshold: 0.35 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [started]);

  useEffect(() => {
    if (!started) {
      return undefined;
    }
    const timer = window.setTimeout(
      () => {
        if (dissolving) {
          setActive((index) => (index + 1) % PACKAGE_TIERS.length);
          setDissolving(false);
        } else {
          setDissolving(true);
        }
      },
      dissolving ? DISSOLVE_MS : HOLD_MS,
    );
    return () => window.clearTimeout(timer);
  }, [started, active, dissolving]);

  return (
    <section
      ref={sectionRef}
      className="relative z-10 mx-auto max-w-4xl px-6 py-20"
      aria-label="IronClaw-Security package pricing"
      data-testid="package-carousel"
    >
      <div className="package-stage">
        {PACKAGE_TIERS.map((tier, index) => {
          const isActive = started && index === active;
          let motionClass = "";
          if (isActive) {
            motionClass = dissolving ? "is-dissolving" : APPEAR_CLASSES[index];
          }
          return (
            <div
              key={tier.key}
              className={`package-stage-item ${motionClass}`.trim()}
              aria-hidden={!isActive || undefined}
            >
              {tier.badge && (
                <div className="mb-6 flex justify-center">
                  <span
                    className="btn-shimmer inline-flex items-center rounded-full bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-6 py-2 font-tech text-xs font-bold uppercase tracking-[0.3em] text-black shadow-[0_0_24px_rgba(255,215,0,0.35)]"
                    data-testid="best-deal-badge"
                  >
                    BEST DEAL
                  </span>
                </div>
              )}
              <PackageCard tier={tier} />
            </div>
          );
        })}
      </div>
    </section>
  );
}
