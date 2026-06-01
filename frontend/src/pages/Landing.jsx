import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  Syringe,
  Terminal,
  FileLock2,
  Boxes,
  Layers,
  ScrollText,
  ArrowRight,
  Check,
} from "lucide-react";
import ParticleField from "@/components/ParticleField";
import AuthModal from "@/components/AuthModal";
import { useAuth } from "@/context/AuthContext";
import { useCountUp } from "@/hooks/useCountUp";

const FEATURES = [
  {
    icon: Syringe,
    title: "Prompt Injection Defense",
    body: "Pattern heuristics + LLM brain semantic reasoning detect adversarial instructions hidden inside agent-returned content before they reach your workflow.",
  },
  {
    icon: Terminal,
    title: "Unsafe Tool Execution Guard",
    body: "Every tool call is evaluated against policy before execution. No agent-initiated shell command, file write, or API call runs without enforcement.",
  },
  {
    icon: FileLock2,
    title: "Data Exfiltration Prevention",
    body: "Sensitive data encoded into agent responses is intercepted and blocked before it can be routed out through tool calls or returned content.",
  },
  {
    icon: Boxes,
    title: "Sandbox Isolation",
    body: "Every artifact is evaluated inside a controlled runtime boundary. Nothing is released directly without system-built analysis.",
  },
  {
    icon: Layers,
    title: "Five-Layer Verdict Engine",
    body: "Every agent output traverses Ingress → Normalizer → Heuristics → AI Brain → Policy Enforcer. No bypass path. No silent pass-through.",
  },
  {
    icon: ScrollText,
    title: "Full Audit Trail",
    body: "Every verdict logged with risk score 0–100, reasoning, and timestamp. Allow / Warn / Quarantine / Block. Exportable for compliance.",
  },
];

const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  show: (i = 0) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, delay: i * 0.08, ease: [0.22, 1, 0.36, 1] },
  }),
};

const ThreatCounter = () => {
  const base = 8472193;
  const target = useCountUp(base, 2600);
  const [extra, setExtra] = useState(0);
  useEffect(() => {
    const t = setInterval(() => setExtra((e) => e + Math.floor(Math.random() * 7) + 1), 1800);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="font-tech text-[#38BDF8]" data-testid="threat-counter">
      {(target + extra).toLocaleString()}
    </span>
  );
};

const Landing = () => {
  const [authOpen, setAuthOpen] = useState(false);
  const [authMode, setAuthMode] = useState("signin");
  const { user } = useAuth();
  const navigate = useNavigate();

  const openAuth = (mode) => {
    if (user) {
      navigate("/dashboard");
      return;
    }
    setAuthMode(mode);
    setAuthOpen(true);
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#050607] text-white">
      {/* nav */}
      <nav className="relative z-20 mx-auto flex max-w-7xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2.5" data-testid="brand-logo">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/10">
            <ShieldCheck className="text-[#FFD700]" size={20} />
          </div>
          <span className="font-tech text-lg font-bold tracking-tight">
            IRON<span className="text-gold-gradient">CLAW</span>
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => openAuth("signin")}
            data-testid="nav-signin-btn"
            className="rounded-lg border border-white/15 px-5 py-2 text-sm font-medium text-white/90 transition hover:border-white/40 hover:text-white"
          >
            Sign In
          </button>
          <button
            onClick={() => openAuth("signup")}
            data-testid="nav-signup-btn"
            className="btn-shimmer rounded-lg bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-5 py-2 text-sm font-semibold text-black transition hover:shadow-[0_0_22px_rgba(255,215,0,0.4)]"
          >
            Sign Up
          </button>
        </div>
      </nav>

      {/* hero */}
      <section className="relative overflow-hidden">
        <ParticleField />
        <div className="pointer-events-none absolute left-1/4 top-20 h-72 w-72 rounded-full bg-[#38BDF8] opacity-20 blur-[120px] animate-float-glow" />
        <div className="pointer-events-none absolute right-1/4 top-40 h-72 w-72 rounded-full bg-[#C9A84C] opacity-20 blur-[120px] animate-float-glow" style={{ animationDelay: "2s" }} />

        <div className="relative z-10 mx-auto max-w-5xl px-6 pb-28 pt-20 text-center">
          <motion.div
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="mx-auto mb-6 inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-xs text-[#BFC1C2]"
          >
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#22C55E]" />
            Enforcement layer for production AI systems
          </motion.div>

          <motion.h1
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={1}
            className="mx-auto max-w-4xl text-4xl font-bold leading-[1.05] tracking-tight sm:text-5xl lg:text-6xl"
          >
            Complete Cyber Security{" "}
            <span className="text-gold-gradient">Frontline Defense</span> For AI
            Agent Platforms.
          </motion.h1>

          <motion.p
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={2}
            className="mx-auto mt-6 max-w-2xl text-base text-[#BFC1C2] sm:text-lg"
          >
            IronClaw-Security sits in front of every agent action, every tool
            call, every inbound return. Every threat intercepted. Every verdict
            auditable.
          </motion.p>

          <motion.div
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={3}
            className="mt-8 inline-flex flex-col items-center gap-1"
          >
            <div className="text-xs uppercase tracking-[0.3em] text-[#737373]">
              Threats blocked
            </div>
            <div className="font-tech text-4xl font-bold drop-shadow-[0_0_18px_rgba(56,189,248,0.5)]">
              <ThreatCounter />
            </div>
          </motion.div>

          <motion.div
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={4}
            className="mt-10 flex items-center justify-center gap-4"
          >
            <button
              onClick={() => openAuth("signin")}
              data-testid="hero-signin-btn"
              className="btn-shimmer rounded-xl border border-white/20 bg-white/5 px-8 py-3.5 font-semibold text-white transition hover:border-[#E5E4E2]/60"
            >
              Sign In
            </button>
            <button
              onClick={() => openAuth("signup")}
              data-testid="hero-signup-btn"
              className="btn-shimmer flex items-center gap-2 rounded-xl bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-8 py-3.5 font-semibold text-black transition hover:shadow-[0_0_28px_rgba(255,215,0,0.45)]"
            >
              Sign Up <ArrowRight size={18} />
            </button>
          </motion.div>
        </div>
      </section>

      {/* features */}
      <section className="relative z-10 mx-auto max-w-7xl px-6 py-20">
        <motion.div
          variants={fadeUp}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true, margin: "-80px" }}
          className="mb-14 text-center"
        >
          <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
            Six layers of <span className="text-platinum-gradient">relentless</span> enforcement
          </h2>
          <p className="mx-auto mt-3 max-w-2xl text-[#BFC1C2]">
            No agent output reaches your workflow without passing every gate.
          </p>
        </motion.div>

        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3">
          {FEATURES.map((f, i) => {
            const Icon = f.icon;
            return (
              <motion.div
                key={f.title}
                variants={fadeUp}
                custom={i}
                initial="hidden"
                whileInView="show"
                viewport={{ once: true, margin: "-60px" }}
                className="sweep card-hover-gold glass relative overflow-hidden rounded-2xl p-7"
                data-testid={`feature-card-${i}`}
              >
                <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-xl border border-[#FFD700]/25 bg-[#C9A84C]/10">
                  <Icon className="text-[#FFD700]" size={22} />
                </div>
                <h3 className="mb-2 text-lg font-semibold tracking-tight text-white">
                  {f.title}
                </h3>
                <p className="text-sm leading-relaxed text-[#BFC1C2]">{f.body}</p>
              </motion.div>
            );
          })}
        </div>
      </section>

      {/* credits */}
      <section className="relative z-10 mx-auto max-w-4xl px-6 py-20">
        <motion.div
          variants={fadeUp}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true }}
          className="glass-platinum overflow-hidden rounded-3xl p-10 text-center sm:p-14"
          data-testid="credits-section"
        >
          <div className="mb-3 inline-block rounded-full border border-[#E5E4E2]/30 bg-white/5 px-4 py-1 font-tech text-xs uppercase tracking-[0.3em] text-[#E5E4E2]">
            Starter Package
          </div>
          <h2 className="text-3xl font-bold tracking-tight sm:text-5xl">
            <span className="text-gold-gradient">$20</span>{" "}
            <span className="text-[#BFC1C2]">=</span>{" "}
            <span className="text-platinum-gradient">20,000 units</span>
          </h2>
          <p className="mt-3 text-lg text-[#BFC1C2]">Pay only for what you use.</p>

          <div className="mx-auto mt-8 grid max-w-2xl grid-cols-1 gap-3 text-left sm:grid-cols-2">
            {[
              "No subscription",
              "No recurring charge",
              "Idle months cost nothing",
              "Scale instantly",
              "Full spend control",
              "Transparent per-unit pricing",
            ].map((b) => (
              <div key={b} className="flex items-center gap-2 text-sm text-white/90">
                <Check size={16} className="text-[#FFD700]" /> {b}
              </div>
            ))}
          </div>
        </motion.div>
      </section>

      {/* footer cta */}
      <section className="relative z-10 mx-auto max-w-4xl px-6 pb-28 pt-10 text-center">
        <motion.div
          variants={fadeUp}
          initial="hidden"
          whileInView="show"
          viewport={{ once: true }}
        >
          <h2 className="mx-auto max-w-2xl text-3xl font-bold tracking-tight sm:text-4xl">
            Start protecting your system against unsafe agents today.
          </h2>
          <button
            onClick={() => openAuth("signup")}
            data-testid="footer-getstarted-btn"
            className="btn-shimmer mt-8 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-10 py-4 text-lg font-semibold text-black transition hover:shadow-[0_0_32px_rgba(255,215,0,0.5)]"
          >
            Get Started <ArrowRight size={20} />
          </button>
        </motion.div>
      </section>

      <footer className="relative z-10 border-t border-white/10 py-8 text-center text-xs text-[#737373]">
        <span className="font-tech">IRONCLAW-SECURITY</span> &middot; The enforcement layer serious engineers trust.
      </footer>

      <AuthModal open={authOpen} onClose={() => setAuthOpen(false)} initialMode={authMode} />
    </div>
  );
};

export default Landing;
