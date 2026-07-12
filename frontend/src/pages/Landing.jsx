import { useState, useEffect, useRef, lazy, Suspense } from "react";
import { motion } from "framer-motion";
import { useNavigate, Link } from "react-router-dom";
import {
  ShieldCheck,
  Syringe,
  ShieldAlert,
  ScrollText,
  Workflow,
  Boxes,
  Activity,
  Network,
  FileSearch,
  KeyRound,
  Lock,
  UserCheck,
  FileClock,
  Fingerprint,
  BrainCircuit,
  ArrowRight,
  Check,
} from "lucide-react";
import AuthModal from "@/components/AuthModal";
import { useAuth } from "@/context/AuthContext";
import { useCountUp } from "@/hooks/useCountUp";

const ParticleField = lazy(() => import("@/components/ParticleField"));

const LAYERS = [
  {
    icon: Syringe,
    title: "Prompt Injection",
    body: "Scans every inbound prompt for injection patterns, jailbreak attempts, and adversarial content before a single LLM call is ever made. The first gate nothing bypasses.",
  },
  {
    icon: ShieldAlert,
    title: "Action Guard",
    body: "A pre-execution gate that evaluates every proposed agent action against risk rules, returning allow / warn / block verdicts before the action is ever allowed to run.",
  },
  {
    icon: ScrollText,
    title: "Action Policy Enforcement",
    body: "Applies named policy rules — allow-lists, deny-lists, and hard capability constraints — to every tool call and agent decision at the policy layer. No exceptions.",
  },
  {
    icon: Workflow,
    title: "Action Decision",
    body: "Synthesizes the guard verdict and policy verdict into a single final executable decision, complete with a full reasoning trace captured for audit.",
  },
  {
    icon: Boxes,
    title: "Sandboxed Execution",
    body: "Executes risky tool calls and code payloads inside an isolated runtime boundary. The detonation service stress-tests payloads in a contained environment before anything reaches production.",
  },
  {
    icon: Activity,
    title: "Heuristics & Behavioral Baseline",
    body: "Detects anomalous agent behavior by comparing live activity against learned baselines, flagging statistical deviations as threats in real time — before they escalate.",
  },
  {
    icon: Network,
    title: "Attack Correlation",
    body: "Cross-correlates signals from every layer and across sessions to expose coordinated multi-step attacks, chained injections, and lateral movement patterns.",
  },
  {
    icon: FileSearch,
    title: "File Inspection + Malware",
    body: "Inspects all file inputs and outputs for malicious payloads, embedded scripts, and malware signatures before they are ever processed or returned to your system.",
  },
  {
    icon: KeyRound,
    title: "Secrets Detection & Redaction",
    body: "Detects credentials, API keys, and sensitive tokens across prompts, responses, and tool outputs — redacting them before leakage and vaulting them securely.",
  },
  {
    icon: Lock,
    title: "Quarantine",
    body: "Holds flagged actions, payloads, and sessions in an isolated store pending human review. Nothing quarantined proceeds downstream automatically. Ever.",
  },
  {
    icon: UserCheck,
    title: "Review Queue & Human-in-the-Loop",
    body: "Routes high-risk or ambiguous verdicts to a human operator review queue — with full context and audit trail — before any final release decision is made.",
  },
  {
    icon: FileClock,
    title: "Audit Log + Incident Store",
    body: "An immutable, timestamped audit trail of every verdict, action, and policy decision. Incidents are persisted for post-hoc investigation and compliance.",
  },
  {
    icon: Fingerprint,
    title: "Access Control, Auth & Org Isolation",
    body: "Enforces API-level authentication, role-based permissions, and hard tenant isolation — so no org can read, influence, or pollute another org's security context.",
  },
  {
    icon: BrainCircuit,
    title: "AI Brain",
    body: "An AI brain analyzes every agent return isolated inside the sandbox, working in lockstep with the security system to ensure NOTHING reaches your computer or phone.",
  },
];

const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  show: (i = 0) => ({
    opacity: 1,
    y: 0,
    transition: { duration: 0.6, delay: i * 0.05, ease: [0.22, 1, 0.36, 1] },
  }),
};

const LiveCounter = ({
  base,
  minMs = 15000,
  maxMs = 20000,
  step,
  color,
  testid,
  storageKey,
}) => {
  let stored;
  try {
    stored = parseInt(localStorage.getItem(storageKey) || "", 10);
  } catch {
    stored = NaN;
  }

  const initial = Number.isFinite(stored) && stored >= base ? stored : base;

  const [value, setValue] = useState(initial);
  const [live, setLive] = useState(false);
  const prevRef = useRef(initial);

  const mountAnimated = useCountUp(initial, 2000, [], initial);
  const liveAnimated = useCountUp(value, 600, [value], prevRef.current);

  useEffect(() => {
    const t = setTimeout(() => setLive(true), 2100);
    return () => clearTimeout(t);
  }, []);

  useEffect(() => {
    if (!live) return;
    let timer;
    const tick = () => {
      const delay = minMs + Math.random() * (maxMs - minMs);
      timer = setTimeout(() => {
        setValue((v) => {
          const next = v + (typeof step === "function" ? step() : step);
          prevRef.current = v;
          try {
            localStorage.setItem(storageKey, String(next));
          } catch {
            // ignore storage errors
          }
          return next;
        });
        tick();
      }, delay);
    };
    tick();
    return () => clearTimeout(timer);
  }, [live, minMs, maxMs, step, storageKey]);

  const shown = live ? liveAnimated : mountAnimated;

  return (
    <span className="font-tech" style={{ color }} data-testid={testid}>
      {shown.toLocaleString()}
    </span>
  );
};

const Landing = () => {
  const [authOpen, setAuthOpen] = useState(false);
  const [authMode, setAuthMode] = useState("signin");
  const [showParticleField, setShowParticleField] = useState(false);
  const [showBelowFold, setShowBelowFold] = useState(false);
  const { user } = useAuth();
  const navigate = useNavigate();

  useEffect(() => {
    const enableHeroEffects = () => setShowParticleField(true);

    if (typeof window !== "undefined" && "requestIdleCallback" in window) {
      const idleId = window.requestIdleCallback(enableHeroEffects, {
        timeout: 1200,
      });
      return () => window.cancelIdleCallback?.(idleId);
    }

    const timeoutId = setTimeout(enableHeroEffects, 300);
    return () => clearTimeout(timeoutId);
  }, []);

  useEffect(() => {
    const onFirstScroll = () => {
      setShowBelowFold(true);
      window.removeEventListener("scroll", onFirstScroll);
    };

    window.addEventListener("scroll", onFirstScroll, { passive: true });
    return () => window.removeEventListener("scroll", onFirstScroll);
  }, []);

  const openAuth = (mode) => {
    if (!showBelowFold) setShowBelowFold(true);

    if (user) {
      navigate("/dashboard");
      return;
    }

    setAuthMode(mode);
    setAuthOpen(true);
  };

  const onCardMove = (e) => {
    const r = e.currentTarget.getBoundingClientRect();
    e.currentTarget.style.setProperty("--mx", `${e.clientX - r.left}px`);
    e.currentTarget.style.setProperty("--my", `${e.clientY - r.top}px`);
  };

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#050607] text-white">
      <nav className="relative z-20 mx-auto flex max-w-7xl items-center justify-between px-6 py-6">
        <div className="flex items-center gap-2.5" data-testid="brand-logo">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/10">
            <ShieldCheck className="text-[#FFD700]" size={20} />
          </div>
          <span className="font-tech text-base font-bold tracking-tight sm:text-lg">
            IRONCLAW<span className="metal-gold-text">-SECURITY</span>
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

      <section className="relative overflow-hidden">
        <Suspense fallback={null}>
          {showParticleField ? <ParticleField /> : null}
        </Suspense>
        <div className="pointer-events-none absolute left-1/4 top-20 h-72 w-72 rounded-full bg-[#38BDF8] opacity-20 blur-[120px] animate-float-glow" />
        <div
          className="pointer-events-none absolute right-1/4 top-40 h-72 w-72 rounded-full bg-[#C9A84C] opacity-20 blur-[120px] animate-float-glow"
          style={{ animationDelay: "2s" }}
        />

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
            className="mt-9 flex flex-wrap items-center justify-center gap-x-14 gap-y-6"
          >
            <div className="flex flex-col items-center gap-1">
              <div className="text-xs uppercase tracking-[0.3em] text-[#737373]">
                Threats blocked
              </div>
              <div className="text-4xl font-bold drop-shadow-[0_0_18px_rgba(56,189,248,0.5)]">
                <LiveCounter
                  base={12000}
                  minMs={15000}
                  maxMs={20000}
                  step={() => Math.floor(Math.random() * 7) + 1}
                  color="#38BDF8"
                  testid="threat-counter"
                  storageKey="ic_threats_blocked"
                />
              </div>
            </div>
            <div className="hidden h-12 w-px bg-white/10 sm:block" />
            <div className="flex flex-col items-center gap-1">
              <div className="text-xs uppercase tracking-[0.3em] text-[#737373]">
                Engineers protected
              </div>
              <div className="text-4xl font-bold drop-shadow-[0_0_18px_rgba(255,215,0,0.45)]">
                <LiveCounter
                  base={1000}
                  minMs={15000}
                  maxMs={20000}
                  step={1}
                  color="#FFD700"
                  testid="user-counter"
                  storageKey="ic_engineers_protected"
                />
              </div>
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

      {showBelowFold ? (
        <>
          <section className="relative z-10 mx-auto max-w-7xl px-6 py-20">
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true, margin: "-80px" }}
              className="mb-14 text-center"
            >
              <div className="mb-3 inline-block rounded-full border border-[#FFD700]/25 bg-[#C9A84C]/10 px-4 py-1 font-tech text-xs uppercase tracking-[0.3em] text-[#FFD700]">
                14 enforcement layers
              </div>
              <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
                Fourteen layers of{" "}
                <span className="metal-gold-text">relentless</span> enforcement
              </h2>
              <p className="mx-auto mt-3 max-w-2xl text-[#BFC1C2]">
                No agent output reaches your workflow without passing every
                gate. No bypass path. No silent pass-through.
              </p>
            </motion.div>

            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {LAYERS.map((f, i) => {
                const Icon = f.icon;
                return (
                  <motion.div
                    key={f.title}
                    variants={fadeUp}
                    custom={i % 4}
                    initial="hidden"
                    whileInView="show"
                    viewport={{ once: true, margin: "-40px" }}
                    onMouseMove={onCardMove}
                    className="feature-card rounded-2xl p-6"
                    data-testid={`feature-card-${i}`}
                  >
                    <div className="mb-4 flex items-center justify-between">
                      <div className="metal-gold-icon flex h-11 w-11 items-center justify-center rounded-xl">
                        <Icon className="text-[#FFD700]" size={20} />
                      </div>
                      <span className="layer-tag font-tech text-xs font-semibold tracking-widest text-white/30">
                        L{i + 1}
                      </span>
                    </div>
                    <h3 className="mb-2 text-base font-semibold tracking-tight">
                      <span className="metal-gold-text">Layer {i + 1}</span>
                      <span className="text-white"> — {f.title}</span>
                    </h3>
                    <p className="text-sm leading-relaxed text-[#BFC1C2]">
                      {f.body}
                    </p>
                  </motion.div>
                );
              })}
            </div>
          </section>

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
                <span className="text-platinum-gradient">5,000 units</span>
              </h2>
              <p className="mt-3 text-lg text-[#BFC1C2]">
                Pay only for what you use.
              </p>
              <p
                className="mt-2 font-tech text-sm text-[#FFD700]"
                data-testid="agents-protected-line"
              >
                5,000 units = 5,000 agent calls protected up to 25,000 tokens
                each, against multiple layers of unsafe behavior. That is up to
                125,000,000 tokens protected by IronClaw-Security python
                defense. No subscription. No recurring charge. Idle time cost
                nothing per month. Scale instantly.
              </p>

              <div className="mx-auto mt-8 grid max-w-2xl grid-cols-1 gap-3 text-left sm:grid-cols-2">
                {[
                  "No subscription",
                  "No recurring charge",
                  "Idle months cost nothing",
                  "Scale instantly",
                  "Full spend control",
                  "Transparent per-unit pricing",
                ].map((b) => (
                  <div
                    key={b}
                    className="flex items-center gap-2 text-sm text-white/90"
                  >
                    <Check size={16} className="text-[#FFD700]" /> {b}
                  </div>
                ))}
              </div>
            </motion.div>
          </section>

          <section className="relative z-10 mx-auto max-w-4xl px-6 pb-24 pt-10 text-center">
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
            >
              <h2 className="mx-auto max-w-2xl text-3xl font-bold tracking-tight sm:text-4xl">
                Start protecting your system against unsafe autonomous agents
                now. Eventually your luck will run out. IronClaw-Security is the
                safety net every production team needs.
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

          <footer className="relative z-10 border-t border-white/10 py-10">
            <div className="mx-auto flex max-w-7xl flex-col items-center gap-4 px-6 text-center">
              <div className="flex items-center gap-2">
                <ShieldCheck className="text-[#FFD700]" size={16} />
                <span className="font-tech text-sm font-bold tracking-tight">
                  IRONCLAW<span className="metal-gold-text">-SECURITY</span>
                </span>
              </div>
              <div className="flex items-center gap-6 text-xs">
                <Link
                  to="/privacy"
                  data-testid="footer-privacy-link"
                  className="text-[#BFC1C2] transition hover:text-[#FFD700]"
                >
                  Privacy Policy
                </Link>
                <span className="text-white/15">|</span>
                <Link
                  to="/terms"
                  data-testid="footer-terms-link"
                  className="text-[#BFC1C2] transition hover:text-[#FFD700]"
                >
                  Terms of Service
                </Link>
              </div>
              <p className="text-xs text-[#737373]">
                The enforcement layer serious engineers trust with production AI
                systems.
              </p>
              <p
                className="font-tech text-xs text-[#737373]"
                data-testid="powered-by"
              >
                Powered by &mdash;{" "}
                <span className="metal-gold-text">
                  Universal Rejuvenation Inc.
                </span>{" "}
                &mdash;{" "}
                <span className="metal-gold-text">
                  The Enlightenism Organization
                </span>
              </p>
            </div>
          </footer>
        </>
      ) : null}

      <AuthModal
        open={authOpen}
        onClose={() => setAuthOpen(false)}
        initialMode={authMode}
      />
    </div>
  );
};

export default Landing;
