import { useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import {
  ShieldCheck,
  LogOut,
  Send,
  Loader2,
  ShieldAlert,
  ShieldOff,
  ShieldX,
  AlertTriangle,
  RotateCcw,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/api";
import { useAuth } from "@/context/AuthContext";

// ── Verdict config ────────────────────────────────────────────────────────────
const VERDICT_CONFIG = {
  allow: {
    label: "ALLOW",
    icon: ShieldCheck,
    bg: "bg-[#22C55E]/10",
    border: "border-[#22C55E]/35",
    text: "text-[#22C55E]",
    bar: "bg-[#22C55E]",
    glow: "shadow-[0_0_24px_rgba(34,197,94,0.18)]",
  },
  warn: {
    label: "WARN",
    icon: AlertTriangle,
    bg: "bg-[#FFD700]/10",
    border: "border-[#FFD700]/35",
    text: "text-[#FFD700]",
    bar: "bg-[#FFD700]",
    glow: "shadow-[0_0_24px_rgba(255,215,0,0.18)]",
  },
  quarantine: {
    label: "QUARANTINE",
    icon: ShieldAlert,
    bg: "bg-[#F97316]/10",
    border: "border-[#F97316]/35",
    text: "text-[#F97316]",
    bar: "bg-[#F97316]",
    glow: "shadow-[0_0_24px_rgba(249,115,22,0.18)]",
  },
  block: {
    label: "BLOCK",
    icon: ShieldX,
    bg: "bg-[#EF4444]/10",
    border: "border-[#EF4444]/35",
    text: "text-[#EF4444]",
    bar: "bg-[#EF4444]",
    glow: "shadow-[0_0_24px_rgba(239,68,68,0.18)]",
  },
};

const clampScore = (v) => Math.min(100, Math.max(0, Number(v) || 0));

// ── Threat score bar ──────────────────────────────────────────────────────────
const ThreatBar = ({ score, barClass }) => (
  <div className="mt-1">
    <div className="mb-1.5 flex items-center justify-between">
      <span className="text-xs uppercase tracking-widest text-[#BFC1C2]">
        Threat Score
      </span>
      <span className="font-tech text-sm font-bold text-white">
        {clampScore(score)}<span className="text-[#737373]">/100</span>
      </span>
    </div>
    <div className="h-2 w-full overflow-hidden rounded-full bg-white/10">
      <div
        className={`h-full rounded-full transition-all duration-700 ${barClass}`}
        style={{ width: `${clampScore(score)}%` }}
      />
    </div>
  </div>
);

// ── Main page ─────────────────────────────────────────────────────────────────
const PromptInspector = () => {
  const { user, loading, logout } = useAuth();
  const navigate = useNavigate();

  const [prompt, setPrompt] = useState("");
  const [context, setContext] = useState("");
  const [inspecting, setInspecting] = useState(false);
  const [result, setResult] = useState(null);
  const [reasoningOpen, setReasoningOpen] = useState(true);
  const textareaRef = useRef(null);

  // Auth guard — redirect if session is gone
  if (!loading && !user) {
    navigate("/");
    return null;
  }

  const handleSignOut = () => {
    logout();
    navigate("/");
  };

  const handleInspect = async () => {
    const trimmed = prompt.trim();
    if (!trimmed) {
      toast.error("Enter a prompt to inspect.");
      return;
    }
    setInspecting(true);
    setResult(null);
    try {
      const payload = { prompt: trimmed };
      if (context.trim()) payload.context = context.trim();
      const { data } = await api.post("/inspect", payload);
      setResult(data);
      setReasoningOpen(true);
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Inspection failed. Try again.");
    } finally {
      setInspecting(false);
    }
  };

  const handleReset = () => {
    setPrompt("");
    setContext("");
    setResult(null);
    textareaRef.current?.focus();
  };

  const handleKeyDown = (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") handleInspect();
  };

  const verdict = result?.verdict?.toLowerCase();
  const cfg = VERDICT_CONFIG[verdict] ?? VERDICT_CONFIG.warn;
  const VerdictIcon = cfg.icon;

  return (
    <div className="min-h-screen bg-[#050607] text-white">
      {/* ── Nav ── */}
      <nav className="sticky top-0 z-40 border-b border-white/10 bg-[#050607]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-5xl items-center justify-between px-6 py-4">
          <button
            onClick={() => navigate("/dashboard")}
            className="flex items-center gap-2.5"
            data-testid="inspector-logo"
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/10">
              <ShieldCheck className="text-[#FFD700]" size={20} />
            </div>
            <span className="font-tech text-lg font-bold tracking-tight">
              IRONCLAW<span className="metal-gold-text">-SECURITY</span>
            </span>
          </button>
          <div className="flex items-center gap-4">
            <span className="font-tech hidden text-sm text-[#BFC1C2] sm:block">
              {user?.email}
            </span>
            <button
              onClick={handleSignOut}
              data-testid="inspector-signout-btn"
              className="flex items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-white/90 transition hover:border-[#EF4444]/50 hover:text-[#EF4444]"
            >
              <LogOut size={16} /> Sign Out
            </button>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-5xl px-6 py-8">
        {/* ── Header ── */}
        <div className="mb-8">
          <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            Prompt Inspector
          </h1>
          <p className="mt-1 text-sm text-[#BFC1C2]">
            Submit any prompt or instruction to IronClaw's enforcement layer and
            receive a real-time verdict with threat scoring and reasoning.
          </p>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* ── Input panel ── */}
          <div className="flex flex-col gap-4">
            <div className="glass-platinum rounded-2xl p-6">
              <label
                htmlFor="prompt-input"
                className="mb-2 block text-xs uppercase tracking-widest text-[#BFC1C2]"
              >
                Prompt / Instruction
              </label>
              <textarea
                id="prompt-input"
                ref={textareaRef}
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={inspecting}
                rows={8}
                placeholder="Paste or type a prompt, tool call, or agent instruction…"
                data-testid="prompt-textarea"
                className="w-full resize-none rounded-xl border border-white/10 bg-white/5 px-4 py-3 font-tech text-sm text-white placeholder-[#3a3a3a] outline-none transition focus:border-[#FFD700]/40 focus:bg-white/[0.07] disabled:opacity-50"
              />

              <label
                htmlFor="context-input"
                className="mb-2 mt-4 block text-xs uppercase tracking-widest text-[#BFC1C2]"
              >
                Context{" "}
                <span className="normal-case tracking-normal text-[#737373]">
                  (optional)
                </span>
              </label>
              <textarea
                id="context-input"
                value={context}
                onChange={(e) => setContext(e.target.value)}
                onKeyDown={handleKeyDown}
                disabled={inspecting}
                rows={3}
                placeholder="System prompt, tool schema, or surrounding context…"
                data-testid="context-textarea"
                className="w-full resize-none rounded-xl border border-white/10 bg-white/5 px-4 py-3 font-tech text-sm text-white placeholder-[#3a3a3a] outline-none transition focus:border-[#FFD700]/40 focus:bg-white/[0.07] disabled:opacity-50"
              />

              <div className="mt-5 flex items-center gap-3">
                <button
                  onClick={handleInspect}
                  disabled={inspecting || !prompt.trim()}
                  data-testid="inspect-btn"
                  className="btn-shimmer flex flex-1 items-center justify-center gap-2 rounded-xl border border-[#FFD700]/30 bg-[#C9A84C]/15 px-6 py-3 text-sm font-semibold text-[#FFD700] transition hover:border-[#FFD700]/60 hover:bg-[#C9A84C]/25 disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {inspecting ? (
                    <>
                      <Loader2 size={16} className="animate-spin" /> Inspecting…
                    </>
                  ) : (
                    <>
                      <Send size={16} /> Inspect Prompt
                    </>
                  )}
                </button>
                {(result || prompt) && (
                  <button
                    onClick={handleReset}
                    data-testid="reset-btn"
                    className="flex items-center gap-2 rounded-xl border border-white/15 px-4 py-3 text-sm text-[#BFC1C2] transition hover:border-white/30 hover:text-white"
                    aria-label="Reset inspector"
                  >
                    <RotateCcw size={15} />
                  </button>
                )}
              </div>
              <p className="mt-2 text-right text-[10px] text-[#3a3a3a]">
                ⌘ + Enter to inspect
              </p>
            </div>
          </div>

          {/* ── Result panel ── */}
          <div className="flex flex-col gap-4">
            {/* Idle state */}
            {!result && !inspecting && (
              <div className="glass-platinum flex min-h-[280px] flex-col items-center justify-center rounded-2xl p-8 text-center">
                <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-full border border-white/10 bg-white/5">
                  <ShieldCheck size={28} className="text-[#737373]" />
                </div>
                <p className="text-sm text-[#737373]">
                  Verdict, threat score, and reasoning will appear here after
                  inspection.
                </p>
              </div>
            )}

            {/* Loading skeleton */}
            {inspecting && (
              <div className="glass-platinum min-h-[280px] rounded-2xl p-6">
                <div className="mb-6 flex items-center gap-3">
                  <div className="h-10 w-10 animate-pulse rounded-full bg-white/10" />
                  <div className="flex-1 space-y-2">
                    <div className="h-4 w-24 animate-pulse rounded bg-white/10" />
                    <div className="h-3 w-16 animate-pulse rounded bg-white/[0.06]" />
                  </div>
                </div>
                <div className="space-y-3">
                  <div className="h-3 w-full animate-pulse rounded bg-white/[0.06]" />
                  <div className="h-3 w-4/5 animate-pulse rounded bg-white/[0.06]" />
                  <div className="h-3 w-3/5 animate-pulse rounded bg-white/[0.06]" />
                </div>
              </div>
            )}

            {/* Verdict result */}
            {result && !inspecting && (
              <div
                className={`rounded-2xl border p-6 ${cfg.bg} ${cfg.border} ${cfg.glow}`}
                data-testid="verdict-card"
              >
                {/* Verdict badge + icon */}
                <div className="mb-5 flex items-center gap-3">
                  <div
                    className={`flex h-11 w-11 items-center justify-center rounded-full border ${cfg.border} ${cfg.bg}`}
                  >
                    <VerdictIcon size={22} className={cfg.text} />
                  </div>
                  <div>
                    <div className="text-xs uppercase tracking-widest text-[#BFC1C2]">
                      Verdict
                    </div>
                    <div
                      className={`font-tech text-xl font-bold ${cfg.text}`}
                      data-testid="verdict-label"
                    >
                      {cfg.label}
                    </div>
                  </div>
                  <span
                    className={`ml-auto rounded-full border px-3 py-1 font-tech text-[10px] font-bold uppercase tracking-wider ${cfg.bg} ${cfg.border} ${cfg.text}`}
                  >
                    {cfg.label}
                  </span>
                </div>

                {/* Threat score bar */}
                <ThreatBar score={result.threat_score} barClass={cfg.bar} />

                {/* Reasoning */}
                {result.reasoning && (
                  <div className="mt-5">
                    <button
                      onClick={() => setReasoningOpen((o) => !o)}
                      className="flex w-full items-center justify-between text-xs uppercase tracking-widest text-[#BFC1C2] transition hover:text-white"
                      data-testid="reasoning-toggle"
                    >
                      <span>Reasoning</span>
                      {reasoningOpen ? (
                        <ChevronUp size={14} />
                      ) : (
                        <ChevronDown size={14} />
                      )}
                    </button>
                    {reasoningOpen && (
                      <p
                        className="mt-2 rounded-xl border border-white/8 bg-black/30 px-4 py-3 font-tech text-xs leading-relaxed text-[#BFC1C2]"
                        data-testid="reasoning-text"
                      >
                        {result.reasoning}
                      </p>
                    )}
                  </div>
                )}

                {/* Extra fields if backend returns them */}
                {result.policy_triggered && (
                  <div className="mt-4 flex items-center gap-2 rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-xs text-[#BFC1C2]">
                    <span className="uppercase tracking-wider">Policy:</span>
                    <span className="font-tech text-white">
                      {result.policy_triggered}
                    </span>
                  </div>
                )}

                {result.units_used != null && (
                  <div className="mt-2 text-right font-tech text-[10px] text-[#737373]">
                    {result.units_used.toLocaleString()} unit
                    {result.units_used !== 1 ? "s" : ""} consumed
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </main>
    </div>
  );
};

export default PromptInspector;