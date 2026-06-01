import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ShieldCheck, Loader2, X, Mail, Lock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import api from "@/lib/api";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";

const AuthModal = ({ open, onClose, initialMode = "signin" }) => {
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const { authenticate } = useAuth();
  const navigate = useNavigate();

  if (!open) return null;

  const submit = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const endpoint = mode === "signup" ? "/auth/signup" : "/auth/signin";
      const { data } = await api.post(endpoint, { email, password });
      authenticate(data.token, data.user);
      toast.success(mode === "signup" ? "Account created. Defenses online." : "Welcome back, operator.");
      onClose();
      navigate("/dashboard");
    } catch (err) {
      const detail = err?.response?.data?.detail || "Something went wrong. Try again.";
      toast.error(detail);
    } finally {
      setLoading(false);
    }
  };

  const switchMode = (m) => {
    setMode(m);
  };

  return (
    <AnimatePresence>
      <motion.div
        className="fixed inset-0 z-[100] flex items-center justify-center px-4"
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        data-testid="auth-modal"
      >
        <div
          className="absolute inset-0 bg-black/70 backdrop-blur-sm"
          onClick={onClose}
        />
        <motion.div
          initial={{ scale: 0.94, y: 20, opacity: 0 }}
          animate={{ scale: 1, y: 0, opacity: 1 }}
          exit={{ scale: 0.94, opacity: 0 }}
          transition={{ type: "spring", stiffness: 260, damping: 24 }}
          className="glass relative z-10 w-full max-w-md rounded-2xl p-8"
        >
          <button
            onClick={onClose}
            data-testid="auth-modal-close"
            className="absolute right-5 top-5 text-white/50 transition hover:text-white"
          >
            <X size={20} />
          </button>

          <div className="mb-7 flex flex-col items-center text-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-xl border border-[#FFD700]/30 bg-[#C9A84C]/10">
              <ShieldCheck className="text-[#FFD700]" size={28} />
            </div>
            <h2 className="text-2xl font-semibold tracking-tight text-white">
              {mode === "signup" ? "Deploy your defenses" : "Operator sign in"}
            </h2>
            <p className="mt-1 text-sm text-[#BFC1C2]">
              {mode === "signup"
                ? "Create an account and arm your AI agents."
                : "Access your enforcement control room."}
            </p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div className="relative">
              <Mail className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40" size={18} />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="you@company.com"
                data-testid="auth-email-input"
                className="w-full rounded-lg border border-white/15 bg-white/5 py-3 pl-11 pr-4 text-sm text-white placeholder-white/40 outline-none transition focus:border-[#FFD700]/50 focus:ring-2 focus:ring-[#FFD700]/20"
              />
            </div>
            <div className="relative">
              <Lock className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40" size={18} />
              <input
                type="password"
                required
                minLength={6}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Password (min 6 chars)"
                data-testid="auth-password-input"
                className="w-full rounded-lg border border-white/15 bg-white/5 py-3 pl-11 pr-4 text-sm text-white placeholder-white/40 outline-none transition focus:border-[#FFD700]/50 focus:ring-2 focus:ring-[#FFD700]/20"
              />
            </div>

            <button
              type="submit"
              disabled={loading}
              data-testid="auth-submit-btn"
              className="btn-shimmer flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-[#C9A84C] to-[#FFD700] py-3 font-semibold text-black transition hover:shadow-[0_0_24px_rgba(255,215,0,0.4)] disabled:opacity-60"
            >
              {loading && <Loader2 className="animate-spin" size={18} />}
              {mode === "signup" ? "Create account" : "Sign in"}
            </button>
          </form>

          <div className="mt-6 text-center text-sm text-[#BFC1C2]">
            {mode === "signup" ? (
              <>
                Already protected?{" "}
                <button
                  onClick={() => switchMode("signin")}
                  data-testid="switch-to-signin"
                  className="font-medium text-[#38BDF8] hover:underline"
                >
                  Sign in
                </button>
              </>
            ) : (
              <>
                New operator?{" "}
                <button
                  onClick={() => switchMode("signup")}
                  data-testid="switch-to-signup"
                  className="font-medium text-[#38BDF8] hover:underline"
                >
                  Create an account
                </button>
              </>
            )}
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
};

export default AuthModal;
