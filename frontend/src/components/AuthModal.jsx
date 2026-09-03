import { useState, useEffect, useMemo, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Loader2, X, Mail, Lock } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/context/AuthContext";
import { toast } from "sonner";

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AUTH_LOGO_SRC = "/images/Golden%20Knight%20Logo128.png";

const AuthModal = ({ open, onClose, initialMode = "signin" }) => {
  const [mode, setMode] = useState(initialMode);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [emailError, setEmailError] = useState("");
  const [emailStatus, setEmailStatus] = useState("");
  const { authenticate, register } = useAuth();
  const navigate = useNavigate();

  const trimmedEmail = useMemo(() => email.trim(), [email]);

  const validateEmail = useCallback((value) => {
    if (!value) {
      return "Email is required.";
    }

    if (!EMAIL_REGEX.test(value)) {
      return "Enter a valid email address.";
    }

    return "";
  }, []);

  useEffect(() => {
    if (open) {
      setMode(initialMode);
      setEmail("");
      setPassword("");
      setLoading(false);
      setEmailError("");
      setEmailStatus("");
    }
  }, [initialMode, open]);

  if (!open) return null;

  const submit = async (e) => {
    e.preventDefault();

    if (loading) return;

    const nextEmailError = validateEmail(trimmedEmail);

    if (nextEmailError) {
      setEmailError(nextEmailError);
      setEmailStatus("");
      return;
    }

    setEmailError("");
    setEmailStatus("Email looks good.");
    setLoading(true);

    try {
      const authResult =
        mode === "signup"
          ? await register(trimmedEmail, password)
          : await authenticate(trimmedEmail, password);

      const nextSession = authResult?.session ?? null;
      const nextUser = authResult?.user ?? nextSession?.user ?? null;
      const hasAuthenticatedSession = Boolean(
        nextSession?.access_token || nextUser?.id,
      );

      if (!hasAuthenticatedSession) {
        throw new Error("Authentication succeeded without an active session.");
      }

      if (mode === "signup") {
        toast.success("Account created. Defenses online.");
      } else {
        toast.success("Welcome back, operator.");
      }

      onClose();
      navigate("/dashboard");
    } catch (err) {
      const detail = err?.message || "Something went wrong. Try again.";
      toast.error(detail);
    } finally {
      setLoading(false);
    }
  };

  const switchMode = (nextMode) => {
    if (loading) return;
    setMode(nextMode);
    setPassword("");
    setEmailError("");
    setEmailStatus("");
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
          onClick={loading ? undefined : onClose}
        />
        <motion.div
          initial={{ scale: 0.94, y: 20, opacity: 0 }}
          animate={{ scale: 1, y: 0, opacity: 1 }}
          exit={{ scale: 0.94, opacity: 0 }}
          transition={{ type: "spring", stiffness: 260, damping: 24 }}
          className="glass relative z-10 w-full max-w-md rounded-2xl p-8"
        >
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            data-testid="auth-modal-close"
            className="absolute right-5 top-5 text-white/50 transition hover:text-white disabled:cursor-not-allowed disabled:opacity-50"
          >
            <X size={20} />
          </button>

          <div className="mb-7 flex flex-col items-center text-center">
            <div className="mb-4 flex h-14 w-14 items-center justify-center overflow-hidden rounded-xl border border-[#FFD700]/30 bg-[#C9A84C]/10 p-2">
              <img
                src={AUTH_LOGO_SRC}
                alt="IronClaw-Security"
                className="brand-logo-image modal-brand-logo"
              />
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
              <Mail
                className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40"
                size={18}
              />
              <input
                type="email"
                required
                autoComplete="email"
                value={email}
                onChange={(e) => {
                  const nextValue = e.target.value;
                  setEmail(nextValue);

                  const trimmedValue = nextValue.trim();

                  if (!trimmedValue) {
                    setEmailError("Email is required.");
                    setEmailStatus("");
                    return;
                  }

                  const nextEmailError = validateEmail(trimmedValue);

                  if (nextEmailError) {
                    setEmailError(nextEmailError);
                    setEmailStatus("");
                    return;
                  }

                  setEmailError("");
                  setEmailStatus("Email looks good.");
                }}
                placeholder="you@company.com"
                data-testid="auth-email-input"
                aria-invalid={emailError ? "true" : "false"}
                aria-describedby={
                  emailError || emailStatus ? "auth-email-status" : undefined
                }
                className={`w-full rounded-lg border bg-white/5 py-3 pl-11 pr-4 text-sm text-white placeholder-white/40 outline-none transition focus:ring-2 ${
                  emailError
                    ? "border-red-400/60 focus:border-red-400/60 focus:ring-red-400/20"
                    : "border-white/15 focus:border-[#FFD700]/50 focus:ring-[#FFD700]/20"
                }`}
              />
            </div>

            {(emailError || emailStatus) && (
              <div
                id="auth-email-status"
                data-testid="auth-email-status"
                className={`flex min-h-[20px] items-center gap-2 text-xs ${
                  emailError ? "text-red-300" : "text-[#BFC1C2]"
                }`}
              >
                {!emailError && emailStatus === "Validating email..." && (
                  <Loader2 className="animate-spin" size={14} />
                )}
                <span>{emailError || emailStatus}</span>
              </div>
            )}

            <div className="relative">
              <Lock
                className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40"
                size={18}
              />
              <input
                type="password"
                required
                minLength={6}
                autoComplete={
                  mode === "signup" ? "new-password" : "current-password"
                }
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
              className="btn-shimmer flex w-full items-center justify-center gap-2 rounded-lg bg-gradient-to-r from-[#C9A84C] to-[#FFD700] py-3 font-semibold text-black transition hover:shadow-[0_0_24px_rgba(255,215,0,0.4)] disabled:cursor-not-allowed disabled:opacity-60"
            >
              {loading && <Loader2 className="animate-spin" size={18} />}
              {loading
                ? mode === "signup"
                  ? "Creating account..."
                  : "Signing in..."
                : mode === "signup"
                  ? "Create account"
                  : "Sign in"}
            </button>

            {loading && (
              <div
                data-testid="auth-loading-state"
                className="rounded-lg border border-white/10 bg-white/5 p-3 text-xs text-[#BFC1C2]"
              >
                <div className="mb-2 flex items-center gap-2">
                  <Loader2 className="animate-spin" size={14} />
                  <span>Securing authentication request...</span>
                </div>
                <div className="h-2 w-full animate-pulse rounded-full bg-white/10" />
              </div>
            )}
          </form>

          <div className="mt-6 text-center text-sm text-[#BFC1C2]">
            {mode === "signup" ? (
              <>
                Already protected?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("signin")}
                  disabled={loading}
                  data-testid="switch-to-signin"
                  className="font-medium text-[#38BDF8] hover:underline disabled:opacity-50"
                >
                  Sign in
                </button>
              </>
            ) : (
              <>
                New operator?{" "}
                <button
                  type="button"
                  onClick={() => switchMode("signup")}
                  disabled={loading}
                  data-testid="switch-to-signup"
                  className="font-medium text-[#38BDF8] hover:underline disabled:opacity-50"
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
