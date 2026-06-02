import { useNavigate } from "react-router-dom";
import { ShieldOff, ShieldCheck, Home, LayoutDashboard } from "lucide-react";
import { useAuth } from "@/context/AuthContext";

const NotFound = () => {
  const navigate = useNavigate();
  const { user } = useAuth();

  return (
    <div className="flex min-h-screen flex-col items-center justify-center bg-[#050607] px-6 text-white">
      {/* Brand mark */}
      <button
        onClick={() => navigate("/")}
        className="mb-10 flex items-center gap-2.5 opacity-80 transition hover:opacity-100"
        aria-label="Go to IronClaw home"
      >
        <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/10">
          <ShieldCheck className="text-[#FFD700]" size={20} />
        </div>
        <span className="font-tech text-lg font-bold tracking-tight">
          IRONCLAW<span className="metal-gold-text">-SECURITY</span>
        </span>
      </button>

      {/* 404 card */}
      <div className="glass-platinum w-full max-w-md rounded-2xl p-10 text-center">
        <div className="mb-5 flex justify-center">
          <div className="flex h-16 w-16 items-center justify-center rounded-full border border-[#EF4444]/25 bg-[#EF4444]/10">
            <ShieldOff className="text-[#EF4444]" size={32} />
          </div>
        </div>

        <div className="font-tech mb-1 text-5xl font-bold tracking-tight text-white">
          404
        </div>
        <h1 className="font-tech mb-3 text-lg font-semibold uppercase tracking-[0.2em] text-[#E5E4E2]">
          Page Not Found
        </h1>
        <p className="mb-8 text-sm leading-relaxed text-[#737373]">
          The route you requested does not exist or has been moved. All traffic
          through IronClaw is monitored — this dead-end has been logged.
        </p>

        <div className="flex flex-col gap-3 sm:flex-row sm:justify-center">
          {user ? (
            <button
              onClick={() => navigate("/dashboard")}
              data-testid="notfound-dashboard-btn"
              className="flex items-center justify-center gap-2 rounded-xl bg-[#C9A84C]/20 border border-[#FFD700]/30 px-6 py-3 text-sm font-semibold text-[#FFD700] transition hover:bg-[#C9A84C]/30 hover:border-[#FFD700]/60"
            >
              <LayoutDashboard size={16} />
              Back to Dashboard
            </button>
          ) : (
            <button
              onClick={() => navigate("/")}
              data-testid="notfound-home-btn"
              className="flex items-center justify-center gap-2 rounded-xl bg-[#C9A84C]/20 border border-[#FFD700]/30 px-6 py-3 text-sm font-semibold text-[#FFD700] transition hover:bg-[#C9A84C]/30 hover:border-[#FFD700]/60"
            >
              <Home size={16} />
              Back to Home
            </button>
          )}
        </div>
      </div>

      <p className="mt-8 text-xs text-[#3a3a3a]">
        IronClaw-Security &mdash; Enforcement Layer Active
      </p>
    </div>
  );
};

export default NotFound;
