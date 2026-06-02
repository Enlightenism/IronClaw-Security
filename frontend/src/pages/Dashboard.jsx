import { useEffect, useState, useCallback, useRef } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import {
  ShieldCheck,
  LogOut,
  Loader2,
  RefreshCw,
  FileSearch,
  ScrollText,
} from "lucide-react";
import { toast } from "sonner";
import api from "@/lib/api";
import { useAuth } from "@/context/AuthContext";
import WalletCard from "@/components/dashboard/WalletCard";
import SecurityAnalysis from "@/components/dashboard/SecurityAnalysis";
import IntegrationCard from "@/components/dashboard/IntegrationCard";

const Dashboard = () => {
  const { user, loading, logout, updateWalletUnits } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [data, setData] = useState(null);
  const [tokens, setTokens] = useState(null);
  const [loadingData, setLoadingData] = useState(true);
  const [purchasingId, setPurchasingId] = useState(null);
  const polledRef = useRef(false);

  const fetchDashboard = useCallback(async () => {
    try {
      const [dash, tok] = await Promise.all([
        api.get("/dashboard"),
        api.get("/integrations/token"),
      ]);
      setData(dash.data);
      setTokens(tok.data);
    } catch {
      // handled by interceptor
    } finally {
      setLoadingData(false);
    }
  }, []);

  useEffect(() => {
    if (!loading && !user) navigate("/");
  }, [loading, user, navigate]);

  useEffect(() => {
    if (user) fetchDashboard();
  }, [user, fetchDashboard]);

  useEffect(() => {
    if (!user) return;
    const refresh = setInterval(fetchDashboard, 5 * 60 * 1000);
    const live = setInterval(async () => {
      try {
        await api.post("/events/simulate");
        fetchDashboard();
      } catch {
        // handled by interceptor
      }
    }, 20000);
    return () => {
      clearInterval(refresh);
      clearInterval(live);
    };
  }, [user, fetchDashboard]);

  const pollPayment = useCallback(
    async (sessionId, attempts = 0) => {
      const maxAttempts = 6;
      if (attempts >= maxAttempts) {
        toast.dismiss("pay");
        toast.error("Payment status check timed out. Refresh in a moment.");
        return;
      }
      try {
        const { data: status } = await api.get(`/payments/status/${sessionId}`);
        if (status.payment_status === "paid") {
          toast.dismiss("pay");
          toast.success(
            `Payment confirmed — ${status.units.toLocaleString()} units added!`,
          );
          updateWalletUnits(status.units);
          await fetchDashboard();
          return;
        }
        if (status.status === "expired") {
          toast.dismiss("pay");
          toast.error("Payment session expired. Please try again.");
          return;
        }
        setTimeout(() => pollPayment(sessionId, attempts + 1), 2000);
      } catch {
        setTimeout(() => pollPayment(sessionId, attempts + 1), 2000);
      }
    },
    [fetchDashboard, updateWalletUnits],
  );

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const sessionId = params.get("session_id");
    if (sessionId && !polledRef.current) {
      polledRef.current = true;
      toast.loading("Verifying your payment...", { id: "pay" });
      pollPayment(sessionId);
      navigate("/dashboard", { replace: true });
    }
  }, [location.search, pollPayment, navigate]);

  const handlePurchase = async (packageId) => {
    setPurchasingId(packageId);
    try {
      const { data: res } = await api.post("/payments/create-checkout", {
        package_id: packageId,
        origin_url: window.location.origin,
      });
      window.location.href = res.url;
    } catch (e) {
      toast.error(e?.response?.data?.detail || "Could not start checkout.");
      setPurchasingId(null);
    }
  };

  const handleSignOut = () => {
    logout();
    navigate("/");
  };

  if (loading || (loadingData && !data)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#050607]">
        <Loader2 className="animate-spin text-[#FFD700]" size={36} />
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#050607] text-white">
      <nav className="sticky top-0 z-40 border-b border-white/10 bg-[#050607]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <button
            onClick={() => navigate("/")}
            className="flex items-center gap-2.5"
            data-testid="dashboard-logo"
          >
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-[#FFD700]/30 bg-[#C9A84C]/10">
              <ShieldCheck className="text-[#FFD700]" size={20} />
            </div>
            <span className="font-tech text-lg font-bold tracking-tight">
              IRONCLAW<span className="metal-gold-text">-SECURITY</span>
            </span>
          </button>

          <div className="flex items-center gap-3">
            {/* Sub-page navigation */}
            <Link
              to="/inspector"
              data-testid="nav-inspector-link"
              className="hidden items-center gap-1.5 rounded-lg border border-white/15 px-4 py-2 text-sm text-[#BFC1C2] transition hover:border-[#38BDF8]/50 hover:text-[#38BDF8] sm:flex"
            >
              <FileSearch size={15} /> Inspector
            </Link>
            <Link
              to="/policies"
              data-testid="nav-policies-link"
              className="hidden items-center gap-1.5 rounded-lg border border-white/15 px-4 py-2 text-sm text-[#BFC1C2] transition hover:border-[#FFD700]/50 hover:text-[#FFD700] sm:flex"
            >
              <ScrollText size={15} /> Policies
            </Link>

            <span
              className="font-tech hidden text-sm text-[#BFC1C2] sm:block"
              data-testid="user-email"
            >
              {user?.email}
            </span>
            <button
              onClick={handleSignOut}
              data-testid="signout-btn"
              className="flex items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-white/90 transition hover:border-[#EF4444]/50 hover:text-[#EF4444]"
            >
              <LogOut size={16} /> Sign Out
            </button>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <div className="mb-8 flex items-end justify-between">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight sm:text-3xl">
              Enforcement Control Room
            </h1>
            <p className="mt-1 text-sm text-[#BFC1C2]">
              Live verdicts, unit draw, and blocked attacks across your
              installs.
            </p>
          </div>
          <button
            onClick={fetchDashboard}
            data-testid="refresh-btn"
            className="hidden items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-[#BFC1C2] transition hover:text-white sm:flex"
          >
            <RefreshCw size={15} /> Refresh
          </button>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <WalletCard
            balance={data?.wallet_units ?? 0}
            lastPayment={data?.last_payment}
            hasPaid={data?.has_paid}
            onPurchase={handlePurchase}
            purchasingId={purchasingId}
          />
          <div className="lg:row-span-2">
            <SecurityAnalysis
              unitsToday={data?.units_today ?? 0}
              unitsWeek={data?.units_week ?? 0}
              dailyUsage={data?.daily_usage ?? []}
              attacks={data?.attacks ?? []}
            />
          </div>

          <div className="grid grid-cols-1 gap-6">
            <IntegrationCard
              title="Claude Code"
              command={tokens?.claude_code_command}
              tint="gold"
              testid="claude-code-card"
            />
            <IntegrationCard
              title="Open Claw"
              command={tokens?.openclaw_command}
              tint="platinum"
              testid="openclaw-card"
            />
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
