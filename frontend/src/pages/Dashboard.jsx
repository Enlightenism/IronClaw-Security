import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  ChevronLeft,
  ChevronRight,
  FileSearch,
  Loader2,
  LogOut,
  RefreshCw,
  ScrollText,
  ShieldCheck,
} from "lucide-react";
import { toast } from "sonner";

import IntegrationCard from "@/components/dashboard/IntegrationCard";
import SecurityAnalysis from "@/components/dashboard/SecurityAnalysis";
import WalletCard from "@/components/dashboard/WalletCard";
import { useAuth } from "@/context/AuthContext";
import api from "@/lib/api";

const ATTACKS_PAGE_SIZE = 25;
const VALID_PACKAGES = ["pkg_5000", "pkg_25000", "pkg_60000"];

const MemoWalletCard = memo(WalletCard);
const MemoSecurityAnalysis = memo(SecurityAnalysis);
const MemoIntegrationCard = memo(IntegrationCard);

const normalizePackageId = (packageId) => {
  switch (packageId) {
    case "pkg_5000":
    case "pkg5000":
      return "pkg_5000";
    case "pkg_25000":
    case "pkg25000":
      return "pkg_25000";
    case "pkg_60000":
    case "pkg60000":
      return "pkg_60000";
    default:
      return "";
  }
};

const getPackageUnits = (packageId) => {
  switch (normalizePackageId(packageId)) {
    case "pkg_5000":
      return 5000;
    case "pkg_25000":
      return 25000;
    case "pkg_60000":
      return 60000;
    default:
      return 0;
  }
};

const getErrorMessage = (error) => {
  const rawDetail = error?.response?.data?.detail;
  const rawMessage = error?.response?.data?.message;
  const topError = error?.response?.data?.error;

  if (typeof rawDetail === "string" && rawDetail.trim()) {
    return rawDetail;
  }

  if (
    rawDetail &&
    typeof rawDetail === "object" &&
    typeof rawDetail.detail === "string" &&
    rawDetail.detail.trim()
  ) {
    return rawDetail.detail;
  }

  if (
    rawDetail &&
    typeof rawDetail === "object" &&
    typeof rawDetail.error === "string" &&
    rawDetail.error.trim()
  ) {
    return rawDetail.error;
  }

  if (typeof rawMessage === "string" && rawMessage.trim()) {
    return rawMessage;
  }

  if (typeof topError === "string" && topError.trim()) {
    return topError;
  }

  if (typeof error?.message === "string" && error.message.trim()) {
    return error.message;
  }

  return "Could not start checkout.";
};

const AttackFeed = memo(function AttackFeed({ attacks }) {
  const [page, setPage] = useState(1);

  useEffect(() => {
    setPage(1);
  }, [attacks]);

  const totalPages = Math.max(1, Math.ceil(attacks.length / ATTACKS_PAGE_SIZE));

  const paginatedAttacks = useMemo(() => {
    const start = (page - 1) * ATTACKS_PAGE_SIZE;
    return attacks.slice(start, start + ATTACKS_PAGE_SIZE);
  }, [attacks, page]);

  const startItem =
    attacks.length === 0 ? 0 : (page - 1) * ATTACKS_PAGE_SIZE + 1;
  const endItem = Math.min(page * ATTACKS_PAGE_SIZE, attacks.length);

  return (
    <section
      className="rounded-2xl border border-white/10 bg-white/[0.03] p-5"
      data-testid="attack-feed"
    >
      <div className="mb-4 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Attack Feed</h2>
          <p className="mt-1 text-sm text-[#BFC1C2]">
            Paginated results to keep large incident sets lightweight.
          </p>
        </div>
        <div
          className="font-tech text-xs text-[#BFC1C2]"
          data-testid="attack-feed-summary"
        >
          {startItem}-{endItem} of {attacks.length}
        </div>
      </div>

      {attacks.length === 0 ? (
        <div
          className="rounded-xl border border-dashed border-white/10 bg-black/20 px-4 py-8 text-center text-sm text-[#BFC1C2]"
          data-testid="attack-feed-empty"
        >
          No attack events available.
        </div>
      ) : (
        <>
          <div className="space-y-3">
            {paginatedAttacks.map((attack, index) => {
              const key =
                attack?.id ??
                attack?.timestamp ??
                attack?.created_at ??
                `${page}-${index}`;

              return (
                <article
                  key={key}
                  className="rounded-xl border border-white/10 bg-black/20 p-4"
                  data-testid="attack-feed-item"
                >
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <div className="text-sm font-semibold text-white">
                        {attack?.title ||
                          attack?.type ||
                          attack?.name ||
                          "Security event"}
                      </div>
                      <div className="mt-1 text-xs text-[#BFC1C2]">
                        {attack?.description ||
                          attack?.summary ||
                          attack?.details ||
                          "No additional event details provided."}
                      </div>
                    </div>
                    <div className="text-right text-xs text-[#BFC1C2]">
                      <div>
                        {attack?.severity || attack?.status || "observed"}
                      </div>
                      <div className="mt-1">
                        {attack?.timestamp || attack?.created_at || ""}
                      </div>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>

          <div className="mt-4 flex items-center justify-between gap-3">
            <button
              type="button"
              onClick={() => setPage((current) => Math.max(1, current - 1))}
              disabled={page === 1}
              data-testid="attack-feed-prev"
              className="inline-flex items-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm text-[#BFC1C2] transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              <ChevronLeft size={16} />
              Prev
            </button>

            <div
              className="font-tech text-xs text-[#BFC1C2]"
              data-testid="attack-feed-page"
            >
              Page {page} / {totalPages}
            </div>

            <button
              type="button"
              onClick={() =>
                setPage((current) => Math.min(totalPages, current + 1))
              }
              disabled={page === totalPages}
              data-testid="attack-feed-next"
              className="inline-flex items-center gap-2 rounded-lg border border-white/15 px-3 py-2 text-sm text-[#BFC1C2] transition hover:text-white disabled:cursor-not-allowed disabled:opacity-40"
            >
              Next
              <ChevronRight size={16} />
            </button>
          </div>
        </>
      )}
    </section>
  );
});

const Dashboard = () => {
  const { user, session, loading, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [data, setData] = useState(null);
  const [tokens, setTokens] = useState(null);
  const [loadingData, setLoadingData] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [purchasingId, setPurchasingId] = useState(null);
  const polledRef = useRef(false);

  const isAuthenticated = Boolean(user || session);

  const fetchDashboard = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoadingData(true);

    try {
      const [dash, tok] = await Promise.all([
        api.get("/dashboard/overview"),
        api.get("/integrations/token"),
      ]);
      setData(dash.data);
      setTokens(tok.data);
    } catch {
      // handled by interceptor
    } finally {
      setLoadingData(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    if (!loading && !isAuthenticated) navigate("/");
  }, [isAuthenticated, loading, navigate]);

  useEffect(() => {
    if (isAuthenticated) fetchDashboard();
  }, [fetchDashboard, isAuthenticated]);

  useEffect(() => {
    if (!isAuthenticated) return undefined;

    const refresh = setInterval(
      () => {
        fetchDashboard({ silent: true });
      },
      5 * 60 * 1000,
    );

    const live = setInterval(async () => {
      try {
        await api.post("/events/simulate");
        fetchDashboard({ silent: true });
      } catch {
        // handled by interceptor
      }
    }, 20000);

    return () => {
      clearInterval(refresh);
      clearInterval(live);
    };
  }, [fetchDashboard, isAuthenticated]);

  const pollPayment = useCallback(
    async (sessionId, packageId, attempts = 0) => {
      const maxAttempts = 6;

      if (!sessionId) {
        toast.dismiss("pay");
        toast.error("Missing payment session.");
        return;
      }

      if (attempts >= maxAttempts) {
        toast.dismiss("pay");
        toast.error("Payment status check timed out. Refresh in a moment.");
        return;
      }

      try {
        const { data: status } = await api.get(
          `/billing/checkout/sessions/${encodeURIComponent(sessionId)}`,
        );

        if (status?.payment_status === "paid") {
          const units =
            Number(status?.unit_credits ?? status?.units ?? 0) ||
            getPackageUnits(packageId);
          toast.dismiss("pay");
          toast.success(
            `Payment confirmed — ${units.toLocaleString()} units added!`,
          );
          await fetchDashboard();
          setPurchasingId(null);
          return;
        }

        if (status?.status === "expired") {
          toast.dismiss("pay");
          toast.error("Payment session expired. Please try again.");
          setPurchasingId(null);
          return;
        }

        setTimeout(() => pollPayment(sessionId, packageId, attempts + 1), 2000);
      } catch {
        setTimeout(() => pollPayment(sessionId, packageId, attempts + 1), 2000);
      }
    },
    [fetchDashboard],
  );

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const sessionId = params.get("session_id");
    const checkoutState = params.get("checkout");
    const packageId = normalizePackageId(params.get("package_id") || "");

    if (checkoutState === "cancel") {
      toast.error("Checkout canceled.");
      navigate("/dashboard", { replace: true });
      setPurchasingId(null);
      return;
    }

    if (checkoutState === "success" && !sessionId) {
      toast.success("Checkout completed. Refreshing billing state...");
      fetchDashboard();
      navigate("/dashboard", { replace: true });
      setPurchasingId(null);
      return;
    }

    if (sessionId && !polledRef.current) {
      polledRef.current = true;
      toast.loading("Verifying your payment...", { id: "pay" });
      pollPayment(sessionId, packageId);
      navigate("/dashboard", { replace: true });
    }
  }, [fetchDashboard, location.search, navigate, pollPayment]);

  const handlePurchase = useCallback(
    async (rawPackageId) => {
      const packageId = normalizePackageId(rawPackageId);

      if (!VALID_PACKAGES.includes(packageId)) {
        toast.error("Invalid package selected.");
        return;
      }

      setPurchasingId(packageId);

      try {
        const organizationId = data?.organization_id ?? "org-001";
        const successUrl = new URL(`${window.location.origin}/dashboard`);
        successUrl.searchParams.set("checkout", "success");
        successUrl.searchParams.set("package_id", packageId);

        const cancelUrl = new URL(`${window.location.origin}/dashboard`);
        cancelUrl.searchParams.set("checkout", "cancel");
        cancelUrl.searchParams.set("package_id", packageId);

        const { data: res } = await api.post("/billing/checkout/sessions", {
          package_id: packageId,
          success_url: successUrl.toString(),
          cancel_url: cancelUrl.toString(),
          organization_id: organizationId,
        });

        const redirectUrl = res?.checkout_url || res?.url;

        if (!redirectUrl) {
          throw new Error("Missing checkout URL.");
        }

        if (typeof window.location.assign === "function") {
          window.location.assign(redirectUrl);
        } else {
          window.location.href = redirectUrl;
        }
      } catch (e) {
        toast.error(getErrorMessage(e));
        setPurchasingId(null);
      }
    },
    [data],
  );

  const handleSignOut = useCallback(async () => {
    await logout();
    navigate("/");
  }, [logout, navigate]);

  const handleRefresh = useCallback(() => {
    setRefreshing(true);
    fetchDashboard();
  }, [fetchDashboard]);

  const walletProps = useMemo(
    () => ({
      balance: data?.wallet_units ?? 0,
      lastPayment: data?.last_payment,
      hasPaid: data?.has_paid,
      onPurchase: handlePurchase,
      purchasingId,
      organizationId: data?.organization_id ?? "org-001",
    }),
    [
      data?.has_paid,
      data?.last_payment,
      data?.organization_id,
      data?.wallet_units,
      handlePurchase,
      purchasingId,
    ],
  );

  const securityProps = useMemo(
    () => ({
      unitsToday: data?.units_today ?? 0,
      unitsWeek: data?.units_week ?? 0,
      dailyUsage: data?.daily_usage ?? [],
      attacks: data?.attacks ?? [],
    }),
    [data?.attacks, data?.daily_usage, data?.units_today, data?.units_week],
  );

  const integrationCards = useMemo(
    () => [
      {
        title: "Claude Code",
        command: tokens?.claude_code_command,
        tint: "gold",
        testid: "claude-code-card",
      },
      {
        title: "Open Claw",
        command: tokens?.openclaw_command,
        tint: "platinum",
        testid: "openclaw-card",
      },
    ],
    [tokens?.claude_code_command, tokens?.openclaw_command],
  );

  const attackFeedItems = useMemo(() => data?.attacks ?? [], [data?.attacks]);

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
            type="button"
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
              type="button"
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
            type="button"
            onClick={handleRefresh}
            data-testid="refresh-btn"
            className="hidden items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-[#BFC1C2] transition hover:text-white sm:flex"
          >
            <RefreshCw
              size={15}
              className={refreshing ? "animate-spin" : undefined}
            />
            Refresh
          </button>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <MemoWalletCard {...walletProps} />

          <div className="space-y-6 lg:row-span-2">
            <MemoSecurityAnalysis {...securityProps} />
            <AttackFeed attacks={attackFeedItems} />
          </div>

          <div className="grid grid-cols-1 gap-6">
            {integrationCards.map((card) => (
              <MemoIntegrationCard
                key={card.testid}
                title={card.title}
                command={card.command}
                tint={card.tint}
                testid={card.testid}
              />
            ))}
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
