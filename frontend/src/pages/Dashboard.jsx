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
} from "lucide-react";
import { toast } from "sonner";

import IntegrationCard from "@/components/dashboard/IntegrationCard";
import SecurityAnalysis from "@/components/dashboard/SecurityAnalysis";
import WalletCard from "@/components/dashboard/WalletCard";
import { useAuth } from "@/context/AuthContext";
import api from "@/lib/api";

const ATTACKS_PAGE_SIZE = 25;
const VALID_PACKAGES = ["pkg5000", "pkg25000", "pkg60000"];
const DASHBOARD_LOGO_SRC = "/images/logo128pxl.svg";
const DASHBOARD_KNIGHT_SRC = "/images/Golden%20Knight%204k%202gb.png";
const INSTALL_KEY_PROGRAMS = [
  {
    program: "claude_code",
    label: "Claude Code",
    tint: "gold",
    commandKey: "claude_code_command",
  },
  {
    program: "openclaw",
    label: "OpenClaw",
    tint: "platinum",
    commandKey: "openclaw_command",
  },
  {
    program: "cursor",
    label: "Cursor",
    tint: "cyan",
    commandKey: "cursor_command",
  },
  {
    program: "goose",
    label: "Goose",
    tint: "violet",
    commandKey: "goose_command",
  },
  {
    program: "gemini_cli",
    label: "Gemini CLI",
    tint: "emerald",
    commandKey: "gemini_cli_command",
  },
  {
    program: "copilot",
    label: "Copilot",
    tint: "indigo",
    commandKey: "copilot_command",
  },
  {
    program: "security_guardian",
    label: "Shared Skill Package",
    tint: "amber",
    commandKey: "security_guardian_command",
  },
];

const CARD_TINT_STYLES = {
  gold: {
    card: "linear-gradient(135deg, rgba(255,214,102,0.18), rgba(10,12,15,0.9))",
    border: "rgba(255,215,0,0.42)",
    glow: "rgba(255,215,0,0.38)",
  },
  platinum: {
    card: "linear-gradient(135deg, rgba(210,221,232,0.15), rgba(10,12,15,0.9))",
    border: "rgba(180,188,196,0.45)",
    glow: "rgba(192,208,223,0.32)",
  },
  cyan: {
    card: "linear-gradient(135deg, rgba(69,182,255,0.14), rgba(10,12,15,0.9))",
    border: "rgba(56,189,248,0.42)",
    glow: "rgba(56,189,248,0.34)",
  },
  violet: {
    card: "linear-gradient(135deg, rgba(167,139,250,0.16), rgba(10,12,15,0.9))",
    border: "rgba(168,85,247,0.42)",
    glow: "rgba(168,85,247,0.28)",
  },
  emerald: {
    card: "linear-gradient(135deg, rgba(16,185,129,0.16), rgba(10,12,15,0.9))",
    border: "rgba(52,211,153,0.4)",
    glow: "rgba(52,211,153,0.3)",
  },
  indigo: {
    card: "linear-gradient(135deg, rgba(99,102,241,0.17), rgba(10,12,15,0.9))",
    border: "rgba(129,140,248,0.42)",
    glow: "rgba(129,140,248,0.32)",
  },
  amber: {
    card: "linear-gradient(135deg, rgba(251,191,36,0.16), rgba(10,12,15,0.9))",
    border: "rgba(253,224,71,0.42)",
    glow: "rgba(253,224,71,0.32)",
  },
};

const MemoWalletCard = memo(WalletCard);
const MemoSecurityAnalysis = memo(SecurityAnalysis);
const MemoIntegrationCard = memo(IntegrationCard);

const normalizePackageId = (packageId) => {
  switch (packageId) {
    case "pkg_5000":
    case "pkg5000":
      return "pkg5000";
    case "pkg_25000":
    case "pkg25000":
      return "pkg25000";
    case "pkg_60000":
    case "pkg60000":
      return "pkg60000";
    default:
      return "";
  }
};

const getPackageUnits = (packageId) => {
  switch (normalizePackageId(packageId)) {
    case "pkg5000":
      return 5000;
    case "pkg25000":
      return 25000;
    case "pkg60000":
      return 60000;
    default:
      return 0;
  }
};

const getErrorMessage = (error) => {
  const rawDetail = error?.response?.data?.detail;
  const rawMessage = error?.response?.data?.message;
  const topError = error?.response?.data?.error;

  if (Array.isArray(rawDetail)) {
    const first = rawDetail[0];
    if (first && typeof first.msg === "string") {
      return first.msg;
    }
    if (first && typeof first.message === "string") {
      return first.message;
    }
  }

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
  const [pointerGlow, setPointerGlow] = useState({ x: 50, y: 25 });
  const [scrollShift, setScrollShift] = useState(0);
  const polledRef = useRef(false);

  const isAuthenticated = Boolean(user || session);

  useEffect(() => {
    if (typeof window === "undefined") return undefined;
    const mediaQuery =
      typeof window.matchMedia === "function"
        ? window.matchMedia("(pointer: coarse)")
        : null;
    if (mediaQuery && mediaQuery.matches) return undefined;

    const handlePointerMove = (event) => {
      const x = (event.clientX / window.innerWidth) * 100;
      const y = (event.clientY / window.innerHeight) * 100;
      setPointerGlow({ x, y });
    };

    const handleScroll = () => {
      setScrollShift(window.scrollY * 0.18);
    };

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("scroll", handleScroll, { passive: true });

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("scroll", handleScroll);
    };
  }, []);

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

  const simulateEvent = useCallback(async () => {
    try {
      const organizationId = data?.organization_id;
      const payload = {
        event_type: "prompt_injection",
        organization_id: organizationId || "org-001",
        payload: {
          source: "dashboard_live_sim",
          timestamp: new Date().toISOString(),
        },
      };
      if (organizationId) {
        payload.organization_id = organizationId;
      }
      await api.post("/events/simulate", payload);
    } catch (err) {
      const detail = err?.response?.data?.detail;
      if (Array.isArray(detail)) {
        const msg =
          detail[0]?.msg || detail[0]?.message || "Invalid event payload.";
        toast.error(msg);
      } else if (typeof detail === "string") {
        toast.error(detail);
      } else {
        toast.error("Failed to simulate event.");
      }
    }
  }, [data?.organization_id]);

  useEffect(() => {
    if (!isAuthenticated) return undefined;

    const refresh = setInterval(
      () => {
        fetchDashboard({ silent: true });
      },
      5 * 60 * 1000,
    );

    const live = setInterval(async () => {
      await simulateEvent();
      fetchDashboard({ silent: true });
    }, 20000);

    return () => {
      clearInterval(refresh);
      clearInterval(live);
    };
  }, [fetchDashboard, isAuthenticated, simulateEvent]);

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
          packageId,
          mode: "payment",
          quantity: 1,
          successUrl: successUrl.toString(),
          cancelUrl: cancelUrl.toString(),
          organizationId,
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

  const installKeyCards = useMemo(() => {
    const slotMap = new Map(
      (Array.isArray(data?.install_keys) ? data.install_keys : []).map(
        (slot) => [slot?.program, slot],
      ),
    );

    return INSTALL_KEY_PROGRAMS.map(({ program, label, tint, commandKey }) => {
      const slot = slotMap.get(program) ?? {
        program,
        status: "locked",
        masked_key: "",
        metadata: {},
      };
      const isActive = slot?.status === "active" && Boolean(slot?.masked_key);
      const placeholderText =
        slot?.metadata?.placeholder_text ||
        slot?.metadata?.placeholder ||
        slot?.metadata?.status_message ||
        "Keys will be generated after purchase";

      return {
        program,
        title: label,
        tint,
        commandKey,
        testid: `install-key-card-${program}`,
        status: slot?.status ?? "locked",
        maskedKey: isActive ? slot.masked_key : "",
        placeholderText,
      };
    });
  }, [data?.install_keys]);

  const integrationCards = useMemo(() => {
    const hasUnlockedToken =
      tokens?.status === "ok" ||
      INSTALL_KEY_PROGRAMS.some(({ commandKey }) =>
        Boolean(tokens?.[commandKey]),
      );

    if (!hasUnlockedToken) {
      return [];
    }

    const toCardTestId = (program) => {
      switch (program) {
        case "claude_code":
          return "claude-code-card";
        case "openclaw":
          return "openclaw-card";
        case "cursor":
          return "cursor-card";
        case "goose":
          return "goose-card";
        case "gemini_cli":
          return "gemini_cli-card";
        case "copilot":
          return "copilot-card";
        case "security_guardian":
          return "security_guardian-card";
        default:
          return `${program}-card`;
      }
    };

    return INSTALL_KEY_PROGRAMS.filter(({ commandKey }) =>
      Boolean(tokens?.[commandKey]),
    )
      .map(({ label, tint, program, commandKey }) => ({
        title: label,
        command: tokens?.[commandKey] || "",
        tint,
        testid: toCardTestId(program),
      }))
      .filter((card) => Boolean(card.command));
  }, [tokens]);

  const attackFeedItems = useMemo(() => data?.attacks ?? [], [data?.attacks]);

  if (loading || (loadingData && !data)) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-[#050607]">
        <Loader2 className="animate-spin text-[#FFD700]" size={36} />
      </div>
    );
  }

  return (
    <div
      className="relative min-h-screen overflow-hidden bg-[#050607] text-white"
      style={{
        backgroundImage:
          "radial-gradient(circle at 15% 15%, rgba(255, 215, 0, 0.16), transparent 22%), radial-gradient(circle at 78% 12%, rgba(56, 189, 248, 0.12), transparent 18%), linear-gradient(180deg, rgba(5,6,7,1) 0%, rgba(9,11,16,1) 100%)",
      }}
    >
      <div className="pointer-events-none absolute inset-0 opacity-80">
        <div
          className="absolute inset-0"
          style={{
            background: `radial-gradient(circle at ${pointerGlow.x}% ${pointerGlow.y}%, rgba(255,215,0,0.20), transparent 18%), radial-gradient(circle at ${100 - pointerGlow.x}% ${pointerGlow.y + 18}%, rgba(56,189,248,0.12), transparent 20%)`,
            transform: `translateY(${scrollShift}px)`,
          }}
        />
        <div
          className="absolute -left-24 top-14 h-72 w-72 rounded-full blur-3xl"
          style={{
            background: "rgba(255,215,0,0.18)",
            transform: `translateY(${scrollShift * 0.5}px)`,
          }}
        />
        <div
          className="absolute -right-20 top-32 h-80 w-80 rounded-full blur-3xl"
          style={{
            background: "rgba(56,189,248,0.14)",
            transform: `translateY(${scrollShift * -0.35}px)`,
          }}
        />
        <div
          className="absolute inset-0 opacity-20"
          style={{
            backgroundImage:
              "linear-gradient(rgba(255,255,255,0.06) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.06) 1px, transparent 1px)",
            backgroundSize: "42px 42px",
            maskImage:
              "linear-gradient(180deg, rgba(0,0,0,0.25), rgba(0,0,0,0.8))",
          }}
        />
      </div>

      <nav className="sticky top-0 z-40 border-b border-white/10 bg-[#050607]/80 backdrop-blur-xl">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4">
          <button
            type="button"
            onClick={() => navigate("/")}
            className="flex items-center gap-2.5"
            data-testid="dashboard-logo"
          >
            <img
              src={DASHBOARD_LOGO_SRC}
              alt="IronClaw-Security"
              className="brand-logo-image"
            />
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
        <div className="mb-8 overflow-hidden rounded-[2rem] border border-[#FFD700]/20 bg-[#0a0b0d]/80 p-2 shadow-[0_0_42px_rgba(255,215,0,0.12)]">
          <img
            src={DASHBOARD_KNIGHT_SRC}
            alt="IronClaw-Security knight"
            className="dashboard-hero-image"
          />
        </div>

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

          <div className="space-y-6">
            <div className="grid grid-cols-1 gap-6">
              {installKeyCards.map((card) => {
                const accent =
                  CARD_TINT_STYLES[card.tint] ?? CARD_TINT_STYLES.gold;
                return (
                  <div
                    key={card.testid}
                    data-testid={card.testid}
                    className="relative overflow-hidden rounded-2xl border p-5 backdrop-blur-xl transition duration-300 hover:-translate-y-0.5 hover:shadow-[0_0_28px_rgba(255,215,0,0.12)]"
                    style={{
                      background: accent.card,
                      borderColor: accent.border,
                      boxShadow: `inset 0 1px 0 rgba(255,255,255,0.08), 0 18px 32px rgba(0,0,0,0.25), 0 0 0 1px ${accent.glow}`,
                    }}
                  >
                    <div
                      className="pointer-events-none absolute inset-0 opacity-90"
                      style={{
                        background: `radial-gradient(circle at 20% 0%, ${accent.glow}, transparent 32%)`,
                      }}
                    />
                    <div className="relative">
                      <div className="mb-3 flex items-center justify-between gap-3">
                        <h2 className="text-lg font-semibold tracking-tight text-white">
                          {card.title}
                        </h2>
                        <span
                          className={`rounded-full border px-2 py-1 text-[10px] font-medium uppercase tracking-wide ${
                            card.status === "active"
                              ? "border-emerald-400/30 bg-emerald-500/10 text-emerald-300"
                              : "border-amber-400/30 bg-amber-500/10 text-amber-200"
                          }`}
                        >
                          {card.status}
                        </span>
                      </div>

                      {card.maskedKey ? (
                        <div className="space-y-2">
                          <div className="text-xs uppercase tracking-[0.2em] text-[#BFC1C2]">
                            Active install key
                          </div>
                          <code className="block break-all rounded-xl border border-emerald-400/20 bg-emerald-500/5 px-3 py-2 font-mono text-sm text-emerald-200">
                            {card.maskedKey}
                          </code>
                        </div>
                      ) : (
                        <p className="text-sm text-[#BFC1C2]">
                          {card.placeholderText}
                        </p>
                      )}
                    </div>
                  </div>
                );
              })}
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
        </div>
      </main>
    </div>
  );
};

export default Dashboard;
