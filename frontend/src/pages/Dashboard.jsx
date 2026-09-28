import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import {
  ChevronLeft,
  ChevronRight,
  Loader2,
  RefreshCw,
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
    program: "openclaw",
    label: "OpenClaw",
    tint: "platinum",
    commandKey: "openclaw_command",
  },
  {
    program: "claude_code",
    label: "Claude Code",
    tint: "gold",
    commandKey: "claude_code_command",
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
    label: "GitHub Copilot",
    tint: "indigo",
    commandKey: "copilot_command",
  },
  {
    program: "hermes",
    label: "Hermes",
    tint: "amber",
    commandKey: "hermes_command",
  },
];

const INSTALL_COMMAND_BUILDERS = {
  claude_code: (key) =>
    `gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ${key}`,
  openclaw: (key) =>
    `gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user --key ${key}`,
  cursor: (key) =>
    `gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user --key ${key}`,
  goose: (key) =>
    `gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user --key ${key}`,
  gemini_cli: (key) =>
    `gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user --key ${key}`,
  copilot: (key) =>
    `gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user --key ${key}`,
  hermes: (key) =>
    `hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ${key}`,
};

const MemoWalletCard = memo(WalletCard);
const MemoSecurityAnalysis = memo(SecurityAnalysis);
const MemoIntegrationCard = memo(IntegrationCard);

const normalizeProgramKey = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  return value.trim().toLowerCase().replace(/[-_]+/g, "_");
};

const hasEmbeddedInstallCommand = (value) => {
  if (typeof value !== "string") {
    return false;
  }

  const candidate = value.trim();
  if (!candidate) {
    return false;
  }

  return /--key\s+ic_install_[A-Za-z0-9_./~:-]+/i.test(candidate);
};

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
  const [_paymentState, setPaymentState] = useState("idle");
  const polledRef = useRef(false);

  const isAuthenticated = Boolean(user || session);

  useEffect(() => {
    if (typeof globalThis === "undefined") {
      return undefined;
    }

    const isCounterSnapshot = (value) =>
      Boolean(
        value &&
        typeof value === "object" &&
        Number.isFinite(Number(value.value)) &&
        Number.isFinite(Number(value.updatedAt)),
      );

    const store = globalThis.__IC_COUNTERS__ || {};
    const existingRegistry = store.__controllers;
    const nextRegistry = new Map();

    const registerCounter = (key, value) => {
      if (!key || !isCounterSnapshot(value)) {
        return;
      }

      const currentEntry = nextRegistry.get(key);
      if (!currentEntry) {
        nextRegistry.set(key, {
          value: Number(value.value),
          updatedAt: Number(value.updatedAt),
        });
        return;
      }

      const currentValue = Number(currentEntry.value);
      const currentUpdatedAt = Number(currentEntry.updatedAt);
      const nextValue = Number(value.value);
      const nextUpdatedAt = Number(value.updatedAt);

      if (
        nextValue > currentValue ||
        (nextValue === currentValue && nextUpdatedAt > currentUpdatedAt)
      ) {
        nextRegistry.set(key, { value: nextValue, updatedAt: nextUpdatedAt });
      }
    };

    if (existingRegistry instanceof Map) {
      for (const [key, value] of existingRegistry.entries()) {
        registerCounter(key, value);
      }
    } else if (existingRegistry && typeof existingRegistry === "object") {
      Object.entries(existingRegistry).forEach(([key, value]) => {
        registerCounter(key, value);
      });
    }

    Object.keys(store).forEach((key) => {
      if (key === "__controllers" || key === "__appMounted") {
        return;
      }

      const currentValue = store[key];
      if (!isCounterSnapshot(currentValue)) {
        delete store[key];
        return;
      }

      const normalizedEntry = {
        value: Number(currentValue.value),
        updatedAt: Number(currentValue.updatedAt),
      };

      const existingEntry = nextRegistry.get(key);
      if (!existingEntry) {
        nextRegistry.set(key, normalizedEntry);
        return;
      }

      const nextValue = Number(normalizedEntry.value);
      const currentValueNumber = Number(existingEntry.value);
      const nextUpdatedAt = Number(normalizedEntry.updatedAt);
      const currentUpdatedAt = Number(existingEntry.updatedAt);

      if (
        nextValue > currentValueNumber ||
        (nextValue === currentValueNumber && nextUpdatedAt > currentUpdatedAt)
      ) {
        nextRegistry.set(key, normalizedEntry);
      }
    });

    store.__controllers = nextRegistry;
    globalThis.__IC_COUNTERS__ = store;

    return undefined;
  }, []);

  useEffect(() => {
    if (typeof globalThis === "undefined") return undefined;
    const mediaQuery =
      typeof globalThis.matchMedia === "function"
        ? globalThis.matchMedia("(pointer: coarse)")
        : null;
    if (mediaQuery && mediaQuery.matches) return undefined;

    const handlePointerMove = (event) => {
      const x = (event.clientX / globalThis.innerWidth) * 100;
      const y = (event.clientY / globalThis.innerHeight) * 100;
      setPointerGlow({ x, y });
    };

    const handleScroll = () => {
      setScrollShift(globalThis.scrollY * 0.18);
    };

    globalThis.addEventListener("pointermove", handlePointerMove);
    globalThis.addEventListener("scroll", handleScroll, { passive: true });

    return () => {
      globalThis.removeEventListener("pointermove", handlePointerMove);
      globalThis.removeEventListener("scroll", handleScroll);
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
    const organizationId = data?.organization_id;
    if (!organizationId) {
      return;
    }

    try {
      const payload = {
        event_type: "prompt_injection",
        organization_id: organizationId,
        payload: {
          source: "dashboard_live_sim",
          timestamp: new Date().toISOString(),
        },
      };
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
          setPaymentState("paid");
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
          setPaymentState("expired");
          toast.dismiss("pay");
          toast.error("Payment session expired. Please try again.");
          setPurchasingId(null);
          return;
        }

        setPaymentState("pending");

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
      setPaymentState("expired");
      toast.error("Checkout canceled.");
      navigate("/dashboard", { replace: true });
      setPurchasingId(null);
      return;
    }

    if (checkoutState === "success" && !sessionId) {
      setPaymentState("paid");
      toast.success("Checkout completed. Refreshing billing state...");
      fetchDashboard();
      navigate("/dashboard", { replace: true });
      setPurchasingId(null);
      return;
    }

    if (sessionId && !polledRef.current) {
      setPaymentState("pending");
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
        const successUrl = new URL(`${globalThis.location.origin}/dashboard`);
        successUrl.searchParams.set("checkout", "success");
        successUrl.searchParams.set("package_id", packageId);

        const cancelUrl = new URL(`${globalThis.location.origin}/dashboard`);
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

        if (typeof globalThis.location.assign === "function") {
          globalThis.location.assign(redirectUrl);
        } else {
          globalThis.location.href = redirectUrl;
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

  const dashboardFooter = (
    <footer className="relative z-10 mt-12 border-t border-white/10 py-8 sm:py-10">
      <div className="mx-auto flex max-w-7xl flex-col items-center gap-3 px-4 text-center sm:px-6">
        <div className="flex flex-col items-center gap-2 sm:flex-row sm:gap-2">
          <img
            src="/images/Golden%20Knight%20Logo128.png"
            alt="IronClaw-Security"
            className="footer-brand-logo"
          />
          <span className="font-tech text-sm font-bold tracking-tight">
            IRONCLAW<span className="metal-gold-text">-SECURITY</span>
          </span>
        </div>
        <div className="flex flex-col items-center gap-2 text-xs sm:flex-row sm:gap-6">
          <Link
            to="/privacy"
            className="text-[#BFC1C2] transition hover:text-[#FFD700]"
          >
            Privacy Policy
          </Link>
          <span className="hidden text-white/15 sm:inline">|</span>
          <Link
            to="/terms"
            className="text-[#BFC1C2] transition hover:text-[#FFD700]"
          >
            Terms of Service
          </Link>
        </div>
        <p className="max-w-2xl text-[11px] text-[#737373] sm:text-xs">
          The enforcement layer serious engineers trust with production AI
          systems.
        </p>
        <p
          className="max-w-4xl font-tech text-[10px] leading-relaxed text-[#737373] sm:text-xs"
          data-testid="powered-by"
        >
          <span className="inline-flex flex-wrap items-center justify-center gap-x-1 gap-y-1">
            Powered by &mdash;{" "}
            <span className="metal-gold-text">Universal Rejuvenation Inc.</span>{" "}
            &mdash;{" "}
            <span className="metal-gold-text">
              The Enlightenism Organization
            </span>
          </span>
        </p>
      </div>
    </footer>
  );

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

  const ownerKey = useMemo(() => {
    const scopedOwner =
      typeof data?.metadata?.owner_key === "string"
        ? data.metadata.owner_key
        : typeof data?.owner_key === "string"
          ? data.owner_key
          : "";

    return scopedOwner.trim().toLowerCase();
  }, [data?.metadata?.owner_key, data?.owner_key]);

  const ownerScopedInstallKeys = useMemo(() => {
    const slots = Array.isArray(data?.install_keys) ? data.install_keys : [];

    return slots
      .filter((slot) => {
        const program = normalizeProgramKey(slot?.program);
        if (!program || program === "security_guardian") {
          return false;
        }

        if (!ownerKey) {
          return true;
        }

        const slotOwner =
          typeof slot?.owner_key === "string" ? slot.owner_key : "";
        return !slotOwner || slotOwner.trim().toLowerCase() === ownerKey;
      })
      .sort((left, right) => {
        const leftProgram = normalizeProgramKey(left?.program);
        const rightProgram = normalizeProgramKey(right?.program);
        const leftIndex = INSTALL_KEY_PROGRAMS.findIndex(
          ({ program }) => program === leftProgram,
        );
        const rightIndex = INSTALL_KEY_PROGRAMS.findIndex(
          ({ program }) => program === rightProgram,
        );

        if (leftIndex === -1 && rightIndex === -1) return 0;
        if (leftIndex === -1) return 1;
        if (rightIndex === -1) return -1;
        return leftIndex - rightIndex;
      });
  }, [data?.install_keys, ownerKey]);

  const integrationCards = useMemo(() => {
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
        case "hermes":
          return "hermes-card";
        default:
          return `${program}-card`;
      }
    };

    const rawInstallKeys = Array.isArray(data?.install_keys)
      ? data.install_keys
      : [];

    return INSTALL_KEY_PROGRAMS.map(({ program, label, tint, commandKey }) => {
      const hasAnyRawSlot = rawInstallKeys.some(
        (entry) => normalizeProgramKey(entry?.program) === program,
      );

      const ownedMatches = ownerScopedInstallKeys.filter(
        (entry) => normalizeProgramKey(entry?.program) === program,
      );
      const ownedSlot =
        ownedMatches.find((entry) => Boolean(entry?.masked_key)) ??
        ownedMatches[0] ??
        null;

      let command = "";

      if (hasAnyRawSlot) {
        const maskedKey =
          typeof ownedSlot?.masked_key === "string"
            ? ownedSlot.masked_key.trim()
            : "";
        const builder = INSTALL_COMMAND_BUILDERS[program];
        command = maskedKey && builder ? builder(maskedKey) : "";
      } else {
        command = hasEmbeddedInstallCommand(tokens?.[commandKey])
          ? tokens[commandKey]
          : "";
      }

      if (!hasEmbeddedInstallCommand(command)) {
        command = "";
      }

      return {
        title: label,
        command,
        tint,
        testid: toCardTestId(program),
      };
    });
  }, [data?.install_keys, ownerScopedInstallKeys, tokens]);

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
              <img
                src="/images/Golden%20Knight%20Logo128.png"
                alt=""
                className="action-button-logo"
              />
              Sign Out
            </button>
          </div>
        </div>
      </nav>

      <main className="mx-auto max-w-7xl px-6 py-8">
        <div className="mb-8">
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
      {dashboardFooter}
    </div>
  );
};

export default Dashboard;
