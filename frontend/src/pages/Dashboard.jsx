import { memo, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Loader2, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import ContactBubble from "@/components/ContactBubble";
import ContactModal from "@/components/ContactModal";
import IntegrationCard from "@/components/dashboard/IntegrationCard";
import SecurityAnalysis from "@/components/dashboard/SecurityAnalysis";
import WalletCard from "@/components/dashboard/WalletCard";
import { useAuth } from "@/context/AuthContext";
import api, { paymentMethods, payments, wallet } from "@/lib/api";

const DASHBOARD_LOGO_SRC = "/images/logo128pxl.svg";
const DASHBOARD_KNIGHT_SRC = "/images/Golden%20Knight%204k%202gb.png";
const FOOTER_RESOURCE_LINKS = [
  { label: "TryHackMe", href: "https://tryhackme.com" },
  { label: "Cisco Networking Academy", href: "https://www.netacad.com" },
  {
    label: "PortSwigger Web Security Academy",
    href: "https://portswigger.net/web-security",
  },
  { label: "OverTheWire", href: "https://overthewire.org" },
  { label: "OWASP", href: "https://owasp.org" },
];
const INSTALL_KEY_PROGRAMS = [
  {
    program: "openclaw",
    label: "OpenClaw",
    agentId: "openclaw",
    tint: "platinum",
  },
  {
    program: "claude_code",
    label: "Claude Code",
    agentId: "claude-code",
    tint: "gold",
  },
  {
    program: "cursor",
    label: "Cursor",
    agentId: "cursor",
    tint: "cyan",
  },
  {
    program: "goose",
    label: "Goose",
    agentId: "goose",
    tint: "violet",
  },
  {
    program: "gemini_cli",
    label: "Gemini CLI",
    agentId: "gemini-cli",
    tint: "emerald",
  },
  {
    program: "copilot",
    label: "GitHub Copilot",
    agentId: "github-copilot",
    tint: "indigo",
  },
  {
    program: "hermes",
    label: "Hermes",
    agentId: null,
    tint: "amber",
  },
];

const MemoWalletCard = memo(WalletCard);
const MemoSecurityAnalysis = memo(SecurityAnalysis);
const MemoIntegrationCard = memo(IntegrationCard);

const normalizePackageId = (packageId) => {
  return typeof packageId === "string" ? packageId.trim() : "";
};

const CHECKOUT_ERROR_MESSAGES = {
  verified_billing_identity_required:
    "Your account needs a verified email before you can buy a package. Sign out, sign back in, then try again.",
  authentication_required:
    "Your session has expired. Please sign in again to buy a package.",
  checkout_storage_unavailable:
    "Payment storage is temporarily unavailable. No charge was made. Please try again in a few minutes.",
  checkout_customer_lookup_unavailable:
    "We could not load your billing profile. No charge was made. Please try again in a few minutes.",
  checkout_customer_persist_unavailable:
    "We could not save your billing profile. No charge was made. Please try again in a few minutes.",
  checkout_fulfillment_storage_unavailable:
    "Checkout is temporarily unavailable while payment records are prepared. No charge was made. Please try again shortly.",
  stripe_checkout_error:
    "Stripe could not start checkout. No charge was made. Please try again.",
};

const getErrorMessage = (error) => {
  const rawDetail = error?.response?.data?.detail;
  const rawMessage = error?.response?.data?.message;
  const topError = error?.response?.data?.error;

  if (!error?.response && error?.request) {
    return "Could not reach the server. Check your connection and try again.";
  }

  const detailCode =
    rawDetail && typeof rawDetail === "object" ? rawDetail.error : undefined;
  if (typeof detailCode === "string" && CHECKOUT_ERROR_MESSAGES[detailCode]) {
    return CHECKOUT_ERROR_MESSAGES[detailCode];
  }

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

const Dashboard = () => {
  const { user, session, loading, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [data, setData] = useState(null);
  const [tokens, setTokens] = useState(null);
  const [loadingData, setLoadingData] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [purchasingId, setPurchasingId] = useState(null);
  const [savingPaymentMethod, setSavingPaymentMethod] = useState(false);
  const [paymentMethodsRefreshKey, setPaymentMethodsRefreshKey] = useState(0);
  const [pointerGlow, setPointerGlow] = useState({ x: 50, y: 25 });
  const [scrollShift, setScrollShift] = useState(0);
  const [_paymentState, setPaymentState] = useState("idle");
  const [contactOpen, setContactOpen] = useState(false);
  const polledRef = useRef(false);
  const paymentPollTimeoutRef = useRef(null);

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
      return { dashboard: dash.data, tokens: tok.data };
    } catch {
      // handled by interceptor
      return null;
    } finally {
      setLoadingData(false);
      setRefreshing(false);
    }
  }, []);

  const createInstallClaim = useCallback(async (integrationId) => {
    const response = await api.post(
      `/integrations/installers/${encodeURIComponent(integrationId)}/claim`,
    );
    return response.data;
  }, []);

  useEffect(() => {
    if (!loading && !isAuthenticated) navigate("/");
  }, [isAuthenticated, loading, navigate]);

  useEffect(() => {
    if (isAuthenticated) fetchDashboard();
  }, [fetchDashboard, isAuthenticated]);

  const pollPayment = useCallback(
    async (sessionId, attempts = 0) => {
      const maxAttempts = 15;
      const scheduleRetry = () => {
        paymentPollTimeoutRef.current = globalThis.setTimeout(() => {
          paymentPollTimeoutRef.current = null;
          pollPayment(sessionId, attempts + 1);
        }, 2000);
      };
      const reportFailure = (message) => {
        toast.dismiss("pay");
        setPaymentState("fulfillment_error");
        setPurchasingId(null);
        toast.error(
          `${message} Use Retry sync to try again, or contact support with checkout session ${sessionId}.`,
          {
            action: {
              label: "Retry sync",
              onClick: () => pollPayment(sessionId, 0),
            },
          },
        );
      };
      const retryOrReport = (message) => {
        if (attempts + 1 < maxAttempts) {
          scheduleRetry();
          return;
        }
        reportFailure(message);
      };

      if (!sessionId) {
        toast.dismiss("pay");
        toast.error("Missing payment session.");
        return;
      }

      if (attempts >= maxAttempts) {
        reportFailure("Payment status could not be verified.");
        return;
      }

      try {
        const { data: status } = await payments.getStatus(sessionId);

        if (String(status?.payment_status || "").toLowerCase() === "paid") {
          try {
            const { data: reconciled } = await payments.reconcile(sessionId);
            const credited = Number(reconciled?.units_credited ?? 0);
            if (
              reconciled?.payment_confirmed === true &&
              reconciled?.fulfillment_status === "install_keys_pending" &&
              Number.isSafeInteger(credited) &&
              credited > 0
            ) {
              fetchDashboard({ silent: true });
              toast.dismiss("pay");
              setPaymentState("fulfillment_error");
              setPurchasingId(null);
              toast.warning(
                `${credited.toLocaleString()} units were added to your wallet, but install keys are still being prepared. Contact support with checkout session ${sessionId} if they do not appear shortly.`,
                {
                  action: {
                    label: "Retry sync",
                    onClick: () => pollPayment(sessionId, 0),
                  },
                },
              );
              return;
            }
            if (
              reconciled?.payment_confirmed !== true ||
              reconciled?.fulfillment_status !== "fulfilled" ||
              !Number.isSafeInteger(credited) ||
              credited <= 0
            ) {
              retryOrReport(
                "Payment is confirmed, but wallet and install-key fulfillment are still pending.",
              );
              return;
            }

            const [snapshot, ledgerResponse] = await Promise.all([
              fetchDashboard({ silent: true }),
              wallet.getLedger(),
            ]);
            if (!snapshot) {
              throw new Error("Dashboard and install-key refresh failed.");
            }

            const walletBalance = Number(ledgerResponse?.data?.balance);
            const dashboardBalance = Number(snapshot.dashboard?.wallet_units);
            if (
              !Number.isSafeInteger(walletBalance) ||
              !Number.isSafeInteger(dashboardBalance) ||
              walletBalance !== dashboardBalance
            ) {
              throw new Error(
                "Wallet balance views have not synchronized yet.",
              );
            }

            const installMetadata = snapshot.tokens?.install_metadata;
            const installKeysReady = INSTALL_KEY_PROGRAMS.every(
              ({ program }) => {
                const slug = program.replace(/_/g, "-");
                const key = installMetadata?.[slug];
                return (
                  key?.available === true &&
                  key.program === program &&
                  key.slug === slug &&
                  typeof key.key_id === "string" &&
                  key.key_id.length > 0
                );
              },
            );
            if (!installKeysReady) {
              throw new Error(
                "One or more paid platform keys are not available yet.",
              );
            }

            setPaymentState("paid");
            setPaymentMethodsRefreshKey((key) => key + 1);
            toast.dismiss("pay");
            toast.success(
              `Payment confirmed — ${credited.toLocaleString()} units added and install keys refreshed!`,
            );
            setPurchasingId(null);
          } catch (error) {
            retryOrReport(
              `Payment is confirmed, but wallet or install-key fulfillment is incomplete. ${getErrorMessage(error)}`,
            );
          }
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
        retryOrReport("Payment status is still pending.");
      } catch (error) {
        retryOrReport(
          `Payment status could not be verified. ${getErrorMessage(error)}`,
        );
      }
    },
    [fetchDashboard],
  );

  useEffect(
    () => () => {
      if (paymentPollTimeoutRef.current !== null) {
        globalThis.clearTimeout(paymentPollTimeoutRef.current);
      }
    },
    [],
  );

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const sessionId = params.get("session_id");
    const checkoutState = params.get("checkout");
    const cardSetupState = params.get("card_setup");

    if (!sessionId) {
      polledRef.current = false;
    }

    if (cardSetupState === "success") {
      setSavingPaymentMethod(false);
      toast.success("Card setup completed. Refreshing saved payment methods.");
      setPaymentMethodsRefreshKey((key) => key + 1);
      fetchDashboard({ silent: true });
      navigate("/dashboard", { replace: true });
      return;
    }

    if (cardSetupState === "cancel") {
      setSavingPaymentMethod(false);
      toast.error("Card setup was canceled. No charge was made.");
      navigate("/dashboard", { replace: true });
      return;
    }

    if (checkoutState === "cancel") {
      setPaymentState("expired");
      toast.error("Checkout canceled.");
      navigate("/dashboard", { replace: true });
      setPurchasingId(null);
      return;
    }

    if (checkoutState === "success" && !sessionId) {
      setPaymentState("pending");
      toast.error("Missing payment session. Payment could not be verified.");
      fetchDashboard();
      navigate("/dashboard", { replace: true });
      setPurchasingId(null);
      return;
    }

    if (sessionId && !polledRef.current) {
      setPaymentState("pending");
      polledRef.current = true;
      toast.loading("Verifying your payment...", { id: "pay" });
      pollPayment(sessionId);
      navigate("/dashboard", { replace: true });
    }
  }, [fetchDashboard, location.search, navigate, pollPayment]);

  const handlePurchase = useCallback(async (rawPackageId, saveCard = false) => {
    const packageId = normalizePackageId(rawPackageId);

    if (!packageId) {
      toast.error("Invalid package selected.");
      return;
    }

    setPurchasingId(packageId);

    try {
      const successUrl = new URL(`${globalThis.location.origin}/dashboard`);
      successUrl.searchParams.set("checkout", "success");
      successUrl.searchParams.set("package_id", packageId);
      const verifiedSuccessUrl = `${successUrl.toString()}&session_id={CHECKOUT_SESSION_ID}`;

      const cancelUrl = new URL(`${globalThis.location.origin}/dashboard`);
      cancelUrl.searchParams.set("checkout", "cancel");
      cancelUrl.searchParams.set("package_id", packageId);

      const { data: res } = await payments.createCheckout({
        packageId,
        mode: "payment",
        quantity: 1,
        successUrl: verifiedSuccessUrl,
        cancelUrl: cancelUrl.toString(),
        saveCard: saveCard === true,
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
  }, []);

  const handleAddPaymentMethod = useCallback(async () => {
    setSavingPaymentMethod(true);
    const successUrl = new URL(`${globalThis.location.origin}/dashboard`);
    successUrl.searchParams.set("card_setup", "success");
    const cancelUrl = new URL(`${globalThis.location.origin}/dashboard`);
    cancelUrl.searchParams.set("card_setup", "cancel");

    try {
      const { data: result } = await paymentMethods.createSetupSession(
        successUrl.toString(),
        cancelUrl.toString(),
      );
      const redirectUrl = result?.checkout_url || result?.url;
      if (!redirectUrl) {
        throw new Error("Missing secure card setup URL.");
      }

      if (typeof globalThis.location.assign === "function") {
        globalThis.location.assign(redirectUrl);
      } else {
        globalThis.location.href = redirectUrl;
      }
    } catch (error) {
      setSavingPaymentMethod(false);
      toast.error(getErrorMessage(error));
    }
  }, []);

  const handleSignOut = useCallback(async () => {
    await logout();
    navigate("/");
  }, [logout, navigate]);

  const dashboardFooter = (
    <footer className="relative z-10 mt-12 border-t border-white/10 py-8 sm:py-10">
      <div className="mx-auto flex max-w-7xl flex-col items-center gap-3 px-4 text-center sm:px-6">
        <section
          aria-labelledby="footer-resources-title"
          data-testid="footer-resources"
          className="flex w-full max-w-4xl flex-col items-center gap-3 border-b border-white/10 pb-6"
        >
          <h3
            id="footer-resources-title"
            className="font-tech text-xs font-bold uppercase tracking-[0.2em] text-white"
          >
            Free Resources For Learning{" "}
            <span className="metal-gold-text">Cyber Security</span>
          </h3>
          <ul className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 text-xs">
            {FOOTER_RESOURCE_LINKS.map((resource, i) => (
              <li key={resource.href}>
                <a
                  href={resource.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  data-testid={`footer-resource-link-${i}`}
                  className="text-[#BFC1C2] transition hover:text-[#FFD700]"
                >
                  {resource.label}
                </a>
              </li>
            ))}
          </ul>
        </section>
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
          <span className="hidden text-white/15 sm:inline">|</span>
          <button
            type="button"
            onClick={() => setContactOpen(true)}
            data-testid="footer-contact-link"
            className="text-[#BFC1C2] transition hover:text-[#FFD700]"
          >
            CONTACT
          </button>
        </div>
        <ContactModal open={contactOpen} onOpenChange={setContactOpen} />
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

  const refreshInFlightRef = useRef(false);

  const handleRefresh = useCallback(async () => {
    if (refreshInFlightRef.current) {
      return;
    }
    refreshInFlightRef.current = true;
    setRefreshing(true);
    setPaymentMethodsRefreshKey((key) => key + 1);
    try {
      const { data: reconciliation } = await payments.reconcileRecent();
      const [snapshot, ledgerResponse] = await Promise.all([
        fetchDashboard({ silent: true }),
        wallet.getLedger(),
      ]);
      if (!snapshot) {
        throw new Error("Dashboard and install-key refresh failed.");
      }

      const walletBalance = Number(ledgerResponse?.data?.balance);
      const dashboardBalance = Number(snapshot.dashboard?.wallet_units);
      if (
        !Number.isSafeInteger(walletBalance) ||
        !Number.isSafeInteger(dashboardBalance) ||
        walletBalance !== dashboardBalance
      ) {
        throw new Error("Wallet balance views have not synchronized yet.");
      }

      const sessions = Array.isArray(reconciliation?.sessions)
        ? reconciliation.sessions
        : [];
      const failures = sessions.filter(
        (session) => session?.status === "failed",
      );
      const incomplete = sessions.filter(
        (session) => session?.status !== "fulfilled",
      );
      if (reconciliation?.truncated === true) {
        toast.error(
          "Payment sync is incomplete because the Stripe session scan reached its limit. Retry or contact support.",
        );
      } else if (
        failures.length > 0 ||
        incomplete.length > 0 ||
        reconciliation?.status === "partial"
      ) {
        const failedSession = incomplete.find((session) => session?.error);
        const detail = failedSession?.error;
        const reference = failedSession?.support_reference;
        const nextStep =
          failedSession?.action === "contact_support"
            ? "Contact support"
            : "Retry sync or contact support";
        toast.error(
          detail
            ? `Payment sync is incomplete. ${detail}${
                reference ? ` Support reference: ${reference}.` : ""
              } ${nextStep}.`
            : "Payment sync is incomplete. Retry or contact support.",
        );
      } else if (
        reconciliation?.status === "no_paid_sessions_found" ||
        Number(reconciliation?.sessions_matched) === 0
      ) {
        toast.info(
          "No completed checkout payment was found for this account, so no units were added.",
        );
      } else {
        const installKeysReady = INSTALL_KEY_PROGRAMS.every(({ program }) => {
          const slug = program.replace(/_/g, "-");
          const key = snapshot.tokens?.install_metadata?.[slug];
          return (
            key?.available === true &&
            key.program === program &&
            key.slug === slug &&
            typeof key.key_id === "string" &&
            key.key_id.length > 0
          );
        });
        if (!installKeysReady) {
          throw new Error(
            "One or more paid platform keys are not available yet.",
          );
        }

        const sessionsReconciled = Number(reconciliation?.sessions_reconciled);
        const unitsCredited = Number(reconciliation?.units_credited);
        if (
          !Number.isSafeInteger(sessionsReconciled) ||
          sessionsReconciled < 1 ||
          !Number.isSafeInteger(unitsCredited) ||
          unitsCredited < 1
        ) {
          throw new Error(
            "Stripe found a paid session, but wallet credit could not be confirmed.",
          );
        }
        const newlyCredited = Number(reconciliation?.newly_credited_units ?? 0);
        if (Number.isSafeInteger(newlyCredited) && newlyCredited > 0) {
          toast.success(
            `Payment confirmed — ${newlyCredited.toLocaleString()} units added to your wallet. Install keys are up to date.`,
          );
        } else {
          toast.info(
            "Wallet is up to date. Every completed payment was already credited, so no new units were added.",
          );
        }
      }
      const expiredCount = Array.isArray(reconciliation?.expired_checkouts)
        ? reconciliation.expired_checkouts.length
        : 0;
      if (expiredCount > 0) {
        toast.info(
          `${expiredCount.toLocaleString()} checkout${expiredCount === 1 ? " was" : "s were"} started but not completed. ${expiredCount === 1 ? "It was" : "They were"} never charged or credited.`,
        );
      }
    } catch (error) {
      await fetchDashboard({ silent: true });
      toast.error(`Payment sync failed. ${getErrorMessage(error)}`);
    } finally {
      refreshInFlightRef.current = false;
      setRefreshing(false);
    }
  }, [fetchDashboard]);

  const walletProps = useMemo(
    () => ({
      balance: data?.wallet_units ?? 0,
      unitsConsumed: Number(data?.wallet?.units_consumed) || 0,
      walletStatus: data?.wallet_status ?? "unavailable",
      lastPayment: data?.last_payment,
      walletHistory: Array.isArray(data?.wallet_history)
        ? data.wallet_history
        : [],
      hasPaid: data?.has_paid,
      onPurchase: handlePurchase,
      purchasingId,
      onAddPaymentMethod: handleAddPaymentMethod,
      addingPaymentMethod: savingPaymentMethod,
      organizationId: data?.metadata?.owner_key ?? data?.organization_id ?? "",
      paymentMethodsRefreshKey,
    }),
    [
      paymentMethodsRefreshKey,
      data?.has_paid,
      data?.last_payment,
      data?.metadata?.owner_key,
      data?.organization_id,
      data?.wallet_units,
      data?.wallet?.units_consumed,
      data?.wallet_status,
      data?.wallet_history,
      handleAddPaymentMethod,
      handlePurchase,
      purchasingId,
      savingPaymentMethod,
    ],
  );

  const installKeyDashboard = useMemo(
    () => data?.metadata?.install_key_dashboard ?? {},
    [data?.metadata?.install_key_dashboard],
  );
  const securityProps = useMemo(
    () => ({
      unitsToday: installKeyDashboard.units_today ?? 0,
      unitsWeek: installKeyDashboard.units_week ?? 0,
      dailyUsage: Array.isArray(installKeyDashboard.daily_usage)
        ? installKeyDashboard.daily_usage
        : [],
      attacks: Array.isArray(installKeyDashboard.attacks)
        ? installKeyDashboard.attacks
        : [],
      blockedAttacksTotal: Number.isSafeInteger(
        installKeyDashboard.blocked_activity_total,
      )
        ? installKeyDashboard.blocked_activity_total
        : 0,
    }),
    [installKeyDashboard],
  );

  const installKeyStatusByProgram = useMemo(() => {
    const statuses = {};
    if (Array.isArray(data?.install_keys)) {
      for (const key of data.install_keys) {
        if (typeof key?.program === "string" && key.program) {
          statuses[key.program] = key.status;
        }
      }
    }
    return statuses;
  }, [data?.install_keys]);

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

    return INSTALL_KEY_PROGRAMS.map(({ program, label, agentId, tint }) => {
      const integrationId = program.replace(/_/g, "-");
      const metadata = tokens?.install_metadata?.[integrationId];
      const slotStatus = installKeyStatusByProgram[program];
      const revoked = slotStatus === "refunded" || slotStatus === "revoked";
      const available =
        !revoked &&
        metadata?.available === true &&
        metadata?.program === program &&
        metadata?.slug === integrationId &&
        Boolean(metadata?.key_id);

      return {
        title: label,
        program,
        integrationId,
        agentId,
        available,
        revoked,
        revokedReason: slotStatus === "refunded" ? "refunded" : "revoked",
        savedCommand:
          !revoked && typeof metadata?.saved_command === "string"
            ? metadata.saved_command
            : "",
        savedCommandClaimed:
          !revoked && metadata?.saved_command_claimed === true,
        onCreateClaim: createInstallClaim,
        tint,
        testid: toCardTestId(program),
      };
    });
  }, [createInstallClaim, installKeyStatusByProgram, tokens?.install_metadata]);

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
        <div className="mx-auto flex max-w-7xl items-center justify-between px-6 py-4 max-sm:flex-col max-sm:justify-center max-sm:gap-4">
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
              IRONCLAW
              <span className="metal-gold-text">
                <span className="max-sm:hidden">-</span>
                <span className="sm:hidden"> </span>
                SECURITY
              </span>
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
            disabled={refreshing}
            data-testid="refresh-btn"
            className="items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-sm text-[#BFC1C2] transition hover:text-white flex disabled:cursor-not-allowed disabled:opacity-60"
          >
            <RefreshCw
              size={15}
              className={refreshing ? "animate-spin" : undefined}
            />
            Refresh
          </button>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          <div className="space-y-6 order-1 lg:order-2">
            <MemoWalletCard {...walletProps} />
            <MemoSecurityAnalysis {...securityProps} />
          </div>

          <div className="space-y-3 order-2 lg:order-1">
            <div className="grid grid-cols-1 gap-3">
              {integrationCards.map((card) => (
                <MemoIntegrationCard
                  key={card.testid}
                  title={card.title}
                  program={card.program}
                  integrationId={card.integrationId}
                  agentId={card.agentId}
                  available={card.available}
                  revoked={card.revoked}
                  revokedReason={card.revokedReason}
                  onCreateClaim={card.onCreateClaim}
                  savedCommand={card.savedCommand}
                  savedCommandClaimed={card.savedCommandClaimed}
                  tint={card.tint}
                  testid={card.testid}
                />
              ))}
            </div>
          </div>
        </div>
      </main>
      {dashboardFooter}
      <ContactBubble />
    </div>
  );
};

export default Dashboard;
