/**
 * frontend/src/pages/Dashboard.test.jsx
 *
 * Test harness for Dashboard.jsx
 * Runner: Jest + @testing-library/react + @testing-library/jest-dom
 */

import {
  act,
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// ── react-router-dom mock ─────────────────────────────────────────────────
const mockNavigate = jest.fn();
const mockLocation = { search: "" };

jest.mock("react-router-dom", () => ({
  useNavigate: () => mockNavigate,
  useLocation: () => mockLocation,
  Link: ({ children, to, ...rest }) => (
    <a href={to} {...rest}>
      {children}
    </a>
  ),
}));

// ── AuthContext mock ────────────────────────────────────────────────────
const mockLogout = jest.fn();
let mockAuthState = {
  user: { email: "test@ironclaw.io" },
  session: null,
  loading: false,
  logout: mockLogout,
};

jest.mock("@/context/AuthContext", () => ({
  useAuth: () => mockAuthState,
}));

// ── api mock ────────────────────────────────────────────────────────────
const mockApiGet = jest.fn();
const mockApiPost = jest.fn();

jest.mock("@/lib/api", () => ({
  __esModule: true,
  default: {
    get: (...args) => mockApiGet(...args),
    post: (...args) => mockApiPost(...args),
  },
  payments: {
    reconcileRecent: () => mockApiPost("/billing/checkout/reconcile-recent"),
    getStatus: (sessionId) =>
      mockApiGet(
        `/billing/checkout/sessions/${encodeURIComponent(sessionId)}/status`,
      ),
    reconcile: (sessionId) =>
      mockApiPost(
        `/billing/checkout/sessions/${encodeURIComponent(sessionId)}/reconcile`,
      ),
  },
  paymentMethods: {
    createSetupSession: (successUrl, cancelUrl) =>
      mockApiPost("/billing/payment-methods/setup-session", {
        successUrl,
        cancelUrl,
      }),
  },
  wallet: {
    getLedger: () => mockApiGet("/billing/units/ledger"),
  },
}));

// ── sonner mock ─────────────────────────────────────────────────────────
const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();
const mockToastLoading = jest.fn();
const mockToastDismiss = jest.fn();

jest.mock("sonner", () => ({
  toast: {
    success: (...args) => mockToastSuccess(...args),
    error: (...args) => mockToastError(...args),
    loading: (...args) => mockToastLoading(...args),
    dismiss: (...args) => mockToastDismiss(...args),
  },
}));

// ── WalletCard mock — captures props ───────────────────────────────────
let mockCapturedWalletProps = null;

jest.mock("@/components/dashboard/WalletCard", () => ({
  __esModule: true,
  default: (props) => {
    mockCapturedWalletProps = props;
    return <div data-testid="wallet-card">WalletCard</div>;
  },
}));

// ── SecurityAnalysis stub — captures props ─────────────────────────────
let mockCapturedSecurityProps = null;

jest.mock("@/components/dashboard/SecurityAnalysis", () => ({
  __esModule: true,
  default: (props) => {
    mockCapturedSecurityProps = props;
    return <div data-testid="security-analysis">SecurityAnalysis</div>;
  },
}));

// ── IntegrationCard stub ────────────────────────────────────────────────
let mockCapturedIntegrationProps = {};

jest.mock("@/components/dashboard/IntegrationCard", () => ({
  __esModule: true,
  default: (props) => {
    mockCapturedIntegrationProps[props.program] = props;
    return (
      <div data-testid={props.testid || `integration-card-${props.title}`}>
        <div>{props.title}</div>
        <button
          type="button"
          data-testid={`${props.testid}-generate`}
          disabled={props.available !== true}
          onClick={() => props.onCreateClaim?.(props.integrationId)}
        >
          Generate
        </button>
        <button type="button" data-testid={`${props.testid}-copy`} disabled>
          Copy
        </button>
      </div>
    );
  },
}));

// ── RuntimeBlocksCard stub ──────────────────────────────────────────────
jest.mock("@/components/dashboard/RuntimeBlocksCard", () => ({
  __esModule: true,
  default: () => <div data-testid="runtime-blocks-card">RuntimeBlocksCard</div>,
}));

// ── Module under test ───────────────────────────────────────────────────
import Dashboard from "./Dashboard";

// ── Default API responses ──────────────────────────────────────────────
const DEFAULT_DASH = {
  wallet_units: 100,
  organization_id: "org-abc",
  last_payment: null,
  wallet_history: [],
  has_paid: false,
  metadata: {
    install_key_dashboard: {
      units_today: 0,
      units_week: 0,
      daily_usage: [],
      attacks: [],
      blocked_activity_total: 0,
      install_key_slots: [],
    },
  },
};

const DEFAULT_TOKENS = {
  status: "locked",
  install_metadata: {},
};

const PAID_TOKENS = {
  status: "ok",
  install_metadata: Object.fromEntries(
    [
      "openclaw",
      "claude_code",
      "cursor",
      "goose",
      "gemini_cli",
      "copilot",
      "hermes",
    ].map((program) => {
      const slug = program.replace(/_/g, "-");
      return [
        slug,
        {
          available: true,
          program,
          slug,
          key_id: `ik_${program}_test`,
        },
      ];
    }),
  ),
};

const makeInstallMetadata = (programs) =>
  Object.fromEntries(
    programs.map((program) => {
      const slug = program.replace(/_/g, "-");
      return [
        slug,
        { available: true, key_id: `key-${program}`, program, slug },
      ];
    }),
  );

const withInstallKeyDashboard = (dashboard, summary) => ({
  ...dashboard,
  metadata: {
    ...(dashboard.metadata ?? {}),
    install_key_dashboard: {
      ...(dashboard.metadata?.install_key_dashboard ?? {}),
      ...summary,
    },
  },
});

function makeAttack(index) {
  return {
    id: `attack-${index}`,
    title: `Attack ${index}`,
    description: `Attack description ${index}`,
    severity: index % 2 === 0 ? "high" : "medium",
    timestamp: `2026-07-12T00:${String(index).padStart(2, "0")}:00Z`,
  };
}

function setupDefaultApis() {
  mockApiGet.mockImplementation((url) => {
    if (url === "/dashboard/overview") {
      return Promise.resolve({ data: DEFAULT_DASH });
    }
    if (url === "/billing/units/ledger") {
      return Promise.resolve({
        data: { balance: DEFAULT_DASH.wallet_units, ledger: [] },
      });
    }
    if (url === "/integrations/token") {
      return Promise.resolve({ data: DEFAULT_TOKENS });
    }
    return Promise.reject(new Error(`Unexpected GET ${url}`));
  });

  mockApiPost.mockImplementation((url) => {
    if (url === "/billing/checkout/reconcile-recent") {
      return Promise.resolve({
        data: {
          status: "no_paid_sessions_found",
          sessions_matched: 0,
          sessions_reconciled: 0,
          units_credited: 0,
          sessions: [],
          truncated: false,
        },
      });
    }
    if (url === "/events/simulate") {
      return Promise.resolve({ data: {} });
    }
    return Promise.resolve({ data: {} });
  });
}

function setupPaidCheckoutApis(sessionId) {
  mockApiGet.mockImplementation((url) => {
    if (url === `/billing/checkout/sessions/${sessionId}/status`) {
      return Promise.resolve({ data: { payment_status: "paid" } });
    }
    if (url === "/dashboard/overview") {
      return Promise.resolve({
        data: { ...DEFAULT_DASH, wallet_units: 5000 },
      });
    }
    if (url === "/billing/units/ledger") {
      return Promise.resolve({
        data: {
          balance: 5000,
          ledger: [
            {
              entry_id: `credit-${sessionId}`,
              delta: 5000,
              reference_id: sessionId,
            },
          ],
        },
      });
    }
    if (url === "/integrations/token") {
      return Promise.resolve({ data: PAID_TOKENS });
    }
    return Promise.reject(new Error(`Unexpected GET ${url}`));
  });
  mockApiPost.mockImplementation((url) => {
    if (url === `/billing/checkout/sessions/${sessionId}/reconcile`) {
      return Promise.resolve({
        data: { payment_confirmed: true, units_credited: 5000 },
      });
    }
    if (url === "/events/simulate") {
      return Promise.resolve({ data: {} });
    }
    return Promise.resolve({ data: {} });
  });
}

function resetWindowLocation() {
  Object.defineProperty(globalThis, "location", {
    value: {
      href: "",
      origin: "http://localhost",
      assign: jest.fn((url) => {
        globalThis.location.href = url;
      }),
    },
    configurable: true,
    writable: true,
  });
}

async function renderDashboard() {
  await act(async () => {
    render(<Dashboard />);
    await Promise.resolve();
  });
}

// ── Setup / teardown ────────────────────────────────────────────────────
beforeEach(() => {
  jest.clearAllMocks();
  cleanup();
  mockCapturedWalletProps = null;
  mockCapturedSecurityProps = null;
  mockCapturedIntegrationProps = {};
  mockLocation.search = "";
  mockAuthState = {
    user: { email: "test@ironclaw.io" },
    session: null,
    loading: false,
    logout: mockLogout,
  };
  mockLogout.mockResolvedValue(undefined);
  setupDefaultApis();
  resetWindowLocation();
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
});

describe("dashboard navigation", () => {
  it("does not render inspector or policy links in the top nav", async () => {
    await renderDashboard();

    expect(screen.queryByTestId("nav-inspector-link")).not.toBeInTheDocument();
    expect(screen.queryByTestId("nav-policies-link")).not.toBeInTheDocument();
    expect(screen.queryByText("Inspector")).not.toBeInTheDocument();
    expect(screen.queryByText("Policies")).not.toBeInTheDocument();
  });

  it("renders the floating contact bubble", async () => {
    await renderDashboard();

    expect(screen.getByTestId("contact-bubble")).toHaveTextContent("CONTACT");
  });

  it("does not emit React act warnings while dashboard data resolves", async () => {
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    await renderDashboard();

    expect(
      errorSpy.mock.calls.some(([message]) =>
        String(message).includes("not wrapped in act"),
      ),
    ).toBe(false);

    errorSpy.mockRestore();
  });
});

// =============================================================================
// Auth redirect
// =============================================================================

describe("auth redirect", () => {
  it("sanitizes stale top-level registry entries without rewriting live counter progression during dashboard mount", async () => {
    globalThis.__IC_COUNTERS__ = {
      ic_threats_blocked: { value: 980, updatedAt: Date.now() },
      ic_engineers_protected: { value: 460, updatedAt: Date.now() },
      __controllers: {
        ic_threats_blocked: { value: 732, updatedAt: Date.now() },
        ic_engineers_protected: { value: 344, updatedAt: Date.now() },
      },
    };

    await renderDashboard();

    expect(globalThis.__IC_COUNTERS__.ic_threats_blocked).toMatchObject({
      value: 980,
    });
    expect(globalThis.__IC_COUNTERS__.ic_engineers_protected).toMatchObject({
      value: 460,
    });
    expect(globalThis.__IC_COUNTERS__.ic_threats_blocked.value).not.toBe(732);
    expect(globalThis.__IC_COUNTERS__.ic_engineers_protected.value).not.toBe(
      344,
    );
    expect(globalThis.__IC_COUNTERS__.__controllers).toBeInstanceOf(Map);
    expect(
      globalThis.__IC_COUNTERS__.__controllers.get("ic_threats_blocked"),
    ).toMatchObject({ value: 980 });
  });

  it("preserves valid shared counter values when the dashboard registry is incomplete during mount", async () => {
    globalThis.__IC_COUNTERS__ = {
      ic_threats_blocked: { value: 980, updatedAt: Date.now() },
      ic_engineers_protected: { value: 460, updatedAt: Date.now() },
      __controllers: {
        ic_engineers_protected: { value: 344, updatedAt: Date.now() },
      },
    };

    await renderDashboard();

    expect(globalThis.__IC_COUNTERS__.ic_threats_blocked).toMatchObject({
      value: 980,
    });
    expect(globalThis.__IC_COUNTERS__.ic_engineers_protected).toMatchObject({
      value: 460,
    });
    expect(globalThis.__IC_COUNTERS__.__controllers).toBeInstanceOf(Map);
    expect(
      globalThis.__IC_COUNTERS__.__controllers.get("ic_threats_blocked"),
    ).toMatchObject({ value: 980 });
  });

  it("calls navigate('/') when user and session are null and loading is false", async () => {
    mockAuthState = {
      user: null,
      session: null,
      loading: false,
      logout: mockLogout,
    };

    await renderDashboard();

    expect(mockNavigate).toHaveBeenCalledWith("/");
  });

  it("does NOT call navigate('/') when user is present", async () => {
    await renderDashboard();

    const redirectCalls = mockNavigate.mock.calls.filter(
      (c) => c[0] === "/" && c.length === 1,
    );
    expect(redirectCalls).toHaveLength(0);
  });

  it("does NOT call navigate('/') when session is present during rehydration", async () => {
    mockAuthState = {
      user: null,
      session: { access_token: "token-123" },
      loading: false,
      logout: mockLogout,
    };

    await renderDashboard();

    const redirectCalls = mockNavigate.mock.calls.filter(
      (c) => c[0] === "/" && c.length === 1,
    );
    expect(redirectCalls).toHaveLength(0);
  });
});

// =============================================================================
// Loading spinner
// =============================================================================

describe("loading spinner", () => {
  it("renders Loader2 spinner when auth loading is true", async () => {
    mockAuthState = {
      user: null,
      session: null,
      loading: true,
      logout: mockLogout,
    };

    await renderDashboard();

    expect(document.querySelector(".animate-spin")).toBeInTheDocument();
    expect(screen.queryByTestId("wallet-card")).not.toBeInTheDocument();
  });

  it("renders spinner when loadingData is true and data is null", async () => {
    mockApiGet.mockReturnValue(new Promise(() => {}));

    await renderDashboard();

    expect(document.querySelector(".animate-spin")).toBeInTheDocument();
    expect(screen.queryByTestId("wallet-card")).not.toBeInTheDocument();
  });

  it("renders dashboard content once data resolves", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });
  });
});

// =============================================================================
// WalletCard organizationId prop
// =============================================================================

describe("WalletCard billing owner and wallet history props", () => {
  it("passes organizationId from dashboard API response to WalletCard", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, organization_id: "org-abc" },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    expect(mockCapturedWalletProps.organizationId).toBe("org-abc");
  });

  it("updates WalletCard organizationId when refreshed dashboard data changes", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    let overviewRequests = 0;
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        overviewRequests += 1;
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            organization_id:
              overviewRequests === 1 ? "org-initial" : "org-refreshed",
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();
    await waitFor(() => {
      expect(mockCapturedWalletProps.organizationId).toBe("org-initial");
    });

    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      expect(mockCapturedWalletProps.organizationId).toBe("org-refreshed");
    });
  });

  it("uses the verified wallet owner from dashboard metadata", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            organization_id: "placeholder",
            metadata: {
              ...DEFAULT_DASH.metadata,
              owner_key: "buyer@ironclaw.test",
            },
            wallet_history: [{ entry_type: "credit", units: 5000 }],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    expect(mockCapturedWalletProps.organizationId).toBe("buyer@ironclaw.test");
    expect(mockCapturedWalletProps.walletHistory).toEqual([
      { entry_type: "credit", units: 5000 },
    ]);
  });

  it("passes an empty organizationId when the API response has no owner", async () => {
    const { organization_id: _unused, ...dashWithoutOrg } = DEFAULT_DASH;

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: dashWithoutOrg });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    expect(mockCapturedWalletProps.organizationId).toBe("");
  });

  it("passes an empty organizationId when organization_id is null", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, organization_id: null },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    expect(mockCapturedWalletProps.organizationId).toBe("");
  });
});

// =============================================================================
// session_id payment polling
// =============================================================================

describe("session_id payment polling", () => {
  it("keeps install keys in placeholder state until payment fulfillment is confirmed", async () => {
    mockLocation.search = "?session_id=cs_test_pending&package_id=pkg_5000";

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [
              {
                program: "claude_code",
                status: "active",
                masked_key: "ic_install_claude_code_...paid",
                metadata: {},
              },
            ],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      if (url === "/billing/checkout/sessions/cs_test_pending/status") {
        return Promise.resolve({
          data: { payment_status: "pending", status: "open" },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(
        screen.queryByText("ic_install_claude_code_...paid"),
      ).not.toBeInTheDocument();
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
    });
  });

  it("does not downgrade the shared counter registry when a lower-valued URL snapshot is rehydrated", async () => {
    globalThis.__IC_COUNTERS__ = {
      ic_threats_blocked: { value: 1500, updatedAt: Date.now() },
      __controllers: new Map([
        ["ic_threats_blocked", { value: 1200, updatedAt: Date.now() - 5000 }],
      ]),
    };

    await renderDashboard();

    expect(globalThis.__IC_COUNTERS__.__controllers).toBeInstanceOf(Map);
    expect(
      globalThis.__IC_COUNTERS__.__controllers.get("ic_threats_blocked"),
    ).toMatchObject({ value: 1500 });
  });

  it("fires toast.loading and navigates replace on session_id in URL", async () => {
    mockLocation.search = "?session_id=cs_test_abc&package_id=pkg_5000";
    setupPaidCheckoutApis("cs_test_abc");

    await renderDashboard();

    expect(mockToastLoading).toHaveBeenCalledWith(
      expect.stringContaining("Verifying"),
      expect.objectContaining({ id: "pay" }),
    );
    expect(mockNavigate).toHaveBeenCalledWith("/dashboard", { replace: true });
  });

  it("fires toast.success with unit count when payment_status is paid", async () => {
    mockLocation.search = "?session_id=cs_test_abc&package_id=pkg_5000";
    setupPaidCheckoutApis("cs_test_abc");

    await renderDashboard();

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith(
        expect.stringContaining("5,000"),
      );
    });
  });

  it("dismisses the pay toast before showing success", async () => {
    mockLocation.search = "?session_id=cs_test_abc&package_id=pkg_5000";
    setupPaidCheckoutApis("cs_test_abc");

    await renderDashboard();

    await waitFor(() => {
      expect(mockToastDismiss).toHaveBeenCalledWith("pay");
    });
  });

  it("reconciles wallet credits and refreshes all paid platform keys before reporting success", async () => {
    mockLocation.search = "?session_id=cs_test_abc&package_id=pkg_5000";
    setupPaidCheckoutApis("cs_test_abc");

    await renderDashboard();

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith(
        expect.stringContaining("install keys refreshed"),
      );
    });

    expect(mockApiPost).toHaveBeenCalledWith(
      "/billing/checkout/sessions/cs_test_abc/reconcile",
    );
    expect(mockApiGet).toHaveBeenCalledWith("/billing/units/ledger");
    expect(mockCapturedWalletProps.balance).toBe(5000);
    for (const program of [
      "openclaw",
      "claude_code",
      "cursor",
      "goose",
      "gemini_cli",
      "copilot",
      "hermes",
    ]) {
      expect(mockCapturedIntegrationProps[program].available).toBe(true);
      expect(
        screen.getByTestId(
          `${mockCapturedIntegrationProps[program].testid}-generate`,
        ),
      ).toBeEnabled();
    }
  });

  it("retries reconciliation after a fulfillment error", async () => {
    mockLocation.search = "?session_id=cs_test_abc&package_id=pkg_5000";
    setupPaidCheckoutApis("cs_test_abc");
    let reconcileAttempts = 0;
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions/cs_test_abc/reconcile") {
        reconcileAttempts += 1;
        if (reconcileAttempts === 1) {
          return Promise.reject(new Error("Temporary fulfillment error"));
        }
        return Promise.resolve({
          data: { payment_confirmed: true, units_credited: 5000 },
        });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();
    await waitFor(() => {
      expect(reconcileAttempts).toBe(1);
    });

    await act(async () => {
      jest.advanceTimersByTime(2000);
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith(
        expect.stringContaining("5,000"),
      );
    });
    expect(reconcileAttempts).toBe(2);
  });

  it("does not mark checkout as paid when Stripe's session ID is missing", async () => {
    mockLocation.search = "?checkout=success&package_id=pkg_5000";

    await renderDashboard();

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        "Missing payment session. Payment could not be verified.",
      );
    });
    expect(mockToastSuccess).not.toHaveBeenCalledWith(
      expect.stringContaining("Checkout completed"),
    );
  });
});

describe("card setup return", () => {
  it("refreshes the dashboard after successful no-charge card setup", async () => {
    mockLocation.search = "?card_setup=success";

    await renderDashboard();

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith(
        "Card setup completed. Refreshing saved payment methods.",
      );
    });
    expect(mockApiGet).toHaveBeenCalledWith("/dashboard/overview");
    expect(mockNavigate).toHaveBeenCalledWith("/dashboard", { replace: true });
  });
});

// =============================================================================
// handlePurchase — invalid package guard
// =============================================================================

describe("handlePurchase — invalid package", () => {
  it("surfaces backend validation errors for an unknown package ID", async () => {
    mockApiPost.mockRejectedValue({
      response: { data: { detail: "Invalid package selected." } },
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_invalid");
    });

    expect(mockToastError).toHaveBeenCalledWith("Invalid package selected.");
  });

  it("uses the backend catalog as the source of truth for package validation", async () => {
    mockApiPost.mockRejectedValue({
      response: { data: { detail: "Invalid package selected." } },
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    const postCallsBefore = mockApiPost.mock.calls.length;

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_invalid");
    });

    expect(mockApiPost).toHaveBeenCalledTimes(postCallsBefore + 1);
    expect(mockApiPost).toHaveBeenCalledWith(
      "/billing/checkout/sessions",
      expect.objectContaining({ packageId: "pkg_invalid" }),
    );
    expect(mockToastError).toHaveBeenCalledWith("Invalid package selected.");
    expect(globalThis.location.assign).not.toHaveBeenCalled();
  });
});

// =============================================================================
// handlePurchase — valid package
// =============================================================================

describe("handlePurchase — valid package", () => {
  it("calls api.post /billing/checkout/sessions with the current request shape used by Dashboard", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            organization_id: "placeholder-org",
            metadata: {
              ...DEFAULT_DASH.metadata,
              owner_key: "buyer@ironclaw.test",
            },
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions") {
        return Promise.resolve({
          data: { url: "https://checkout.stripe.com/pay/cs_test_xyz" },
        });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_5000");
    });

    expect(mockApiPost).toHaveBeenCalledWith("/billing/checkout/sessions", {
      packageId: "pkg_5000",
      successUrl:
        "http://localhost/dashboard?checkout=success&package_id=pkg_5000&session_id={CHECKOUT_SESSION_ID}",
      cancelUrl:
        "http://localhost/dashboard?checkout=cancel&package_id=pkg_5000",
      organizationId: "buyer@ironclaw.test",
      mode: "payment",
      quantity: 1,
    });
  });

  it("redirects with window.location.assign when checkout response returns url", async () => {
    const checkoutUrl = "https://checkout.stripe.com/pay/cs_test_xyz";

    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions") {
        return Promise.resolve({ data: { url: checkoutUrl } });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_5000");
    });

    await waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledWith(checkoutUrl);
      expect(window.location.href).toBe(checkoutUrl);
    });
  });

  it("redirects with window.location.assign when checkout response returns checkout_url", async () => {
    const checkoutUrl = "https://checkout.stripe.com/pay/cs_test_checkout_url";

    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions") {
        return Promise.resolve({ data: { checkout_url: checkoutUrl } });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_25000");
    });

    await waitFor(() => {
      expect(window.location.assign).toHaveBeenCalledWith(checkoutUrl);
      expect(window.location.href).toBe(checkoutUrl);
      expect(mockToastError).not.toHaveBeenCalled();
    });
  });

  it("falls back to window.location.href when window.location.assign is unavailable", async () => {
    const checkoutUrl = "https://checkout.stripe.com/pay/cs_test_href_only";

    window.location.assign = undefined;

    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions") {
        return Promise.resolve({ data: { url: checkoutUrl } });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_60000");
    });

    await waitFor(() => {
      expect(window.location.href).toBe(checkoutUrl);
    });
  });

  it("accepts all three valid package IDs without toast.error", async () => {
    const validIds = ["pkg5000", "pkg25000", "pkg60000"];

    for (const pkgId of validIds) {
      cleanup();
      jest.clearAllMocks();
      mockCapturedWalletProps = null;
      mockCapturedSecurityProps = null;
      mockLocation.search = "";
      mockAuthState = {
        user: { email: "test@ironclaw.io" },
        session: null,
        loading: false,
        logout: mockLogout,
      };
      mockLogout.mockResolvedValue(undefined);
      setupDefaultApis();
      resetWindowLocation();

      mockApiPost.mockImplementation((url) => {
        if (url === "/billing/checkout/sessions") {
          return Promise.resolve({
            data: { url: "https://checkout.stripe.com/pay/x" },
          });
        }
        if (url === "/events/simulate") {
          return Promise.resolve({ data: {} });
        }
        return Promise.resolve({ data: {} });
      });

      await renderDashboard();

      await waitFor(() => {
        expect(mockCapturedWalletProps).not.toBeNull();
      });

      await act(async () => {
        await mockCapturedWalletProps.onPurchase(pkgId);
      });

      expect(mockToastError).not.toHaveBeenCalled();
    }
  });

  it("calls toast.error when api.post rejects", async () => {
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions") {
        return Promise.reject({
          response: { data: { detail: "Checkout failed" } },
        });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_5000");
    });

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        expect.stringContaining("Checkout failed"),
      );
    });
  });

  it("calls toast.error when checkout response has neither url nor checkout_url", async () => {
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions") {
        return Promise.resolve({ data: {} });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onPurchase("pkg_5000");
    });

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        expect.stringContaining("Missing checkout URL"),
      );
    });
  });

  it("starts hosted card setup without creating a paid package checkout", async () => {
    const setupUrl = "https://checkout.stripe.com/c/setup_test_001";
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/payment-methods/setup-session") {
        return Promise.resolve({ data: { checkout_url: setupUrl } });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();
    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await mockCapturedWalletProps.onAddPaymentMethod();
    });

    expect(mockApiPost).toHaveBeenCalledWith(
      "/billing/payment-methods/setup-session",
      {
        successUrl: "http://localhost/dashboard?card_setup=success",
        cancelUrl: "http://localhost/dashboard?card_setup=cancel",
      },
    );
    expect(mockApiPost).not.toHaveBeenCalledWith(
      "/billing/checkout/sessions",
      expect.anything(),
    );
    expect(globalThis.location.assign).toHaveBeenCalledWith(setupUrl);
  });
});

// =============================================================================
// Sign out
// =============================================================================

describe("sign out", () => {
  it("calls logout() when Sign Out is clicked", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("signout-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("signout-btn"));

    expect(mockLogout).toHaveBeenCalledTimes(1);
  });

  it("awaits logout() before calling navigate('/')", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    let resolveLogout;
    mockLogout.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          resolveLogout = resolve;
        }),
    );

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("signout-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("signout-btn"));

    expect(mockLogout).toHaveBeenCalledTimes(1);
    expect(mockNavigate).not.toHaveBeenCalledWith("/");

    await act(async () => {
      resolveLogout();
    });

    await waitFor(() => {
      expect(mockNavigate).toHaveBeenCalledWith("/");
    });
  });
});

// =============================================================================
// Dashboard renders core structure
// =============================================================================

describe("dashboard structure", () => {
  it("renders WalletCard after data loads", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });
  });

  it("renders SecurityAnalysis after data loads", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("security-analysis")).toBeInTheDocument();
    });
  });

  it("renders user email in nav", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("user-email")).toHaveTextContent(
        "test@ironclaw.io",
      );
    });
  });

  it("passes balance from wallet_units to WalletCard", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, wallet_units: 9999 },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedWalletProps).not.toBeNull();
    });

    expect(mockCapturedWalletProps.balance).toBe(9999);
  });

  it("renders all seven runtimes in canonical order and keeps unissued runtimes locked", async () => {
    const cardIds = [
      "openclaw-card",
      "claude-code-card",
      "cursor-card",
      "goose-card",
      "gemini_cli-card",
      "copilot-card",
      "hermes-card",
    ];

    await renderDashboard();

    await waitFor(() => {
      for (const cardId of cardIds) {
        expect(screen.getByTestId(cardId)).toBeInTheDocument();
        expect(screen.getByTestId(`${cardId}-generate`)).toBeDisabled();
      }
    });

    const renderedCardIds = Array.from(
      document.querySelectorAll('[data-testid$="-card"]'),
    )
      .map((card) => card.getAttribute("data-testid"))
      .filter((cardId) => cardIds.includes(cardId));
    expect(renderedCardIds).toEqual(cardIds);
    expect(
      screen.queryByTestId("security_guardian-card"),
    ).not.toBeInTheDocument();
  });

  it("ignores masked dashboard keys and legacy command fields", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [
              {
                program: "claude_code",
                status: "active",
                masked_key: "ic_install_claude_code_...masked",
              },
            ],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            claude_code_command:
              "gh skill install Enlightenism/IronClaw-Security skills/ironclaw-security --agent claude-code --scope user",
            install_metadata: {},
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card-generate")).toBeDisabled();
    expect(screen.getByTestId("claude-code-card-copy")).toBeDisabled();
    expect(screen.queryByText(/ic_install_/)).not.toBeInTheDocument();
    expect(mockApiPost).not.toHaveBeenCalledWith(
      "/integrations/installers/claude-code/claim",
    );
  });

  it("marks a refunded runtime as revoked and drops its available and saved command state", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [{ program: "claude_code", status: "refunded" }],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            install_metadata: {
              "claude-code": {
                ...makeInstallMetadata(["claude_code"])["claude-code"],
                saved_command:
                  "python -m ironclaw_installer redeem --program claude_code",
                saved_command_claimed: true,
              },
            },
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    expect(mockCapturedIntegrationProps.claude_code).toMatchObject({
      revoked: true,
      revokedReason: "refunded",
      available: false,
      savedCommand: "",
      savedCommandClaimed: false,
    });
    expect(screen.getByTestId("claude-code-card-generate")).toBeDisabled();
  });

  it("requests an install claim only after an eligible runtime is selected", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            install_metadata: makeInstallMetadata(["claude_code"]),
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    expect(screen.getByTestId("claude-code-card-generate")).toBeEnabled();
    expect(screen.getByTestId("openclaw-card-generate")).toBeDisabled();
    expect(mockApiPost).not.toHaveBeenCalledWith(
      "/integrations/installers/claude-code/claim",
    );

    await user.click(screen.getByTestId("claude-code-card-generate"));

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith(
        "/integrations/installers/claude-code/claim",
      );
    });
  });

  it("keeps metadata unavailable when the canonical program, slug, or key ID is inconsistent", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            install_metadata: {
              "claude-code": {
                available: true,
                program: "openclaw",
                slug: "claude-code",
                key_id: "key-claude-code",
              },
              openclaw: {
                available: true,
                program: "openclaw",
                slug: "openclaw",
                key_id: "",
              },
            },
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    expect(screen.getByTestId("claude-code-card-generate")).toBeDisabled();
    expect(screen.getByTestId("openclaw-card-generate")).toBeDisabled();
  });

  it("renders canonical runtime labels and excludes Security Guardian as a standalone platform", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
      expect(screen.getByTestId("openclaw-card")).toBeInTheDocument();
      expect(screen.getByTestId("cursor-card")).toBeInTheDocument();
      expect(screen.getByTestId("goose-card")).toBeInTheDocument();
      expect(screen.getByTestId("gemini_cli-card")).toBeInTheDocument();
      expect(screen.getByTestId("copilot-card")).toBeInTheDocument();
      expect(screen.getByTestId("hermes-card")).toBeInTheDocument();
    });

    expect(screen.getAllByText("GitHub Copilot").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Hermes").length).toBeGreaterThan(0);
    expect(screen.queryAllByText("Hermes Agent")).toHaveLength(0);
    expect(screen.queryAllByText("Copilot")).toHaveLength(0);
    expect(
      screen.queryByTestId("security_guardian-card"),
    ).not.toBeInTheDocument();
  });

  it("passes attack and usage data to SecurityAnalysis", async () => {
    const attacks = [makeAttack(1), makeAttack(2)];
    const dailyUsage = [
      { day: "Mon", units: 10 },
      { day: "Tue", units: 20 },
    ];

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: withInstallKeyDashboard(DEFAULT_DASH, {
            units_today: 11,
            units_week: 77,
            daily_usage: dailyUsage,
            attacks,
            blocked_activity_total: 5,
          }),
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockCapturedSecurityProps).not.toBeNull();
    });

    expect(mockCapturedSecurityProps.unitsToday).toBe(11);
    expect(mockCapturedSecurityProps.unitsWeek).toBe(77);
    expect(mockCapturedSecurityProps.dailyUsage).toEqual(dailyUsage);
    expect(mockCapturedSecurityProps.attacks).toEqual(attacks);
    expect(screen.getByTestId("attack-feed-blocked-total")).toHaveTextContent(
      "5",
    );
  });
});

// =============================================================================
// Attack feed pagination
// =============================================================================

describe("attack feed pagination", () => {
  it("renders empty state when no attacks are available", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed")).toBeInTheDocument();
    });

    expect(screen.getByTestId("attack-feed-empty")).toBeInTheDocument();
    expect(screen.getByTestId("attack-feed-summary")).toHaveTextContent(
      "0-0 of 0",
    );
    expect(screen.queryAllByTestId("attack-feed-item")).toHaveLength(0);
  });

  it("renders only the first 25 attacks on page 1", async () => {
    const attacks = Array.from({ length: 30 }, (_, index) =>
      makeAttack(index + 1),
    );

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: withInstallKeyDashboard(DEFAULT_DASH, { attacks }),
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getAllByTestId("attack-feed-item")).toHaveLength(25);
    });

    expect(screen.getByTestId("attack-feed-summary")).toHaveTextContent(
      "1-25 of 30",
    );
    expect(screen.getByTestId("attack-feed-page")).toHaveTextContent(
      "Page 1 / 2",
    );
    expect(screen.getByText("Attack 1")).toBeInTheDocument();
    expect(screen.getByText("Attack 25")).toBeInTheDocument();
    expect(screen.queryByText("Attack 26")).not.toBeInTheDocument();
  });

  it("moves to the next page when Next is clicked", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    const attacks = Array.from({ length: 30 }, (_, index) =>
      makeAttack(index + 1),
    );

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: withInstallKeyDashboard(DEFAULT_DASH, { attacks }),
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed-next")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("attack-feed-next"));

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed-page")).toHaveTextContent(
        "Page 2 / 2",
      );
    });

    expect(screen.getByTestId("attack-feed-summary")).toHaveTextContent(
      "26-30 of 30",
    );
    expect(screen.getAllByTestId("attack-feed-item")).toHaveLength(5);
    expect(screen.getByText("Attack 26")).toBeInTheDocument();
    expect(screen.getByText("Attack 30")).toBeInTheDocument();
    expect(screen.queryByText("Attack 25")).not.toBeInTheDocument();
  });

  it("disables Prev on the first page and Next on the last page", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    const attacks = Array.from({ length: 30 }, (_, index) =>
      makeAttack(index + 1),
    );

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: withInstallKeyDashboard(DEFAULT_DASH, { attacks }),
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed-prev")).toBeDisabled();
      expect(screen.getByTestId("attack-feed-next")).not.toBeDisabled();
    });

    await user.click(screen.getByTestId("attack-feed-next"));

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed-prev")).not.toBeDisabled();
      expect(screen.getByTestId("attack-feed-next")).toBeDisabled();
    });
  });

  it("resets attack feed to page 1 after a refresh loads a new attack set", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    const firstAttackSet = Array.from({ length: 30 }, (_, index) =>
      makeAttack(index + 1),
    );
    const refreshedAttackSet = Array.from({ length: 5 }, (_, index) =>
      makeAttack(index + 101),
    );

    mockApiGet
      .mockResolvedValueOnce({
        data: withInstallKeyDashboard(DEFAULT_DASH, {
          attacks: firstAttackSet,
        }),
      })
      .mockResolvedValueOnce({ data: DEFAULT_TOKENS })
      .mockResolvedValueOnce({
        data: withInstallKeyDashboard(DEFAULT_DASH, {
          attacks: refreshedAttackSet,
        }),
      })
      .mockResolvedValueOnce({ data: DEFAULT_TOKENS });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed-next")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("attack-feed-next"));

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed-page")).toHaveTextContent(
        "Page 2 / 2",
      );
    });

    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      expect(screen.getByTestId("attack-feed-page")).toHaveTextContent(
        "Page 1 / 1",
      );
    });

    const feed = screen.getByTestId("attack-feed");
    expect(within(feed).getByText("Attack 101")).toBeInTheDocument();
    expect(within(feed).queryByText("Attack 26")).not.toBeInTheDocument();
  });
});

// =============================================================================
// Refresh behavior
// =============================================================================

describe("refresh behavior", () => {
  it("re-fetches dashboard data when Refresh is clicked", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("refresh-btn")).toBeInTheDocument();
    });

    const dashboardCallsBefore = mockApiGet.mock.calls.filter(
      ([url]) => url === "/dashboard/overview",
    ).length;

    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      const dashboardCallsAfter = mockApiGet.mock.calls.filter(
        ([url]) => url === "/dashboard/overview",
      ).length;
      expect(dashboardCallsAfter).toBeGreaterThan(dashboardCallsBefore);
    });
  });

  it("reconciles recent checkout sessions before re-fetching on Refresh", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("refresh-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith(
        "/billing/checkout/reconcile-recent",
      );
    });
  });

  it("reports a completed reconciliation only after wallet and platform keys are confirmed", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, wallet_units: 5000 },
        });
      }
      if (url === "/billing/units/ledger") {
        return Promise.resolve({ data: { balance: 5000, ledger: [] } });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: PAID_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/reconcile-recent") {
        return Promise.resolve({
          data: {
            status: "complete",
            sessions_matched: 1,
            sessions_reconciled: 1,
            units_credited: 5000,
            sessions: [
              {
                session_id: "cs_refresh_001",
                status: "fulfilled",
                units_credited: 5000,
              },
            ],
            truncated: false,
          },
        });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();
    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith(
        expect.stringContaining("5,000 units are in your wallet"),
      );
    });
  });

  it("shows the backend reconciliation failure instead of a generic sync message", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/reconcile-recent") {
        return Promise.reject({
          response: {
            data: {
              detail: {
                error: "reconcile_error",
                detail: "STRIPE_SECRET_KEY is not configured.",
              },
            },
          },
        });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();
    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        "Payment sync failed. STRIPE_SECRET_KEY is not configured.",
      );
    });
  });

  it("reports a partial Stripe recovery without claiming payment fulfillment", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });
    mockApiPost.mockImplementation((url) => {
      if (url === "/billing/checkout/reconcile-recent") {
        return Promise.resolve({
          data: {
            status: "partial",
            sessions_matched: 1,
            sessions_reconciled: 0,
            units_credited: 0,
            sessions: [
              {
                session_id: "cs_untrusted_001",
                status: "failed",
                error: "Checkout session integrity verification failed.",
              },
            ],
            truncated: false,
          },
        });
      }
      if (url === "/events/simulate") {
        return Promise.resolve({ data: {} });
      }
      return Promise.resolve({ data: {} });
    });

    await renderDashboard();
    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        "Payment sync is incomplete. Checkout session integrity verification failed.",
      );
    });
    expect(mockToastSuccess).not.toHaveBeenCalled();
  });

  it("does not report success when Stripe finds no paid checkout", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

    await renderDashboard();
    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        expect.stringContaining("No paid checkout was found"),
      );
    });
  });

  it("starts the live polling interval and posts to /events/simulate", async () => {
    await renderDashboard();

    await act(async () => {
      jest.advanceTimersByTime(20000);
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith(
        "/events/simulate",
        expect.objectContaining({
          event_type: "prompt_injection",
          organization_id: "org-abc",
        }),
      );
    });
  });

  it("starts the refresh interval and re-fetches /dashboard after 5 minutes", async () => {
    await renderDashboard();

    const dashboardCallsBefore = mockApiGet.mock.calls.filter(
      ([url]) => url === "/dashboard/overview",
    ).length;

    await act(async () => {
      jest.advanceTimersByTime(5 * 60 * 1000);
    });

    await waitFor(() => {
      const dashboardCallsAfter = mockApiGet.mock.calls.filter(
        ([url]) => url === "/dashboard/overview",
      ).length;
      expect(dashboardCallsAfter).toBeGreaterThan(dashboardCallsBefore);
    });
  });
});
