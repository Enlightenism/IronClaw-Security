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

// â”€â”€ react-router-dom mock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ AuthContext mock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ api mock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const mockApiGet = jest.fn();
const mockApiPost = jest.fn();

jest.mock("@/lib/api", () => ({
  __esModule: true,
  default: {
    get: (...args) => mockApiGet(...args),
    post: (...args) => mockApiPost(...args),
  },
}));

// â”€â”€ sonner mock â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
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

// â”€â”€ WalletCard mock â€” captures props â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let capturedWalletProps = null;

jest.mock("@/components/dashboard/WalletCard", () => ({
  __esModule: true,
  default: (props) => {
    capturedWalletProps = props;
    return <div data-testid="wallet-card">WalletCard</div>;
  },
}));

// â”€â”€ SecurityAnalysis stub â€” captures props â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
let capturedSecurityProps = null;

jest.mock("@/components/dashboard/SecurityAnalysis", () => ({
  __esModule: true,
  default: (props) => {
    capturedSecurityProps = props;
    return <div data-testid="security-analysis">SecurityAnalysis</div>;
  },
}));

// â”€â”€ IntegrationCard stub â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
jest.mock("@/components/dashboard/IntegrationCard", () => ({
  __esModule: true,
  default: ({ title, command, testid }) => (
    <div data-testid={testid || `integration-card-${title}`}>
      <div>{title}</div>
      {command ? (
        <>
          <div data-testid={`${testid}-value`}>{command}</div>
          <button type="button" data-testid={`${testid}-copy`}>
            Copy
          </button>
        </>
      ) : null}
    </div>
  ),
}));

// â”€â”€ Module under test â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
import Dashboard from "./Dashboard";

// â”€â”€ Default API responses â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
const DEFAULT_DASH = {
  wallet_units: 100,
  organization_id: "org-abc",
  last_payment: null,
  has_paid: false,
  units_today: 0,
  units_week: 0,
  daily_usage: [],
  attacks: [],
};

const DEFAULT_TOKENS = {
  status: "ok",
  claude_code_command:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...abcd",
  openclaw_command:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user --key ic_install_openclaw_...abcd",
  cursor_command:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user --key ic_install_cursor_...ijkl",
  goose_command:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user --key ic_install_goose_...mnop",
  gemini_cli_command:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user --key ic_install_gemini_cli_...qrst",
  copilot_command:
    "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user --key ic_install_copilot_...uvwx",
  hermes_command:
    "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_...abcd",
};

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
    if (url === "/integrations/token") {
      return Promise.resolve({ data: DEFAULT_TOKENS });
    }
    return Promise.reject(new Error(`Unexpected GET ${url}`));
  });

  mockApiPost.mockImplementation((url) => {
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

// â”€â”€ Setup / teardown â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
beforeEach(() => {
  jest.clearAllMocks();
  cleanup();
  capturedWalletProps = null;
  capturedSecurityProps = null;
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

describe("WalletCard organizationId prop", () => {
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
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.organizationId).toBe("org-abc");
  });

  it("passes organizationId='org-001' fallback when API response has no organization_id", async () => {
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
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.organizationId).toBe("org-001");
  });

  it("passes organizationId='org-001' fallback when organization_id is null", async () => {
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
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.organizationId).toBe("org-001");
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
      if (url === "/billing/checkout/sessions/cs_test_pending") {
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

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      if (url === "/billing/checkout/sessions/cs_test_abc") {
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    expect(mockToastLoading).toHaveBeenCalledWith(
      expect.stringContaining("Verifying"),
      expect.objectContaining({ id: "pay" }),
    );
    expect(mockNavigate).toHaveBeenCalledWith("/dashboard", { replace: true });
  });

  it("fires toast.success with unit count when payment_status is paid", async () => {
    mockLocation.search = "?session_id=cs_test_abc&package_id=pkg_5000";

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      if (url === "/billing/checkout/sessions/cs_test_abc") {
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith(
        expect.stringContaining("5,000"),
      );
    });
  });

  it("dismisses the pay toast before showing success", async () => {
    mockLocation.search = "?session_id=cs_test_abc&package_id=pkg_5000";

    mockApiGet.mockImplementation((url) => {
      if (url === "/billing/checkout/sessions/cs_test_abc") {
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
      }
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(mockToastDismiss).toHaveBeenCalledWith("pay");
    });
  });
});

// =============================================================================
// handlePurchase â€” invalid package guard
// =============================================================================

describe("handlePurchase â€” invalid package", () => {
  it("calls toast.error for an unknown package ID", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_invalid");
    });

    expect(mockToastError).toHaveBeenCalledWith(
      expect.stringContaining("Invalid"),
    );
  });

  it("does NOT call api.post for an unknown package ID", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    const postCallsBefore = mockApiPost.mock.calls.length;

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_invalid");
    });

    expect(mockApiPost.mock.calls.length).toBe(postCallsBefore);
  });
});

// =============================================================================
// handlePurchase â€” valid package
// =============================================================================

describe("handlePurchase â€” valid package", () => {
  it("calls api.post /billing/checkout/sessions with the current request shape used by Dashboard", async () => {
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
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_5000");
    });

    expect(mockApiPost).toHaveBeenCalledWith("/billing/checkout/sessions", {
      packageId: "pkg5000",
      successUrl:
        "http://localhost/dashboard?checkout=success&package_id=pkg5000",
      cancelUrl:
        "http://localhost/dashboard?checkout=cancel&package_id=pkg5000",
      organizationId: "org-abc",
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
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_5000");
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
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_25000");
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
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_60000");
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
      capturedWalletProps = null;
      capturedSecurityProps = null;
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
        expect(capturedWalletProps).not.toBeNull();
      });

      await act(async () => {
        await capturedWalletProps.onPurchase(pkgId);
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
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_5000");
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
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_5000");
    });

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        expect.stringContaining("Missing checkout URL"),
      );
    });
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
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.balance).toBe(9999);
  });

  it("keeps runtime command cards hidden until a valid unlocked token is available", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: { status: "locked" } });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.queryByTestId("claude-code-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("openclaw-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("cursor-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("goose-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("gemini_cli-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("copilot-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("hermes-card")).not.toBeInTheDocument();
      expect(
        screen.queryByTestId("security_guardian-card"),
      ).not.toBeInTheDocument();
    });
  });

  it("hides keyless runtime commands even when a valid install key exists", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [
              {
                program: "claude_code",
                status: "active",
                masked_key: "ic_install_claude_code_...abcd",
                metadata: {},
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
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.queryByTestId("claude-code-card")).not.toBeInTheDocument();
      expect(
        screen.queryByText("ic_install_claude_code_...abcd"),
      ).not.toBeInTheDocument();
    });
  });

  it("rejects placeholder and generic token payloads instead of rendering a command card", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            claude_code_command:
              "gh auth login --token placeholder",
            goose_command:
              "export IRONCLAW_API_KEY=demo-token",
            hermes_command:
              "hermes skills install https://example.com --name ironclaw-security --key placeholder",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.queryByTestId("claude-code-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("goose-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("hermes-card")).not.toBeInTheDocument();
      expect(screen.queryByText("placeholder")).not.toBeInTheDocument();
      expect(screen.queryByText("demo-token")).not.toBeInTheDocument();
    });
  });

  it("uses the current owner-scoped install_keys to map runtime cards and commands", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            owner_key: "org-abc",
            metadata: { owner_key: "org-abc" },
            install_keys: [
              {
                program: "hermes",
                owner_key: "org-abc",
                status: "active",
                masked_key: "ic_install_hermes_...abcd",
                metadata: {},
              },
              {
                program: "security_guardian",
                owner_key: "org-abc",
                status: "active",
                masked_key: "ic_install_security_guardian_...shared",
                metadata: {},
              },
              {
                program: "claude_code",
                owner_key: "other-owner",
                status: "active",
                masked_key: "ic_install_claude_code_...foreign",
                metadata: {},
              },
            ],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            hermes_command:
              "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_...abcd",
            claude_code_command:
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...foreign",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("hermes-card")).toBeInTheDocument();
      expect(screen.getAllByText("Hermes").length).toBeGreaterThan(0);
      expect(
        screen.queryByTestId("security_guardian-card"),
      ).not.toBeInTheDocument();
      expect(screen.queryByTestId("claude-code-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("openclaw-card")).not.toBeInTheDocument();
    });

    expect(screen.getByTestId("hermes-card")).toHaveTextContent("Hermes");
  });

  it("prefers the current owner's active runtime key over stale duplicate entries", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            owner_key: "org-abc",
            metadata: { owner_key: "org-abc" },
            install_keys: [
              {
                program: "claude_code",
                owner_key: "other-owner",
                status: "active",
                masked_key: "ic_install_claude_code_...foreign",
                metadata: {},
              },
              {
                program: "claude_code",
                owner_key: "org-abc",
                status: "locked",
                masked_key: "",
                metadata: {
                  placeholder: "Keys will be generated after purchase",
                },
              },
              {
                program: "claude_code",
                owner_key: "org-abc",
                status: "active",
                masked_key: "ic_install_claude_code_...current",
                metadata: {},
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
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...current",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
      expect(screen.getByTestId("claude-code-card")).toHaveTextContent(
        "gh skill install",
      );
      expect(screen.getByTestId("claude-code-card-copy")).toBeInTheDocument();
    });
  });

  it("renders a copyable command card for a generated Hermes install key", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [
              {
                program: "hermes",
                status: "active",
                masked_key: "ic_install_hermes_...abcd",
                metadata: {},
              },
            ],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            hermes_command:
              "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_...abcd",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("hermes-card")).toBeInTheDocument();
      expect(screen.getByTestId("hermes-card")).toHaveTextContent(
        "hermes skills install",
      );
    });

    expect(screen.getByTestId("hermes-card-copy")).toBeInTheDocument();
  });

  it("renders the command card without exposing the embedded install key value", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [
              {
                program: "claude_code",
                status: "active",
                masked_key: "ic_install_claude_code_...abcd",
                metadata: {},
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
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...abcd",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
      expect(screen.getByTestId("claude-code-card")).toHaveTextContent(
        "gh skill install",
      );
      expect(
        screen.queryByText("ic_install_claude_code_...abcd"),
      ).not.toBeInTheDocument();
    });

    expect(
      screen.queryByText("REACT_APP_IRONCLAW_API_KEY"),
    ).not.toBeInTheDocument();
  });

  it("renders canonical runtime labels and excludes Security Guardian as a platform", async () => {
    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
      expect(screen.getByTestId("openclaw-card")).toBeInTheDocument();
      expect(screen.getByTestId("cursor-card")).toBeInTheDocument();
      expect(screen.getByTestId("goose-card")).toBeInTheDocument();
      expect(screen.getByTestId("gemini_cli-card")).toBeInTheDocument();
      expect(screen.getByTestId("copilot-card")).toBeInTheDocument();
      expect(screen.getByTestId("hermes-card")).toBeInTheDocument();
      expect(
        screen.queryByTestId("security_guardian-card"),
      ).not.toBeInTheDocument();
    });

    expect(screen.getAllByText("GitHub Copilot").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Hermes").length).toBeGreaterThan(0);
    expect(screen.queryAllByText("Hermes Agent").length).toBe(0);
    expect(screen.queryAllByText("Copilot").length).toBe(0);
  });

  it("renders the canonical runtime order with Hermes in the final card slot", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({ data: { ...DEFAULT_DASH, install_keys: [] } });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("openclaw-card")).toBeInTheDocument();
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
      expect(screen.getByTestId("cursor-card")).toBeInTheDocument();
      expect(screen.getByTestId("goose-card")).toBeInTheDocument();
      expect(screen.getByTestId("gemini_cli-card")).toBeInTheDocument();
      expect(screen.getByTestId("copilot-card")).toBeInTheDocument();
      expect(screen.getByTestId("hermes-card")).toBeInTheDocument();
    });

    expect(
      screen.queryByTestId("security_guardian-card"),
    ).not.toBeInTheDocument();
  });

  it("shows masked keys only for active runtime slots and keeps locked slots in placeholder state", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [
              {
                program: "claude_code",
                status: "active",
                masked_key: "ic_install_claude_code_...abcd",
                metadata: {
                  placeholder: "Keys will be generated after purchase",
                },
              },
              {
                program: "goose",
                status: "locked",
                masked_key: "",
                metadata: {
                  placeholder: "Keys will be generated after purchase",
                },
              },
              {
                program: "hermes",
                status: "active",
                masked_key: "ic_install_hermes_...efgh",
                metadata: {
                  placeholder: "Keys will be generated after purchase",
                },
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
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...abcd",
            goose_command:
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user --key ic_install_goose_...mnop",
            hermes_command:
              "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_...efgh",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
      expect(screen.getByTestId("hermes-card")).toBeInTheDocument();
      expect(screen.queryByTestId("goose-card")).not.toBeInTheDocument();
      expect(screen.queryByTestId("goose-card-copy")).not.toBeInTheDocument();
    });

    expect(screen.getByTestId("claude-code-card-copy")).toBeInTheDocument();
    expect(screen.getByTestId("hermes-card-copy")).toBeInTheDocument();
  });

  it("keeps the UI consistent across issued, locked, and reactivated runtime states", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard/overview") {
        return Promise.resolve({
          data: {
            ...DEFAULT_DASH,
            install_keys: [
              {
                program: "cursor",
                status: "locked",
                masked_key: "",
                metadata: {
                  placeholder: "Keys will be generated after purchase",
                },
              },
              {
                program: "copilot",
                status: "active",
                masked_key: "ic_install_copilot_...wxyz",
                metadata: { placeholder: "" },
              },
            ],
          },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({
          data: {
            status: "ok",
            cursor_command:
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user --key ic_install_cursor_...ijkl",
            copilot_command:
              "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user --key ic_install_copilot_...uvwx",
          },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await renderDashboard();

    await waitFor(() => {
      expect(screen.queryByTestId("cursor-card")).not.toBeInTheDocument();
      expect(screen.getByTestId("copilot-card")).toBeInTheDocument();
      expect(screen.getByTestId("copilot-card")).toHaveTextContent(
        "gh skill install",
      );
    });

    expect(screen.queryByTestId("cursor-card-copy")).not.toBeInTheDocument();
    expect(screen.getByTestId("copilot-card-copy")).toBeInTheDocument();
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
          data: {
            ...DEFAULT_DASH,
            units_today: 11,
            units_week: 77,
            daily_usage: dailyUsage,
            attacks,
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
      expect(capturedSecurityProps).not.toBeNull();
    });

    expect(capturedSecurityProps.unitsToday).toBe(11);
    expect(capturedSecurityProps.unitsWeek).toBe(77);
    expect(capturedSecurityProps.dailyUsage).toEqual(dailyUsage);
    expect(capturedSecurityProps.attacks).toEqual(attacks);
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
          data: { ...DEFAULT_DASH, attacks },
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
          data: { ...DEFAULT_DASH, attacks },
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
          data: { ...DEFAULT_DASH, attacks },
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
        data: { ...DEFAULT_DASH, attacks: firstAttackSet },
      })
      .mockResolvedValueOnce({ data: DEFAULT_TOKENS })
      .mockResolvedValueOnce({
        data: { ...DEFAULT_DASH, attacks: refreshedAttackSet },
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
