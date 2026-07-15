/**
 * frontend/src/pages/Dashboard.test.jsx
 *
 * Test harness for Dashboard.jsx
 * Runner: Jest + @testing-library/react + @testing-library/jest-dom
 */

import React from "react";
import {
  act,
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";

// ── react-router-dom mock ─────────────────────────────────────────────────────
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

// ── AuthContext mock ──────────────────────────────────────────────────────────
const mockLogout = jest.fn();
let mockAuthState = {
  user: { email: "test@ironclaw.io" },
  loading: false,
  logout: mockLogout,
};

jest.mock("@/context/AuthContext", () => ({
  useAuth: () => mockAuthState,
}));

// ── api mock ──────────────────────────────────────────────────────────────────
const mockApiGet = jest.fn();
const mockApiPost = jest.fn();

jest.mock("@/lib/api", () => ({
  __esModule: true,
  default: {
    get: (...args) => mockApiGet(...args),
    post: (...args) => mockApiPost(...args),
  },
}));

// ── sonner mock ───────────────────────────────────────────────────────────────
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

// ── WalletCard mock — captures props ─────────────────────────────────────────
let capturedWalletProps = null;

jest.mock("@/components/dashboard/WalletCard", () => ({
  __esModule: true,
  default: (props) => {
    capturedWalletProps = props;
    return <div data-testid="wallet-card">WalletCard</div>;
  },
}));

// ── SecurityAnalysis stub — captures props ───────────────────────────────────
let capturedSecurityProps = null;

jest.mock("@/components/dashboard/SecurityAnalysis", () => ({
  __esModule: true,
  default: (props) => {
    capturedSecurityProps = props;
    return <div data-testid="security-analysis">SecurityAnalysis</div>;
  },
}));

// ── IntegrationCard stub ─────────────────────────────────────────────────────
jest.mock("@/components/dashboard/IntegrationCard", () => ({
  __esModule: true,
  default: ({ title, testid }) => (
    <div data-testid={testid || `integration-card-${title}`}>{title}</div>
  ),
}));

// ── Module under test ─────────────────────────────────────────────────────────
import Dashboard from "@/pages/Dashboard";

// ── Default API responses ─────────────────────────────────────────────────────
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
  claude_code_command: "ironclaw --token abc",
  openclaw_command: "openclaw --token xyz",
};

const DEFAULT_PRICE_IDS = {
  REACT_APP_STRIPE_PRICE_ID_PKG_5000: "price_test_5000",
  REACT_APP_STRIPE_PRICE_ID_PKG_25000: "price_test_25000",
  REACT_APP_STRIPE_PRICE_ID_PKG_60000: "price_test_60000",
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
    if (url === "/dashboard") {
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

function setPriceIdEnv(overrides = {}) {
  process.env.REACT_APP_STRIPE_PRICE_ID_PKG_5000 =
    overrides.REACT_APP_STRIPE_PRICE_ID_PKG_5000 ??
    DEFAULT_PRICE_IDS.REACT_APP_STRIPE_PRICE_ID_PKG_5000;
  process.env.REACT_APP_STRIPE_PRICE_ID_PKG_25000 =
    overrides.REACT_APP_STRIPE_PRICE_ID_PKG_25000 ??
    DEFAULT_PRICE_IDS.REACT_APP_STRIPE_PRICE_ID_PKG_25000;
  process.env.REACT_APP_STRIPE_PRICE_ID_PKG_60000 =
    overrides.REACT_APP_STRIPE_PRICE_ID_PKG_60000 ??
    DEFAULT_PRICE_IDS.REACT_APP_STRIPE_PRICE_ID_PKG_60000;
}

function resetWindowLocation() {
  delete window.location;
  window.location = {
    href: "",
    origin: "http://localhost",
    assign: jest.fn((url) => {
      window.location.href = url;
    }),
  };
}

// ── Setup / teardown ──────────────────────────────────────────────────────────
beforeEach(() => {
  jest.clearAllMocks();
  cleanup();
  capturedWalletProps = null;
  capturedSecurityProps = null;
  mockLocation.search = "";
  mockAuthState = {
    user: { email: "test@ironclaw.io" },
    loading: false,
    logout: mockLogout,
  };
  setPriceIdEnv();
  setupDefaultApis();
  resetWindowLocation();
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
});

// =============================================================================
// Auth redirect
// =============================================================================

describe("auth redirect", () => {
  it("calls navigate('/') when user is null and loading is false", async () => {
    mockAuthState = { user: null, loading: false, logout: mockLogout };

    await act(async () => {
      render(<Dashboard />);
    });

    expect(mockNavigate).toHaveBeenCalledWith("/");
  });

  it("does NOT call navigate('/') when user is present", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

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
    mockAuthState = { user: null, loading: true, logout: mockLogout };

    await act(async () => {
      render(<Dashboard />);
    });

    expect(document.querySelector(".animate-spin")).toBeInTheDocument();
    expect(screen.queryByTestId("wallet-card")).not.toBeInTheDocument();
  });

  it("renders spinner when loadingData is true and data is null", async () => {
    mockApiGet.mockReturnValue(new Promise(() => {}));

    await act(async () => {
      render(<Dashboard />);
    });

    expect(document.querySelector(".animate-spin")).toBeInTheDocument();
    expect(screen.queryByTestId("wallet-card")).not.toBeInTheDocument();
  });

  it("renders dashboard content once data resolves", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

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
      if (url === "/dashboard") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, organization_id: "org-abc" },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.organizationId).toBe("org-abc");
  });

  it("passes organizationId='org-001' fallback when API response has no organization_id", async () => {
    const { organization_id: _unused, ...dashWithoutOrg } = DEFAULT_DASH;

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard") {
        return Promise.resolve({ data: dashWithoutOrg });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.organizationId).toBe("org-001");
  });

  it("passes organizationId='org-001' fallback when organization_id is null", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, organization_id: null },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.organizationId).toBe("org-001");
  });
});

// =============================================================================
// session_id payment poll
// =============================================================================

describe("session_id payment polling", () => {
  it("fires toast.loading and navigates replace on session_id in URL", async () => {
    mockLocation.search = "?session_id=cs_test_abc";

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      if (url === "/payments/status/cs_test_abc") {
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

    expect(mockToastLoading).toHaveBeenCalledWith(
      expect.stringContaining("Verifying"),
      expect.objectContaining({ id: "pay" }),
    );
    expect(mockNavigate).toHaveBeenCalledWith("/dashboard", { replace: true });
  });

  it("fires toast.success with unit count when payment_status is paid", async () => {
    mockLocation.search = "?session_id=cs_test_abc";

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      if (url === "/payments/status/cs_test_abc") {
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(mockToastSuccess).toHaveBeenCalledWith(
        expect.stringContaining("5,000"),
      );
    });
  });

  it("dismisses the pay toast before showing success", async () => {
    mockLocation.search = "?session_id=cs_test_abc";

    mockApiGet.mockImplementation((url) => {
      if (url === "/payments/status/cs_test_abc") {
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
      }
      if (url === "/dashboard") {
        return Promise.resolve({ data: DEFAULT_DASH });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(mockToastDismiss).toHaveBeenCalledWith("pay");
    });
  });
});

// =============================================================================
// handlePurchase — invalid package guard
// =============================================================================

describe("handlePurchase — invalid package", () => {
  it("calls toast.error for an unknown package ID", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

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
    await act(async () => {
      render(<Dashboard />);
    });

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
// handlePurchase — valid package
// =============================================================================

describe("handlePurchase — valid package", () => {
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

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_5000");
    });

    expect(mockApiPost).toHaveBeenCalledWith("/billing/checkout/sessions", {
      price_id: "price_test_5000",
      success_url: "http://localhost/dashboard?checkout=success",
      cancel_url: "http://localhost/dashboard?checkout=cancel",
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

    await act(async () => {
      render(<Dashboard />);
    });

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

  it("shows a checkout error when the response returns checkout_url instead of url", async () => {
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

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_25000");
    });

    await waitFor(() => {
      expect(window.location.assign).not.toHaveBeenCalled();
      expect(window.location.href).toBe("");
      expect(mockToastError).toHaveBeenCalledWith(
        expect.stringContaining("Missing checkout URL"),
      );
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

    await act(async () => {
      render(<Dashboard />);
    });

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
    const validIds = ["pkg_5000", "pkg_25000", "pkg_60000"];

    for (const pkgId of validIds) {
      cleanup();
      jest.clearAllMocks();
      capturedWalletProps = null;
      capturedSecurityProps = null;
      mockLocation.search = "";
      mockAuthState = {
        user: { email: "test@ironclaw.io" },
        loading: false,
        logout: mockLogout,
      };
      setPriceIdEnv();
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

      await act(async () => {
        render(<Dashboard />);
      });

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

    await act(async () => {
      render(<Dashboard />);
    });

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

    await act(async () => {
      render(<Dashboard />);
    });

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

  it("calls toast.error when a valid package has no configured price ID", async () => {
    process.env.REACT_APP_STRIPE_PRICE_ID_PKG_5000 = "";

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      await capturedWalletProps.onPurchase("pkg_5000");
    });

    expect(
      mockApiPost.mock.calls.some(
        ([url]) => url === "/billing/checkout/sessions",
      ),
    ).toBe(false);
    expect(mockToastError).toHaveBeenCalledWith(
      expect.stringContaining("Package price not configured"),
    );
  });
});

// =============================================================================
// Sign out
// =============================================================================

describe("sign out", () => {
  it("calls logout() when Sign Out is clicked", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("signout-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("signout-btn"));

    expect(mockLogout).toHaveBeenCalledTimes(1);
  });

  it("calls navigate('/') when Sign Out is clicked", async () => {
    const user = userEvent.setup({ advanceTimers: jest.advanceTimersByTime });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("signout-btn")).toBeInTheDocument();
    });

    await user.click(screen.getByTestId("signout-btn"));

    expect(mockNavigate).toHaveBeenCalledWith("/");
  });
});

// =============================================================================
// Dashboard renders core structure
// =============================================================================

describe("dashboard structure", () => {
  it("renders WalletCard after data loads", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });
  });

  it("renders SecurityAnalysis after data loads", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("security-analysis")).toBeInTheDocument();
    });
  });

  it("renders user email in nav", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("user-email")).toHaveTextContent(
        "test@ironclaw.io",
      );
    });
  });

  it("passes balance from wallet_units to WalletCard", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, wallet_units: 9999 },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.balance).toBe(9999);
  });

  it("renders integration cards after data loads", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("claude-code-card")).toBeInTheDocument();
      expect(screen.getByTestId("openclaw-card")).toBeInTheDocument();
    });
  });

  it("passes attack and usage data to SecurityAnalysis", async () => {
    const attacks = [makeAttack(1), makeAttack(2)];
    const dailyUsage = [
      { day: "Mon", units: 10 },
      { day: "Tue", units: 20 },
    ];

    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard") {
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

    await act(async () => {
      render(<Dashboard />);
    });

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
    await act(async () => {
      render(<Dashboard />);
    });

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
      if (url === "/dashboard") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, attacks },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

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
      if (url === "/dashboard") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, attacks },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

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
      if (url === "/dashboard") {
        return Promise.resolve({
          data: { ...DEFAULT_DASH, attacks },
        });
      }
      if (url === "/integrations/token") {
        return Promise.resolve({ data: DEFAULT_TOKENS });
      }
      return Promise.reject(new Error(`Unexpected GET ${url}`));
    });

    await act(async () => {
      render(<Dashboard />);
    });

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

    await act(async () => {
      render(<Dashboard />);
    });

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

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("refresh-btn")).toBeInTheDocument();
    });

    const dashboardCallsBefore = mockApiGet.mock.calls.filter(
      ([url]) => url === "/dashboard",
    ).length;

    await user.click(screen.getByTestId("refresh-btn"));

    await waitFor(() => {
      const dashboardCallsAfter = mockApiGet.mock.calls.filter(
        ([url]) => url === "/dashboard",
      ).length;
      expect(dashboardCallsAfter).toBeGreaterThan(dashboardCallsBefore);
    });
  });

  it("starts the live polling interval and posts to /events/simulate", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    await act(async () => {
      jest.advanceTimersByTime(20000);
    });

    await waitFor(() => {
      expect(mockApiPost).toHaveBeenCalledWith("/events/simulate");
    });
  });

  it("starts the refresh interval and re-fetches /dashboard after 5 minutes", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    const dashboardCallsBefore = mockApiGet.mock.calls.filter(
      ([url]) => url === "/dashboard",
    ).length;

    await act(async () => {
      jest.advanceTimersByTime(5 * 60 * 1000);
    });

    await waitFor(() => {
      const dashboardCallsAfter = mockApiGet.mock.calls.filter(
        ([url]) => url === "/dashboard",
      ).length;
      expect(dashboardCallsAfter).toBeGreaterThan(dashboardCallsBefore);
    });
  });
});
