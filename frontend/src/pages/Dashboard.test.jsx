/**
 * frontend/src/pages/Dashboard.test.jsx
 *
 * Test harness for Dashboard.jsx
 * Runner : Jest + @testing-library/react + @testing-library/jest-dom
 */

import React from "react";
import { render, screen, waitFor, act } from "@testing-library/react";
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
let mockAuthState = { user: { email: "test@ironclaw.io" }, loading: false };

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

// ── SecurityAnalysis stub ────────────────────────────────────────────────────
jest.mock("@/components/dashboard/SecurityAnalysis", () => ({
  __esModule: true,
  default: () => <div data-testid="security-analysis">SecurityAnalysis</div>,
}));

// ── IntegrationCard stub ─────────────────────────────────────────────────────
jest.mock("@/components/dashboard/IntegrationCard", () => ({
  __esModule: true,
  default: ({ title }) => (
    <div data-testid={`integration-card-${title}`}>{title}</div>
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

function setupDefaultApis() {
  mockApiGet.mockImplementation((url) => {
    if (url === "/dashboard") return Promise.resolve({ data: DEFAULT_DASH });
    if (url === "/integrations/token")
      return Promise.resolve({ data: DEFAULT_TOKENS });
    return Promise.reject(new Error(`Unexpected GET ${url}`));
  });
  mockApiPost.mockResolvedValue({ data: {} });
}

// ── Setup / teardown ──────────────────────────────────────────────────────────
beforeEach(() => {
  jest.clearAllMocks();
  capturedWalletProps = null;
  mockLocation.search = "";
  mockAuthState = {
    user: { email: "test@ironclaw.io" },
    loading: false,
    logout: mockLogout,
  };
  setupDefaultApis();

  delete window.location;
  window.location = { href: "", origin: "http://localhost" };

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
    // Hang the API so loadingData stays true
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
// WalletCard receives organizationId from API response
// =============================================================================

describe("WalletCard organizationId prop", () => {
  it("passes organizationId from dashboard API response to WalletCard", async () => {
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard")
        return Promise.resolve({
          data: { ...DEFAULT_DASH, organization_id: "org-abc" },
        });
      if (url === "/integrations/token")
        return Promise.resolve({ data: DEFAULT_TOKENS });
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
    const { organization_id: _removed, ...dashWithoutOrg } = DEFAULT_DASH;
    mockApiGet.mockImplementation((url) => {
      if (url === "/dashboard")
        return Promise.resolve({ data: dashWithoutOrg });
      if (url === "/integrations/token")
        return Promise.resolve({ data: DEFAULT_TOKENS });
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
      if (url === "/dashboard")
        return Promise.resolve({
          data: { ...DEFAULT_DASH, organization_id: null },
        });
      if (url === "/integrations/token")
        return Promise.resolve({ data: DEFAULT_TOKENS });
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
      if (url === "/dashboard")
        return Promise.resolve({ data: DEFAULT_DASH });
      if (url === "/integrations/token")
        return Promise.resolve({ data: DEFAULT_TOKENS });
      if (url === "/payments/status/cs_test_abc")
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
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
      if (url === "/dashboard")
        return Promise.resolve({ data: DEFAULT_DASH });
      if (url === "/integrations/token")
        return Promise.resolve({ data: DEFAULT_TOKENS });
      if (url === "/payments/status/cs_test_abc")
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
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
      if (url === "/payments/status/cs_test_abc")
        return Promise.resolve({
          data: { payment_status: "paid", units: 5000 },
        });
      return Promise.resolve({ data: DEFAULT_DASH });
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
      capturedWalletProps.onPurchase("pkg_invalid");
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
      capturedWalletProps.onPurchase("pkg_invalid");
    });

    expect(mockApiPost.mock.calls.length).toBe(postCallsBefore);
  });
});

// =============================================================================
// handlePurchase — valid package
// =============================================================================

describe("handlePurchase — valid package", () => {
  it("calls api.post /payments/create-checkout with the package ID", async () => {
    mockApiPost.mockResolvedValueOnce({
      data: { url: "https://checkout.stripe.com/pay/cs_test_xyz" },
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      capturedWalletProps.onPurchase("pkg_5000");
    });

    expect(mockApiPost).toHaveBeenCalledWith(
      "/payments/create-checkout",
      expect.objectContaining({ package_id: "pkg_5000" }),
    );
  });

  it("sets window.location.href to the Stripe checkout URL on success", async () => {
    const checkoutUrl = "https://checkout.stripe.com/pay/cs_test_xyz";
    mockApiPost.mockResolvedValueOnce({ data: { url: checkoutUrl } });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      capturedWalletProps.onPurchase("pkg_5000");
    });

    await waitFor(() => {
      expect(window.location.href).toBe(checkoutUrl);
    });
  });

  it("accepts all three valid package IDs without toast.error", async () => {
    const validIds = ["pkg_5000", "pkg_25000", "pkg_60000"];

    for (const pkgId of validIds) {
      jest.clearAllMocks();
      setupDefaultApis();
      mockApiPost.mockResolvedValueOnce({
        data: { url: "https://checkout.stripe.com/pay/x" },
      });

      await act(async () => {
        render(<Dashboard />);
      });

      await waitFor(() => {
        expect(capturedWalletProps).not.toBeNull();
      });

      await act(async () => {
        capturedWalletProps.onPurchase(pkgId);
      });

      expect(mockToastError).not.toHaveBeenCalled();
    }
  });

  it("calls toast.error when api.post rejects", async () => {
    mockApiPost.mockRejectedValueOnce({
      response: { data: { detail: "Checkout failed" } },
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    await act(async () => {
      capturedWalletProps.onPurchase("pkg_5000");
    });

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        expect.stringContaining("Checkout failed"),
      );
    });
  });
});

// =============================================================================
// Sign out
// =============================================================================

describe("sign out", () => {
  it("calls logout() when Sign Out is clicked", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("signout-btn")).toBeInTheDocument();
    });

    await userEvent.click(screen.getByTestId("signout-btn"));

    expect(mockLogout).toHaveBeenCalledTimes(1);
  });

  it("calls navigate('/') when Sign Out is clicked", async () => {
    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(screen.getByTestId("signout-btn")).toBeInTheDocument();
    });

    await userEvent.click(screen.getByTestId("signout-btn"));

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
      if (url === "/dashboard")
        return Promise.resolve({
          data: { ...DEFAULT_DASH, wallet_units: 9999 },
        });
      return Promise.resolve({ data: DEFAULT_TOKENS });
    });

    await act(async () => {
      render(<Dashboard />);
    });

    await waitFor(() => {
      expect(capturedWalletProps).not.toBeNull();
    });

    expect(capturedWalletProps.balance).toBe(9999);
  });
});
