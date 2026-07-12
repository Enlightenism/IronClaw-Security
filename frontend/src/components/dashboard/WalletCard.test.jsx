/**
 * frontend/src/components/dashboard/WalletCard.test.jsx
 *
 * Full test harness for WalletCard.jsx.
 * Runner: Jest + @testing-library/react + @testing-library/jest-dom
 */

import React from "react";
import { render, screen, waitFor, cleanup, act } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import WalletCard from "@/components/dashboard/WalletCard";

// ── api mock ──────────────────────────────────────────────────────────────────
const mockApiGet = jest.fn();
const mockApiPatch = jest.fn();
const mockApiDelete = jest.fn();

jest.mock("@/lib/api", () => ({
  __esModule: true,
  default: {
    get: (...args) => mockApiGet(...args),
    patch: (...args) => mockApiPatch(...args),
    delete: (...args) => mockApiDelete(...args),
  },
}));

// ── useCountUp mock — returns raw value so output is predictable ──────────────
jest.mock("@/hooks/useCountUp", () => ({
  useCountUp: (value) => value,
}));

// ── sonner mock ───────────────────────────────────────────────────────────────
const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();

jest.mock("sonner", () => ({
  toast: {
    success: (...args) => mockToastSuccess(...args),
    error: (...args) => mockToastError(...args),
  },
}));

const EMPTY_METHODS_RESPONSE = {
  data: { status: "ok", methods: [], defaultmethodid: null },
};

const TWO_METHODS_RESPONSE = {
  data: {
    status: "ok",
    defaultmethodid: "pm_default",
    methods: [
      {
        methodid: "pm_default",
        brand: "Visa",
        brand_display: "Visa",
        last4: "4242",
        expmonth: 12,
        expyear: 2028,
        exp_display: "12/2028",
        status: "active",
      },
      {
        methodid: "pm_other",
        brand: "Mastercard",
        brand_display: "Mastercard",
        last4: "1234",
        expmonth: 6,
        expyear: 2027,
        exp_display: "6/2027",
        status: "active",
      },
    ],
  },
};

const DEFAULT_PROPS = {
  balance: 500,
  lastPayment: null,
  hasPaid: false,
  onPurchase: jest.fn(),
  purchasingId: null,
  organizationId: "org-001",
};

const ORIGINAL_ENV = process.env;

function setupEmptyMethods() {
  mockApiGet.mockResolvedValue(EMPTY_METHODS_RESPONSE);
}

function setupTwoMethods() {
  mockApiGet.mockResolvedValue(TWO_METHODS_RESPONSE);
}

async function renderWalletCard(props = {}) {
  let view;
  await act(async () => {
    view = render(<WalletCard {...DEFAULT_PROPS} {...props} />);
  });
  return view;
}

beforeEach(() => {
  jest.clearAllMocks();
  cleanup();
  process.env = {
    ...ORIGINAL_ENV,
    REACT_APP_STRIPE_PUBLISHABLE_KEY: "pk_test_abc123",
  };
  setupEmptyMethods();
});

afterEach(() => {
  cleanup();
  process.env = ORIGINAL_ENV;
});

// =============================================================================
// WalletCard — NO Stripe key
// =============================================================================

describe("WalletCard — no Stripe key", () => {
  beforeEach(() => {
    delete process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY;
  });

  it("renders data-testid='wallet-card' without crashing", async () => {
    await renderWalletCard();
    expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
  });

  it("does not render StripeKeyWarning with REACT_APP_STRIPE_PUBLISHABLE_KEY text", async () => {
    await renderWalletCard();
    expect(
      screen.queryByText(/REACT_APP_STRIPE_PUBLISHABLE_KEY/),
    ).not.toBeInTheDocument();
  });

  it("all three purchase buttons remain enabled", async () => {
    await renderWalletCard();
    expect(screen.getByTestId("purchase-pkg_5000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).not.toBeDisabled();
  });

  it("StripeModeTag still renders Stripe test and not Stripe live", async () => {
    await renderWalletCard();
    expect(screen.getByText(/Stripe test/i)).toBeInTheDocument();
    expect(screen.queryByText(/Stripe live/i)).not.toBeInTheDocument();
  });
});

// =============================================================================
// WalletCard — test key present (pk_test_...)
// =============================================================================

describe("WalletCard — test Stripe key", () => {
  beforeEach(() => {
    process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY = "pk_test_abc123";
  });

  it("StripeKeyWarning is not in the DOM", async () => {
    await renderWalletCard();
    expect(
      screen.queryByText(/REACT_APP_STRIPE_PUBLISHABLE_KEY/),
    ).not.toBeInTheDocument();
  });

  it("StripeModeTag renders with text 'Stripe test'", async () => {
    await renderWalletCard();
    expect(screen.getByText(/Stripe test/i)).toBeInTheDocument();
  });

  it("all three purchase buttons are enabled when purchasingId is null", async () => {
    await renderWalletCard({ purchasingId: null });
    expect(screen.getByTestId("purchase-pkg_5000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).not.toBeDisabled();
  });

  it("purchase buttons are disabled when purchasingId is set to a tier ID", async () => {
    await renderWalletCard({ purchasingId: "pkg_5000" });
    expect(screen.getByTestId("purchase-pkg_5000")).toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).toBeDisabled();
  });
});

// =============================================================================
// WalletCard — live key present (pk_live_...)
// =============================================================================

describe("WalletCard — live Stripe key", () => {
  beforeEach(() => {
    process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY = "pk_live_xyz789";
  });

  it("still renders the current Stripe test tag", async () => {
    await renderWalletCard();
    expect(screen.getByText(/Stripe test/i)).toBeInTheDocument();
  });
});

// =============================================================================
// Balance display
// =============================================================================

describe("balance display", () => {
  it("data-testid='wallet-balance' renders the formatted balance", async () => {
    await renderWalletCard({ balance: 12500 });
    expect(screen.getByTestId("wallet-balance")).toHaveTextContent(
      (12500).toLocaleString(),
    );
  });

  it("balance of 0 renders '0' without throwing", async () => {
    await renderWalletCard({ balance: 0 });
    expect(screen.getByTestId("wallet-balance")).toHaveTextContent("0");
  });
});

// =============================================================================
// Tier purchase buttons
// =============================================================================

describe("tier purchase buttons", () => {
  it("clicking purchase-pkg_5000 calls onPurchase with exactly 'pkg_5000'", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase });

    await user.click(screen.getByTestId("purchase-pkg_5000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_5000");
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("clicking purchase-pkg_25000 calls onPurchase with exactly 'pkg_25000'", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase });

    await user.click(screen.getByTestId("purchase-pkg_25000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_25000");
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("clicking purchase-pkg_60000 calls onPurchase with exactly 'pkg_60000'", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase });

    await user.click(screen.getByTestId("purchase-pkg_60000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_60000");
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("does not throw when onPurchase prop is omitted", async () => {
    const user = userEvent.setup();

    await renderWalletCard({ onPurchase: undefined });

    await expect(
      user.click(screen.getByTestId("purchase-pkg_5000")),
    ).resolves.toBeUndefined();
  });
});

// =============================================================================
// Last payment display
// =============================================================================

describe("last payment display", () => {
  it("renders last purchase block with label and formatted amount when hasPaid=true", async () => {
    await renderWalletCard({
      hasPaid: true,
      lastPayment: { label: "Team", amount: 90 },
    });

    expect(screen.getByText(/Last purchase:/i)).toBeInTheDocument();
    expect(screen.getByText(/\$90\.00/)).toBeInTheDocument();
  });

  it("does not render last purchase block when hasPaid=false", async () => {
    await renderWalletCard({
      hasPaid: false,
      lastPayment: { label: "Team", amount: 90 },
    });

    expect(screen.queryByText(/Last purchase/i)).not.toBeInTheDocument();
  });

  it("does not render last purchase block when lastPayment is null", async () => {
    await renderWalletCard({
      hasPaid: true,
      lastPayment: null,
    });

    expect(screen.queryByText(/Last purchase/i)).not.toBeInTheDocument();
  });
});

// =============================================================================
// Payment method panel — stable current behavior
// =============================================================================

describe("Payment method panel — stable current behavior", () => {
  it("renders the saved payment method section", async () => {
    await renderWalletCard();
    expect(screen.getByTestId("saved-payment-method")).toBeInTheDocument();
  });

  it("renders the current empty-state copy", async () => {
    await renderWalletCard({ organizationId: "org-001" });

    await waitFor(() => {
      expect(
        screen.getByText(/No payment method on file yet/i),
      ).toBeInTheDocument();
      expect(
        screen.getByText(/Complete a purchase to securely save one with Stripe/i),
      ).toBeInTheDocument();
    });
  });

  it("renders the Stripe test mode tag in the payment method panel", async () => {
    await renderWalletCard();
    expect(screen.getByText(/Stripe test/i)).toBeInTheDocument();
  });

  it("does not render loading copy from the old implementation", async () => {
    await renderWalletCard();
    expect(screen.queryByText(/Loading saved methods/i)).not.toBeInTheDocument();
  });

  it("does not render old payment-method-row test ids from the removed implementation", async () => {
    setupTwoMethods();
    await renderWalletCard();

    expect(
      screen.queryByTestId("payment-method-row-pm_default"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("payment-method-row-pm_other"),
    ).not.toBeInTheDocument();
  });

  it("does not render old set-default or delete controls from the removed implementation", async () => {
    setupTwoMethods();
    await renderWalletCard();

    expect(screen.queryByTestId("set-default-pm_other")).not.toBeInTheDocument();
    expect(screen.queryByTestId("delete-method-pm_other")).not.toBeInTheDocument();
    expect(screen.queryByTestId("delete-method-pm_default")).not.toBeInTheDocument();
  });

  it("does not render add-new-card-btn from the old implementation", async () => {
    setupTwoMethods();
    await renderWalletCard();
    expect(screen.queryByTestId("add-new-card-btn")).not.toBeInTheDocument();
  });

  it("does not require api.get to be called on render for the current implementation", async () => {
    await renderWalletCard({ organizationId: "org-001" });

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });

    expect(mockApiGet).not.toHaveBeenCalled();
  });
});

// =============================================================================
// api.get silent failure
// =============================================================================

describe("api.get silent failure", () => {
  beforeEach(() => {
    mockApiGet.mockRejectedValue(new Error("Network error"));
  });

  it("does not throw and component stays mounted", async () => {
    await renderWalletCard();

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });
  });

  it("does not call toast on api.get failure", async () => {
    await renderWalletCard();

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });

    expect(mockToastSuccess).not.toHaveBeenCalled();
    expect(mockToastError).not.toHaveBeenCalled();
  });
});
