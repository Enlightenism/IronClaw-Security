/**
 * frontend/src/components/dashboard/WalletCard.test.jsx
 *
 * Full test harness for WalletCard.jsx.
 * Runner: Jest + @testing-library/react + @testing-library/jest-dom
 */

import React from "react";
import {
  render,
  screen,
  waitFor,
  cleanup,
  act,
  within,
} from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import WalletCard from "@/components/dashboard/WalletCard";

// ── api mock ──────────────────────────────────────────────────────────────────
const mockApiGet = jest.fn();
const mockApiPost = jest.fn();
const mockApiPatch = jest.fn();
const mockApiDelete = jest.fn();

const mockPaymentMethodsList = jest.fn();
const mockPaymentMethodsSetDefault = jest.fn();
const mockPaymentMethodsDelete = jest.fn();

jest.mock("@/lib/api", () => ({
  __esModule: true,
  default: {
    get: (...args) => mockApiGet(...args),
    post: (...args) => mockApiPost(...args),
    patch: (...args) => mockApiPatch(...args),
    delete: (...args) => mockApiDelete(...args),
  },
  paymentMethods: {
    list: (...args) => mockPaymentMethodsList(...args),
    setDefault: (...args) => mockPaymentMethodsSetDefault(...args),
    delete: (...args) => mockPaymentMethodsDelete(...args),
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

let orgCounter = 0;
function uniqueOrgId() {
  orgCounter += 1;
  return `org-test-${orgCounter}`;
}

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

const BILLING_CATALOGUE_RESPONSE = {
  data: {
    packages: {
      starter: {
        package_id: "pkg_5000",
        aliases: ["pkg5000", "starter"],
        label: "Starter",
        units: 5000,
        price_usd: 20,
        tokens_per_unit: 25000,
        token_coverage: 125000000,
        featured: false,
      },
      team: {
        package_id: "pkg_25000",
        aliases: ["pkg25000", "team"],
        label: "Team",
        units: 25000,
        price_usd: 90,
        tokens_per_unit: 25000,
        token_coverage: 625000000,
        featured: true,
      },
      enterprise: {
        package_id: "pkg_60000",
        aliases: ["pkg60000", "enterprise"],
        label: "Enterprise",
        units: 60000,
        price_usd: 180,
        tokens_per_unit: 25000,
        token_coverage: 1500000000,
        featured: false,
      },
    },
  },
};

const DEFAULT_PROPS = {
  balance: 500,
  lastPayment: null,
  walletHistory: [],
  hasPaid: false,
  onPurchase: jest.fn(),
  purchasingId: null,
  onAddPaymentMethod: jest.fn(),
  addingPaymentMethod: false,
  organizationId: "",
};

const ORIGINAL_ENV = process.env;

function setupEmptyMethods() {
  mockPaymentMethodsList.mockResolvedValue(EMPTY_METHODS_RESPONSE);
}

function setupTwoMethods() {
  mockPaymentMethodsList.mockResolvedValue(TWO_METHODS_RESPONSE);
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
  mockApiGet.mockResolvedValue(BILLING_CATALOGUE_RESPONSE);
  setupEmptyMethods();
});

afterEach(() => {
  cleanup();
  process.env = ORIGINAL_ENV;
});

// =============================================================================
// WalletCard — no Stripe key
// =============================================================================

describe("WalletCard — no Stripe key", () => {
  beforeEach(() => {
    process.env = { ...ORIGINAL_ENV };
    delete process.env.REACT_APP_STRIPE_PUBLISHABLE_KEY;
  });

  it("renders data-testid='wallet-card' without crashing", async () => {
    await renderWalletCard({
      organizationId: "",
    });
    expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
  });

  it("renders StripeKeyWarning when no publishable key is set", async () => {
    await renderWalletCard({
      organizationId: "",
    });
    expect(
      screen.getByText(
        /Stripe publishable key is not present in the frontend build/i,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/REACT_APP_STRIPE_PUBLISHABLE_KEY/i),
    ).toBeInTheDocument();
  });

  it("all three purchase buttons remain enabled", async () => {
    await renderWalletCard({
      organizationId: "",
    });
    expect(screen.getByTestId("purchase-pkg_5000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).not.toBeDisabled();
  });

  it("shows Best Deal on the highest-priced package", async () => {
    await renderWalletCard({ organizationId: "" });

    const enterpriseCard =
      screen.getByTestId("purchase-pkg_60000").parentElement;
    const teamCard = screen.getByTestId("purchase-pkg_25000").parentElement;

    expect(within(enterpriseCard).getByText(/Best Deal/i)).toBeInTheDocument();
    expect(within(teamCard).queryByText(/Best Deal/i)).not.toBeInTheDocument();
  });

  it("renders the current no-key runtime behavior", async () => {
    await renderWalletCard({
      organizationId: "",
    });
    expect(
      screen.getByText(
        /Stripe publishable key is not present in the frontend build/i,
      ),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/REACT_APP_STRIPE_PUBLISHABLE_KEY/i),
    ).toBeInTheDocument();
    expect(screen.queryByTitle("Stripe test mode")).not.toBeInTheDocument();
  });
});

// =============================================================================
// WalletCard — current Stripe mode behavior
// =============================================================================

describe("WalletCard — current Stripe mode behavior", () => {
  it("renders Stripe test mode tag when pk_test key is present", async () => {
    await renderWalletCard({
      organizationId: "",
    });
    expect(screen.getByTitle("Stripe test mode")).toBeInTheDocument();
  });

  it("all three purchase buttons are enabled when purchasingId is null", async () => {
    await renderWalletCard({ purchasingId: null, organizationId: "" });
    expect(screen.getByTestId("purchase-pkg_5000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).not.toBeDisabled();
  });

  it("purchase buttons are disabled when purchasingId is set to a tier ID", async () => {
    await renderWalletCard({ purchasingId: "pkg_5000", organizationId: "" });
    expect(screen.getByTestId("purchase-pkg_5000")).toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).toBeDisabled();
  });
});

// =============================================================================
// Balance display
// =============================================================================

describe("balance display", () => {
  it("data-testid='wallet-balance' renders the formatted balance", async () => {
    await renderWalletCard({ balance: 12500, organizationId: "" });
    expect(screen.getByTestId("wallet-balance")).toHaveTextContent(
      (12500).toLocaleString(),
    );
  });

  it("balance of 0 renders '0' without throwing", async () => {
    await renderWalletCard({ balance: 0, organizationId: "" });
    expect(screen.getByTestId("wallet-balance")).toHaveTextContent("0");
  });

  it("renders the units consumed on the front face", async () => {
    await renderWalletCard({
      balance: 12500,
      unitsConsumed: 480,
      organizationId: "",
    });
    expect(screen.getByTestId("wallet-units-consumed")).toHaveTextContent(
      (480).toLocaleString(),
    );
  });

  it("does not claim the wallet is active when health is unavailable", async () => {
    await renderWalletCard({ balance: 12500, organizationId: "" });
    expect(screen.getByTestId("wallet-health")).toHaveTextContent(
      "Status unavailable",
    );
    expect(screen.getByTestId("wallet-health")).toHaveAttribute(
      "data-wallet-status",
      "unavailable",
    );
  });
});

// =============================================================================
// Tier purchase buttons
// =============================================================================

describe("tier purchase buttons", () => {
  it("clicking purchase-pkg_5000 calls onPurchase with the canonical package ID", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });

    await user.click(screen.getByTestId("purchase-pkg_5000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_5000", false);
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("clicking purchase-pkg_25000 calls onPurchase with the canonical package ID", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });

    await openPackage(user, "pkg_25000");
    await user.click(screen.getByTestId("purchase-pkg_25000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_25000", false);
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("clicking purchase-pkg_60000 calls onPurchase with the canonical package ID", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });

    await openPackage(user, "pkg_60000");
    await user.click(screen.getByTestId("purchase-pkg_60000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_60000", false);
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("passes save-card consent only after the user opts in", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });
    await user.click(screen.getByTestId("wallet-flip-toggle"));
    const consent = screen.getByTestId("save-card-consent");
    expect(consent).not.toBeChecked();

    await user.click(consent);
    await user.click(screen.getByTestId("purchase-pkg_5000"));

    expect(onPurchase).toHaveBeenCalledWith("pkg_5000", true);
  });

  it("does not throw when onPurchase prop is omitted", async () => {
    const user = userEvent.setup();

    await renderWalletCard({ onPurchase: undefined, organizationId: "" });

    await expect(
      user.click(screen.getByTestId("purchase-pkg_5000")),
    ).resolves.toBeUndefined();
    expect(mockToastError).toHaveBeenCalledWith(
      "Purchase action is unavailable.",
    );
  });

  it("re-enables purchase buttons when the parent clears a failed checkout", async () => {
    const { rerender } = await renderWalletCard({
      purchasingId: "pkg_5000",
      organizationId: "",
    });

    expect(screen.getByTestId("purchase-pkg_5000")).toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).toBeDisabled();

    await act(async () => {
      rerender(
        <WalletCard {...DEFAULT_PROPS} purchasingId={null} organizationId="" />,
      );
    });

    expect(screen.getByTestId("purchase-pkg_5000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_25000")).not.toBeDisabled();
    expect(screen.getByTestId("purchase-pkg_60000")).not.toBeDisabled();
  });
});

async function openPackage(user, id) {
  for (let attempt = 0; attempt < 4; attempt += 1) {
    if (
      screen.getByTestId(`deck-page-${id}`).getAttribute("data-deck-state") ===
      "top"
    ) {
      return;
    }
    await user.click(screen.getByTestId("wallet-deck-tab"));
  }
  throw new Error(`${id} did not reach the top of the package deck.`);
}

describe("wallet package deck", () => {
  it("shows Starter on top with a Next Package tab and hides the other pages", async () => {
    await renderWalletCard({ organizationId: "" });

    expect(screen.getByTestId("deck-page-pkg_5000")).toHaveAttribute(
      "data-deck-state",
      "top",
    );
    expect(screen.getByTestId("deck-page-pkg_5000")).toHaveAttribute(
      "aria-hidden",
      "false",
    );
    expect(screen.getByTestId("deck-page-pkg_25000")).toHaveAttribute(
      "data-deck-state",
      "stacked",
    );
    expect(screen.getByTestId("deck-page-pkg_25000")).toHaveAttribute(
      "aria-hidden",
      "true",
    );
    expect(screen.getByTestId("deck-page-pkg_25000")).toHaveAttribute("inert");
    expect(screen.getAllByTestId("wallet-deck-tab")).toHaveLength(1);
    expect(screen.getByTestId("wallet-deck-tab")).toHaveTextContent(
      "Next Package",
    );
  });

  it("shows the package detail sentence and gold package title on each purchase page", async () => {
    await renderWalletCard({ organizationId: "" });

    expect(screen.getByTestId("deck-page-pkg_5000")).toHaveTextContent(
      "Starter Package",
    );
    expect(screen.getByTestId("package-detail-pkg_5000")).toHaveTextContent(
      "5,000 units = 25,000 tokens per unit = 125,000,000 tokens protected by IronClaw-Security.",
    );
    expect(screen.getByTestId("package-detail-pkg_25000")).toHaveTextContent(
      "25,000 units = 25,000 tokens per unit = 625,000,000 tokens protected by IronClaw-Security.",
    );
    expect(screen.getByTestId("package-detail-pkg_60000")).toHaveTextContent(
      "60,000 units = 25,000 tokens per unit = 1,500,000,000 tokens protected by IronClaw-Security.",
    );
  });

  it("turns forward and back through the deck with direction-aware tab labels", async () => {
    const user = userEvent.setup();
    await renderWalletCard({ organizationId: "" });

    await user.click(screen.getByTestId("wallet-deck-tab"));
    expect(screen.getByTestId("deck-page-pkg_25000")).toHaveAttribute(
      "data-deck-state",
      "top",
    );
    expect(screen.getByTestId("wallet-deck-tab")).toHaveTextContent(
      "Next Package",
    );

    await user.click(screen.getByTestId("wallet-deck-tab"));
    expect(screen.getByTestId("deck-page-pkg_60000")).toHaveAttribute(
      "data-deck-state",
      "top",
    );
    expect(screen.getByTestId("wallet-deck-tab")).toHaveTextContent(
      "Previous Package",
    );

    await user.click(screen.getByTestId("wallet-deck-tab"));
    expect(screen.getByTestId("deck-page-pkg_25000")).toHaveAttribute(
      "data-deck-state",
      "top",
    );
    expect(screen.getByTestId("wallet-deck-tab")).toHaveTextContent(
      "Previous Package",
    );

    await user.click(screen.getByTestId("wallet-deck-tab"));
    expect(screen.getByTestId("deck-page-pkg_5000")).toHaveAttribute(
      "data-deck-state",
      "top",
    );
    expect(screen.getByTestId("wallet-deck-tab")).toHaveTextContent(
      "Next Package",
    );
  });

  it("activates the deck tab from the keyboard", async () => {
    const user = userEvent.setup();
    await renderWalletCard({ organizationId: "" });

    screen.getByTestId("wallet-deck-tab").focus();
    await user.keyboard("{Enter}");

    expect(screen.getByTestId("deck-page-pkg_25000")).toHaveAttribute(
      "data-deck-state",
      "top",
    );
  });

  it("sends the package on top of the deck to the purchase handler", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });
    await openPackage(user, "pkg_60000");
    await user.click(screen.getByTestId("purchase-pkg_60000"));

    expect(onPurchase).toHaveBeenCalledWith("pkg_60000", false);
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
      organizationId: "",
    });

    expect(screen.getByText(/Last purchase:/i)).toBeInTheDocument();
    expect(screen.getByText(/\$90\.00/)).toBeInTheDocument();
  });

  it("does not render last purchase block when hasPaid=false", async () => {
    await renderWalletCard({
      hasPaid: false,
      lastPayment: { label: "Team", amount: 90 },
      organizationId: "",
    });

    expect(screen.queryByText(/Last purchase/i)).not.toBeInTheDocument();
  });

  it("does not render last purchase block when lastPayment is null", async () => {
    await renderWalletCard({
      hasPaid: true,
      lastPayment: null,
      organizationId: "",
    });

    expect(screen.queryByText(/Last purchase/i)).not.toBeInTheDocument();
  });

  it("renders wallet activity returned by the dashboard API", async () => {
    await renderWalletCard({
      walletHistory: [
        {
          entry_type: "credit",
          label: "Starter",
          units: 5000,
          balance_after: 5000,
          created_at: "2026-01-01T00:00:00Z",
        },
      ],
      organizationId: "",
    });

    expect(screen.getByTestId("wallet-history")).toBeInTheDocument();
    expect(
      within(screen.getByTestId("wallet-history")).getByText("Starter"),
    ).toBeInTheDocument();
    expect(screen.getByText("+5,000 units")).toBeInTheDocument();
  });
});

// =============================================================================
// Payment method panel — current behavior
// =============================================================================

describe("Payment method panel — current behavior", () => {
  it("renders the saved payment method section", async () => {
    await renderWalletCard({ organizationId: uniqueOrgId() });
    expect(screen.getByTestId("saved-payment-method")).toBeInTheDocument();
  });

  it("explains that a card can be saved without making a purchase", async () => {
    await renderWalletCard({ organizationId: uniqueOrgId() });

    await waitFor(() => {
      expect(screen.getByText(/No saved card yet/i)).toBeInTheDocument();
      expect(
        screen.getByText(/Add one securely without making a purchase/i),
      ).toBeInTheDocument();
    });
    expect(screen.getByTestId("add-payment-method")).toBeEnabled();
  });

  it("starts the no-charge card setup flow without triggering a package purchase", async () => {
    const user = userEvent.setup();
    const onAddPaymentMethod = jest.fn();
    await renderWalletCard({
      organizationId: uniqueOrgId(),
      onAddPaymentMethod,
    });

    await user.click(screen.getByTestId("add-payment-method"));

    expect(onAddPaymentMethod).toHaveBeenCalledTimes(1);
    expect(DEFAULT_PROPS.onPurchase).not.toHaveBeenCalled();
  });

  it("renders loading copy while payment methods are being fetched", async () => {
    mockPaymentMethodsList.mockImplementation(() => new Promise(() => {}));

    await renderWalletCard({ organizationId: uniqueOrgId() });
    expect(screen.getByText(/Loading saved methods/i)).toBeInTheDocument();
  });

  it("requests payment methods on render when organizationId is present", async () => {
    const orgId = uniqueOrgId();
    await renderWalletCard({ organizationId: orgId });

    await waitFor(() => {
      expect(mockPaymentMethodsList).toHaveBeenCalledWith(orgId);
    });
  });

  it("does not fetch payment methods when organizationId is missing", async () => {
    await renderWalletCard({ organizationId: "" });

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });

    expect(mockPaymentMethodsList).not.toHaveBeenCalled();
  });

  it("renders payment method rows when methods are returned", async () => {
    setupTwoMethods();
    await renderWalletCard({ organizationId: uniqueOrgId() });

    expect(
      await screen.findByTestId("payment-method-row-pm_default"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("payment-method-row-pm_other"),
    ).toBeInTheDocument();
  });

  it("hides raw card numbers and other sensitive payment fields in the dashboard UI", async () => {
    mockPaymentMethodsList.mockResolvedValue({
      data: {
        status: "ok",
        defaultmethodid: "pm_masked",
        methods: [
          {
            methodid: "pm_masked",
            brand: "Visa",
            brand_display: "Visa",
            last4: "4242",
            expmonth: 12,
            expyear: 2029,
            exp_display: "12/29",
            status: "active",
            card: {
              brand: "Visa",
              last4: "4242",
              exp_month: 12,
              exp_year: 2029,
              number: "4242424242424242",
              cvc: "123",
            },
            customer: "cus_test_123",
            payment_method_id: "pm_masked",
            fingerprint: "abc123",
          },
        ],
      },
    });

    await renderWalletCard({ organizationId: uniqueOrgId() });

    const row = await screen.findByTestId("payment-method-row-pm_masked");

    expect(within(row).getByText(/Visa\s+····4242/i)).toBeInTheDocument();
    expect(
      within(row).queryByText(/4242424242424242/i),
    ).not.toBeInTheDocument();
    expect(within(row).queryByText(/cus_test_123/i)).not.toBeInTheDocument();
    expect(within(row).queryByText(/abc123/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/4242424242424242/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/cus_test_123/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/abc123/i)).not.toBeInTheDocument();
  });

  it("renders delete controls for returned methods without a set-default control", async () => {
    setupTwoMethods();
    await renderWalletCard({ organizationId: uniqueOrgId() });

    expect(
      await screen.findByTestId("delete-method-pm_default"),
    ).toBeInTheDocument();
    expect(screen.getByTestId("delete-method-pm_other")).toBeInTheDocument();
    expect(
      screen.queryByTestId("set-default-pm_other"),
    ).not.toBeInTheDocument();
  });

  it("does not show an add-card action that can accidentally start a purchase", async () => {
    setupTwoMethods();
    await renderWalletCard({ organizationId: uniqueOrgId() });

    expect(screen.queryByTestId("add-new-card-btn")).not.toBeInTheDocument();
  });
});

// =============================================================================
// Payment method interactions
// =============================================================================

describe("Payment method interactions", () => {
  it("removes a payment method", async () => {
    const user = userEvent.setup();
    const orgId = uniqueOrgId();
    mockPaymentMethodsDelete.mockResolvedValue({ data: { status: "ok" } });
    mockPaymentMethodsList
      .mockResolvedValueOnce(TWO_METHODS_RESPONSE)
      .mockResolvedValueOnce({
        data: {
          status: "ok",
          defaultmethodid: "pm_default",
          methods: [TWO_METHODS_RESPONSE.data.methods[0]],
        },
      });

    await renderWalletCard({ organizationId: orgId });

    const button = await screen.findByTestId("delete-method-pm_other");
    await user.click(button);

    await waitFor(() => {
      expect(mockPaymentMethodsDelete).toHaveBeenCalledWith("pm_other", orgId);
    });

    expect(mockToastSuccess).toHaveBeenCalledWith("Payment method removed.");
  });

  it("shows the Stripe removal error without retrying through another endpoint", async () => {
    const user = userEvent.setup();
    mockPaymentMethodsDelete.mockRejectedValue({
      response: { data: { detail: "Primary delete failed." } },
    });
    mockPaymentMethodsList.mockResolvedValueOnce(TWO_METHODS_RESPONSE);

    await renderWalletCard({ organizationId: uniqueOrgId() });

    const button = await screen.findByTestId("delete-method-pm_other");
    await user.click(button);

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith("Primary delete failed.");
    });
    expect(mockApiPost).not.toHaveBeenCalled();
  });

  it("shows the nested detail message when removal returns an object detail", async () => {
    const user = userEvent.setup();
    mockPaymentMethodsDelete.mockRejectedValue({
      response: {
        data: {
          detail: {
            error: "detach_error",
            detail: "Stripe could not detach the card.",
            methodid: "pm_other",
          },
        },
      },
    });
    mockPaymentMethodsList.mockResolvedValueOnce(TWO_METHODS_RESPONSE);

    await renderWalletCard({ organizationId: uniqueOrgId() });

    const button = await screen.findByTestId("delete-method-pm_other");
    await user.click(button);

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        "Stripe could not detach the card.",
      );
    });
  });

  it("does not expose a card button that can trigger a paid package checkout", async () => {
    const onPurchase = jest.fn();
    setupTwoMethods();

    await renderWalletCard({ onPurchase, organizationId: uniqueOrgId() });

    expect(screen.queryByTestId("add-new-card-btn")).not.toBeInTheDocument();
    expect(onPurchase).not.toHaveBeenCalled();
  });
});

// =============================================================================
// paymentMethods.list silent failure
// =============================================================================

describe("paymentMethods.list failure", () => {
  beforeEach(() => {
    mockPaymentMethodsList.mockRejectedValue(new Error("Network error"));
  });

  it("does not throw and component stays mounted", async () => {
    await renderWalletCard({ organizationId: uniqueOrgId() });

    await waitFor(() => {
      expect(screen.getByTestId("wallet-card")).toBeInTheDocument();
    });
  });

  it("shows an explicit retrieval error rather than an empty-state message", async () => {
    const user = userEvent.setup();
    await renderWalletCard({ organizationId: uniqueOrgId() });
    await user.click(screen.getByTestId("wallet-flip-toggle"));

    await waitFor(() => {
      expect(screen.getByRole("alert")).toHaveTextContent(
        /Saved payment methods could not be loaded/i,
      );
    });

    expect(
      screen.queryByText(/No payment method on file yet/i),
    ).not.toBeInTheDocument();
    expect(mockToastSuccess).not.toHaveBeenCalled();
  });
});

// =============================================================================
// Wallet flip, package sheen, and saved-method refresh
// =============================================================================

describe("wallet flip and package sheen", () => {
  it("toggles between the balance face and the card face with the keyboard", async () => {
    const user = userEvent.setup();
    await renderWalletCard({ organizationId: "" });

    const toggle = screen.getByTestId("wallet-flip-toggle");
    const front = screen.getByTestId("wallet-front");
    const back = screen.getByTestId("wallet-back");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(front).toHaveAttribute("aria-hidden", "false");
    expect(front).not.toHaveAttribute("inert");
    expect(back).toHaveAttribute("aria-hidden", "true");
    expect(back).toHaveAttribute("inert");

    toggle.focus();
    await user.keyboard("{Enter}");

    expect(toggle).toHaveAttribute("aria-expanded", "true");
    expect(front).toHaveAttribute("aria-hidden", "true");
    expect(front).toHaveAttribute("inert");
    expect(back).toHaveAttribute("aria-hidden", "false");
    expect(back).not.toHaveAttribute("inert");
  });

  it("gives every package button the sheen class", async () => {
    await renderWalletCard({ organizationId: "" });

    for (const id of ["pkg_5000", "pkg_25000", "pkg_60000"]) {
      expect(screen.getByTestId(`purchase-${id}`)).toHaveClass("btn-shimmer");
    }
  });

  it("refetches saved payment methods when the refresh key changes", async () => {
    const orgId = uniqueOrgId();
    setupTwoMethods();
    const view = await renderWalletCard({
      organizationId: orgId,
      paymentMethodsRefreshKey: 0,
    });
    const callsBefore = mockPaymentMethodsList.mock.calls.length;

    await act(async () => {
      view.rerender(
        <WalletCard
          {...DEFAULT_PROPS}
          organizationId={orgId}
          paymentMethodsRefreshKey={1}
        />,
      );
    });

    await waitFor(() => {
      expect(mockPaymentMethodsList.mock.calls.length).toBeGreaterThan(
        callsBefore,
      );
    });
  });
});
