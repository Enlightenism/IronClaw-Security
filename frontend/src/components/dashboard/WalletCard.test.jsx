/**
 * frontend/src/components/dashboard/WalletCard.test.jsx
 *
 * Full test harness for WalletCard.jsx.
 * Runner: Jest + @testing-library/react + @testing-library/jest-dom
 */

import React from "react";
import { render, screen, cleanup, act, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import WalletCard from "@/components/dashboard/WalletCard";

// ── api mock ──────────────────────────────────────────────────────────────────
const mockApiGet = jest.fn();
const mockApiPost = jest.fn();
const mockApiPatch = jest.fn();
const mockApiDelete = jest.fn();

jest.mock("@/lib/api", () => ({
  __esModule: true,
  default: {
    get: (...args) => mockApiGet(...args),
    post: (...args) => mockApiPost(...args),
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
  onPurchase: jest.fn(),
  purchasingId: null,
};

const ORIGINAL_ENV = process.env;

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
  });
});

// =============================================================================
// WalletCard — current Stripe mode behavior
// =============================================================================

describe("WalletCard — current Stripe mode behavior", () => {
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

  it("does not render units used on the front face", async () => {
    await renderWalletCard({ balance: 12500, organizationId: "" });
    expect(
      screen.queryByTestId("wallet-units-consumed"),
    ).not.toBeInTheDocument();
    expect(screen.queryByText("Units used")).not.toBeInTheDocument();
  });

  it("shows the pay-per-use copy and states that cards are not saved", async () => {
    await renderWalletCard({ balance: 12500, organizationId: "" });
    expect(
      screen.getByText(
        "Pay only for what you use. No subscription, no recurring charge. For security reasons we do not save card information.",
      ),
    ).toBeInTheDocument();
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
    expect(onPurchase).toHaveBeenCalledWith("pkg_5000");
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("clicking purchase-pkg_25000 calls onPurchase with the canonical package ID", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });

    await openPackage(user, "pkg_25000");
    await user.click(screen.getByTestId("purchase-pkg_25000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_25000");
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("clicking purchase-pkg_60000 calls onPurchase with the canonical package ID", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });

    await openPackage(user, "pkg_60000");
    await user.click(screen.getByTestId("purchase-pkg_60000"));
    expect(onPurchase).toHaveBeenCalledWith("pkg_60000");
    expect(onPurchase).toHaveBeenCalledTimes(1);
  });

  it("does not render a save-card checkbox and sends only the package ID", async () => {
    const user = userEvent.setup();
    const onPurchase = jest.fn();

    await renderWalletCard({ onPurchase, organizationId: "" });
    expect(screen.queryByTestId("save-card-consent")).not.toBeInTheDocument();

    await user.click(screen.getByTestId("purchase-pkg_5000"));

    expect(onPurchase).toHaveBeenCalledWith("pkg_5000");
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

    expect(onPurchase).toHaveBeenCalledWith("pkg_60000");
  });
});

// =============================================================================
// Wallet package sheen
// =============================================================================

describe("wallet package sheen", () => {
  it("gives every package button the sheen class", async () => {
    await renderWalletCard({ organizationId: "" });

    for (const id of ["pkg_5000", "pkg_25000", "pkg_60000"]) {
      expect(screen.getByTestId(`purchase-${id}`)).toHaveClass("btn-shimmer");
    }
  });
});
