import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import IntegrationCard from "./IntegrationCard.jsx";

const mockWriteText = jest.fn();
const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();
const CLAIM_TOKEN = `ic_claim_${"A".repeat(43)}`;

jest.mock("sonner", () => ({
  toast: {
    success: (...args) => mockToastSuccess(...args),
    error: (...args) => mockToastError(...args),
  },
}));

const makeClaim = (overrides = {}) => ({
  integration_id: "claude-code",
  program: "claude_code",
  claim_token: CLAIM_TOKEN,
  expires_at: new Date(Date.now() + 60_000).toISOString(),
  command: `python -m pip install --no-deps --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git\npython -m ironclaw_installer bootstrap --program claude_code --claim-token ${CLAIM_TOKEN}`,
  ...overrides,
});

const renderCard = (props = {}) =>
  render(
    <IntegrationCard
      title="Claude Code"
      program="claude_code"
      integrationId="claude-code"
      available
      onCreateClaim={jest.fn()}
      testid="claude-code-card"
      {...props}
    />,
  );

const getDisplayedCommand = () =>
  screen.getByTestId("claude-code-card").querySelector("code")?.textContent;

describe("IntegrationCard", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("does not request or expose a claim until the user generates one", async () => {
    const onCreateClaim = jest.fn();

    renderCard({ onCreateClaim });

    expect(screen.getByTestId("claude-code-card")).toHaveTextContent(
      "Generate a one-time bootstrap command after purchase",
    );
    expect(screen.getByTestId("claude-code-card-generate")).toBeEnabled();
    expect(screen.getByTestId("claude-code-card-copy")).toBeDisabled();
    expect(onCreateClaim).not.toHaveBeenCalled();
  });

  it("does not show per-platform usage stats or the legacy card copy", () => {
    renderCard();

    expect(
      screen.queryByTestId("claude-code-card-units-consumed"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("claude-code-card-blocked-attacks"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card")).toHaveTextContent(
      "Install commands will be available to generate after purchase",
    );
  });

  it("requests and displays a valid one-time claim only after an explicit click", async () => {
    const user = userEvent.setup();
    const claim = makeClaim();
    const onCreateClaim = jest.fn().mockResolvedValue(claim);

    renderCard({ onCreateClaim });

    await user.click(screen.getByTestId("claude-code-card-generate"));

    await waitFor(() => {
      expect(getDisplayedCommand()).toBe(claim.command);
    });
    expect(onCreateClaim).toHaveBeenCalledWith("claude-code");
    expect(screen.getByTestId("claude-code-card-copy")).toBeEnabled();
    expect(mockToastSuccess).toHaveBeenCalledWith(
      "One-time install command generated",
    );
  });

  it("rejects long-lived install keys and malformed claim commands", async () => {
    const user = userEvent.setup();
    const invalidClaim = makeClaim({
      claim_token: "ic_install_claude_code_...masked",
      command:
        "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...masked",
    });
    const onCreateClaim = jest.fn().mockResolvedValue(invalidClaim);

    renderCard({ onCreateClaim });

    await user.click(screen.getByTestId("claude-code-card-generate"));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledWith(
        "Unable to generate a secure install command. Please try again.",
      );
    });
    expect(screen.queryByText(invalidClaim.command)).not.toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card-copy")).toBeDisabled();
  });

  it("rejects claims for another runtime and shell command injection", async () => {
    const user = userEvent.setup();
    const onCreateClaim = jest
      .fn()
      .mockResolvedValueOnce(makeClaim({ program: "openclaw" }))
      .mockResolvedValueOnce(
        makeClaim({
          command: `gh skill install --key ${CLAIM_TOKEN}; unexpected-command`,
        }),
      );
    const { rerender } = renderCard({ onCreateClaim });

    await user.click(screen.getByTestId("claude-code-card-generate"));
    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledTimes(1);
    });

    rerender(
      <IntegrationCard
        title="Claude Code"
        program="claude_code"
        integrationId="claude-code"
        available
        onCreateClaim={onCreateClaim}
        testid="claude-code-card"
      />,
    );
    await user.click(screen.getByTestId("claude-code-card-generate"));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledTimes(2);
    });
    expect(screen.queryByText(/unexpected-command/)).not.toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card-copy")).toBeDisabled();
  });

  it("keeps unavailable runtimes locked and never requests a claim", async () => {
    const user = userEvent.setup();
    const onCreateClaim = jest.fn();

    renderCard({ available: false, onCreateClaim });

    expect(screen.getByTestId("claude-code-card-generate")).toBeDisabled();
    await user.click(screen.getByTestId("claude-code-card-generate"));
    expect(onCreateClaim).not.toHaveBeenCalled();
  });

  it("does not render Security Guardian as a standalone runtime", () => {
    const { container } = renderCard({
      title: "Security Guardian",
      program: "security_guardian",
      integrationId: "security-guardian",
    });

    expect(container.firstChild).toBeNull();
  });

  it("copies the generated one-time command", async () => {
    const user = userEvent.setup();
    Object.defineProperty(window.navigator, "clipboard", {
      value: {
        writeText: mockWriteText.mockResolvedValue(undefined),
      },
      configurable: true,
    });
    const claim = makeClaim();

    renderCard({ onCreateClaim: jest.fn().mockResolvedValue(claim) });

    await user.click(screen.getByTestId("claude-code-card-generate"));
    await waitFor(() => {
      expect(getDisplayedCommand()).toBe(claim.command);
    });
    const copyButton = screen.getByTestId("claude-code-card-copy");
    expect(copyButton).toBeEnabled();
    await user.click(copyButton);

    await waitFor(() => {
      expect(mockWriteText).toHaveBeenCalledWith(claim.command);
      expect(mockToastSuccess).toHaveBeenCalledWith("Install command copied");
    });
  });

  it("rejects an expired claim instead of leaving its command available", async () => {
    const user = userEvent.setup();
    const claim = makeClaim({
      expires_at: new Date(Date.now() - 60_000).toISOString(),
    });

    renderCard({ onCreateClaim: jest.fn().mockResolvedValue(claim) });

    await user.click(screen.getByTestId("claude-code-card-generate"));

    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalled();
    });
    expect(screen.getByTestId("claude-code-card-copy")).toBeDisabled();
  });
});
