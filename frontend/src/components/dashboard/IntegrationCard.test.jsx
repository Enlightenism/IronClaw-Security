import { act, render, screen, waitFor } from "@testing-library/react";
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

const INSTALLER_SOURCE_COMMAND =
  "python -m pip install --no-deps --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git";
const CLAUDE_CODE_GENERIC_COMMAND =
  "gh skill install Enlightenism/IronClaw-Security skills/ironclaw-security --agent claude-code --scope user";

const makeClaim = (overrides = {}) => ({
  integration_id: "claude-code",
  program: "claude_code",
  claim_token: CLAIM_TOKEN,
  command: `${INSTALLER_SOURCE_COMMAND}\npython -m ironclaw_installer redeem --program claude_code --claim-token ${CLAIM_TOKEN}\n${CLAUDE_CODE_GENERIC_COMMAND}`,
  ...overrides,
});

const renderCard = (props = {}) =>
  render(
    <IntegrationCard
      title="Claude Code"
      program="claude_code"
      integrationId="claude-code"
      agentId="claude-code"
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

  afterEach(() => {
    delete window.IntersectionObserver;
  });

  it("does not request or expose a claim until the user generates one", async () => {
    const onCreateClaim = jest.fn();

    renderCard({ onCreateClaim });

    expect(screen.getByTestId("claude-code-card")).toHaveTextContent(
      "Generate a one-time install command after purchase",
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
      "generate a one-time install command for this platform",
    );
  });

  it("renders decorative glass cracks as a hidden, non-interactive layer", () => {
    renderCard();

    const cracks = screen.getByTestId("claude-code-card-cracks");
    expect(cracks.tagName.toLowerCase()).toBe("svg");
    expect(cracks).toHaveAttribute("aria-hidden", "true");
    expect(cracks).toHaveClass("pointer-events-none");
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
    expect(screen.queryByText(/expires/i)).not.toBeInTheDocument();
    expect(mockToastSuccess).toHaveBeenCalledWith(
      "One-time install command generated",
    );
  });

  it("rejects the legacy pip bootstrap template and --key install commands", async () => {
    const user = userEvent.setup();
    const legacyClaim = makeClaim({
      command: `${INSTALLER_SOURCE_COMMAND}\npython -m ironclaw_installer bootstrap --program claude_code --claim-token ${CLAIM_TOKEN}`,
    });
    const keyClaim = makeClaim({
      command: `gh skill install Enlightenism/IronClaw-Security skills/ironclaw-security --agent claude-code --scope user --key ${CLAIM_TOKEN}`,
    });
    const onCreateClaim = jest
      .fn()
      .mockResolvedValueOnce(legacyClaim)
      .mockResolvedValueOnce(keyClaim);

    renderCard({ onCreateClaim });

    await user.click(screen.getByTestId("claude-code-card-generate"));
    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByText(legacyClaim.command)).not.toBeInTheDocument();

    await user.click(screen.getByTestId("claude-code-card-generate"));
    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledTimes(2);
    });
    expect(screen.queryByText(keyClaim.command)).not.toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card-copy")).toBeDisabled();
  });

  it("accepts the Hermes command contract without an agent id", async () => {
    const user = userEvent.setup();
    const hermesToken = `ic_claim_${"B".repeat(43)}`;
    const hermesCommand = `${INSTALLER_SOURCE_COMMAND}\npython -m ironclaw_installer redeem --program hermes --claim-token ${hermesToken}\nhermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security`;
    const onCreateClaim = jest.fn().mockResolvedValue(
      makeClaim({
        integration_id: "hermes",
        program: "hermes",
        claim_token: hermesToken,
        command: hermesCommand,
      }),
    );

    renderCard({
      title: "Hermes",
      program: "hermes",
      integrationId: "hermes",
      agentId: null,
      testid: "hermes-card",
      onCreateClaim,
    });

    await user.click(screen.getByTestId("hermes-card-generate"));

    await waitFor(() => {
      expect(
        screen.getByTestId("hermes-card").querySelector("code")?.textContent,
      ).toBe(hermesCommand);
    });
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

  it("does not block a claim based on a legacy expires_at field", async () => {
    const user = userEvent.setup();
    const claim = makeClaim({
      expires_at: new Date(Date.now() - 60_000).toISOString(),
    });

    renderCard({ onCreateClaim: jest.fn().mockResolvedValue(claim) });

    await user.click(screen.getByTestId("claude-code-card-generate"));

    await waitFor(() => {
      expect(getDisplayedCommand()).toBe(claim.command);
    });
    expect(screen.getByTestId("claude-code-card-copy")).toBeEnabled();
  });

  it("restores a saved command from the dashboard and flags a redeemed key", () => {
    const savedCommand = makeClaim().command;

    renderCard({ savedCommand, savedCommandClaimed: true });

    expect(getDisplayedCommand()).toBe(savedCommand);
    expect(screen.getByTestId("claude-code-card-claimed-note")).toBeTruthy();
  });

  it("keeps the card locked when a saved command fails validation", () => {
    renderCard({ savedCommand: `${makeClaim().command} && rm -rf /` });

    expect(screen.getByTestId("claude-code-card-copy").disabled).toBe(true);
    expect(screen.queryByTestId("claude-code-card-claimed-note")).toBeNull();
  });

  it("shows the refunded revoked state without copy, generate, or a restored command", () => {
    const onCreateClaim = jest.fn();

    renderCard({
      savedCommand: makeClaim().command,
      savedCommandClaimed: true,
      revoked: true,
      revokedReason: "refunded",
      onCreateClaim,
    });

    expect(
      screen.getByTestId("claude-code-card-revoked-note"),
    ).toHaveTextContent("Revoked — purchase refunded");
    expect(getDisplayedCommand()).toBe("Revoked");
    expect(screen.queryByTestId("claude-code-card-copy")).toBeNull();
    expect(screen.queryByTestId("claude-code-card-generate")).toBeNull();
    expect(onCreateClaim).not.toHaveBeenCalled();
  });

  it("gives each card a different, repeatable crack pattern", () => {
    const { unmount } = render(
      <>
        <IntegrationCard
          title="Claude Code"
          program="claude_code"
          integrationId="claude-code"
          available
          onCreateClaim={jest.fn()}
          testid="card-a"
        />
        <IntegrationCard
          title="Codex"
          program="codex"
          integrationId="codex"
          available
          onCreateClaim={jest.fn()}
          testid="card-b"
        />
      </>,
    );
    const fracturePaths = (testid) =>
      Array.from(
        screen.getByTestId(`${testid}-cracks`).querySelectorAll("path"),
      ).map((path) => path.getAttribute("d"));

    const first = fracturePaths("card-a");
    expect(first.length).toBeGreaterThan(0);
    expect(first).not.toEqual(fracturePaths("card-b"));
    unmount();

    renderCard();
    expect(fracturePaths("claude-code-card")).toEqual(first);
  });

  it("keeps cracks hidden until the card scrolls into view", () => {
    let onIntersect;
    window.IntersectionObserver = jest.fn((callback) => {
      onIntersect = callback;
      return {
        observe: jest.fn(),
        disconnect: jest.fn(),
        unobserve: jest.fn(),
      };
    });

    renderCard();
    const firstPath = screen
      .getByTestId("claude-code-card-cracks")
      .querySelector("path");
    expect(firstPath.style.strokeDashoffset).toBe("1");

    act(() => {
      onIntersect([{ isIntersecting: true }]);
    });
    expect(firstPath.style.strokeDashoffset).toBe("0");
  });
});
