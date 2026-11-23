import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import IntegrationCard from "./IntegrationCard.jsx";

const mockWriteText = jest.fn();
const mockToastSuccess = jest.fn();
const mockToastError = jest.fn();
const CLAIM_TOKEN = `ic_claim_${"A".repeat(43)}`;
const INSTALLER_SOURCE_COMMAND =
  "python -m pip install --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git@v1.0.3";

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
  command: `python -m pip install --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git@v1.0.3\npython -m ironclaw_installer bootstrap --program claude_code --claim-token ${CLAIM_TOKEN}`,
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
  screen
    .getByTestId("claude-code-card-skill-command-block")
    .querySelector("code")?.textContent;

const getDisplayedBootstrapCommand = () =>
  screen
    .getByTestId("claude-code-card-bootstrap-command-block")
    .querySelector("code")?.textContent;

describe("IntegrationCard", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  afterEach(() => {
    delete window.IntersectionObserver;
  });

  it("renders the same explanation for every runtime card", () => {
    const runtimes = [
      ["OpenClaw", "openclaw", "openclaw-card"],
      ["Claude Code", "claude_code", "claude-code-card"],
      ["Cursor", "cursor", "cursor-card"],
      ["Goose", "goose", "goose-card"],
      ["Antigravity CLI", "antigravity_cli", "antigravity_cli-card"],
      ["GitHub Copilot", "copilot", "copilot-card"],
      ["Hermes", "hermes", "hermes-card"],
    ];

    const { container } = render(
      <>
        {runtimes.map(([title, program, testid]) => (
          <IntegrationCard
            key={program}
            title={title}
            program={program}
            integrationId={program.replace(/_/g, "-")}
            available
            onCreateClaim={jest.fn()}
            testid={testid}
          />
        ))}
      </>,
    );

    const explanations = Array.from(
      container.querySelectorAll('[data-testid$="-explanation"]'),
    ).map((node) => node.textContent);
    expect(explanations).toHaveLength(runtimes.length);
    expect(new Set(explanations).size).toBe(1);
    expect(explanations[0]).toBe(
      "Your install commands will be available after purchase.",
    );
  });

  it("Claude Code renders the Claude-specific layout without a skill-only section", () => {
    renderCard();

    expect(
      screen.getByTestId("claude-code-card-install-command"),
    ).toHaveTextContent("Install IronClaw-Security");
    expect(
      screen.getByTestId("claude-code-card-skill-command-block"),
    ).toBeInTheDocument();
    expect(
      screen.getByTestId("claude-code-card-bootstrap-command-block"),
    ).toBeInTheDocument();
    expect(
      screen.queryByTestId("claude-code-card-instructions"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card-manual")).toBeEnabled();
  });

  it("opens the install guide after purchase before a command is generated", async () => {
    const user = userEvent.setup();
    renderCard();

    await user.click(screen.getByTestId("claude-code-card-manual"));

    expect(
      screen.getByRole("dialog", { name: "Claude Code Install Guide" }),
    ).toBeInTheDocument();
  });

  it("Antigravity CLI uses the shared button labels", () => {
    renderCard({
      title: "Antigravity CLI",
      program: "antigravity_cli",
      integrationId: "antigravity-cli",
      testid: "antigravity-cli-card",
    });

    expect(
      screen.getByTestId("antigravity-cli-card-generate"),
    ).toHaveTextContent("Generate New Install Commands");
  });

  it("does not show runtime coverage labels on platform cards", () => {
    renderCard({ program: "goose", testid: "goose-card" });

    expect(screen.queryByTestId("goose-card-coverage")).not.toBeInTheDocument();
    expect(screen.getByTestId("goose-card")).not.toHaveTextContent(
      /Install:|Return:/,
    );
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

  it("does not show per-platform usage stats and keeps the install guidance", () => {
    renderCard();

    expect(
      screen.queryByTestId("claude-code-card-units-consumed"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("claude-code-card-blocked-attacks"),
    ).not.toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card")).toHaveTextContent(
      "Your install commands will be available after purchase.",
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
      expect(getDisplayedCommand()).toBe(INSTALLER_SOURCE_COMMAND);
      expect(getDisplayedBootstrapCommand()).toBe(
        `python -m ironclaw_installer bootstrap --program claude_code --claim-token ${CLAIM_TOKEN}`,
      );
    });
    expect(onCreateClaim).toHaveBeenCalledWith("claude-code");
    expect(screen.getByTestId("claude-code-card-copy")).toBeEnabled();
    expect(screen.getByTestId("claude-code-card-copy")).toHaveTextContent(
      "Copy Installer Bootsrap Command",
    );
    expect(screen.getByTestId("claude-code-card-copy-skill")).toBeEnabled();
    expect(screen.getByTestId("claude-code-card-copy-skill")).toHaveTextContent(
      "Copy Install Skill Command",
    );
    expect(
      screen.getByTestId("claude-code-card-explanation"),
    ).toBeEmptyDOMElement();
    expect(screen.queryByText(/expires/i)).not.toBeInTheDocument();
    expect(mockToastSuccess).toHaveBeenCalledWith(
      "One-time install command generated",
    );
  });

  it("rejects the retired redeem template and --key install commands", async () => {
    const user = userEvent.setup();
    const retiredClaim = makeClaim({
      command: `${INSTALLER_SOURCE_COMMAND}\npython -m ironclaw_installer redeem --program claude_code --claim-token ${CLAIM_TOKEN}\ngh skill install Enlightenism/IronClaw-Security skills/ironclaw-security --agent claude-code --scope user --pin v1.0.3`,
    });
    const keyClaim = makeClaim({
      command: `gh skill install Enlightenism/IronClaw-Security skills/ironclaw-security --agent claude-code --scope user --key ${CLAIM_TOKEN}`,
    });
    const onCreateClaim = jest
      .fn()
      .mockResolvedValueOnce(retiredClaim)
      .mockResolvedValueOnce(keyClaim);

    renderCard({ onCreateClaim });

    await user.click(screen.getByTestId("claude-code-card-generate"));
    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledTimes(1);
    });
    expect(screen.queryByText(retiredClaim.command)).not.toBeInTheDocument();

    await user.click(screen.getByTestId("claude-code-card-generate"));
    await waitFor(() => {
      expect(mockToastError).toHaveBeenCalledTimes(2);
    });
    expect(screen.queryByText(keyClaim.command)).not.toBeInTheDocument();
    expect(screen.getByTestId("claude-code-card-copy")).toBeDisabled();
  });

  it("accepts the Hermes bootstrap command contract", async () => {
    const user = userEvent.setup();
    const hermesToken = `ic_claim_${"B".repeat(43)}`;
    const hermesCommand = `${INSTALLER_SOURCE_COMMAND}\npython -m ironclaw_installer bootstrap --program hermes --claim-token ${hermesToken}`;
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
      testid: "hermes-card",
      onCreateClaim,
    });

    await user.click(screen.getByTestId("hermes-card-generate"));

    await waitFor(() => {
      expect(
        screen
          .getByTestId("hermes-card-skill-command-block")
          .querySelector("code")?.textContent,
      ).toBe(INSTALLER_SOURCE_COMMAND);
      expect(
        screen
          .getByTestId("hermes-card-bootstrap-command-block")
          .querySelector("code")?.textContent,
      ).toBe(
        `python -m ironclaw_installer bootstrap --program hermes --claim-token ${hermesToken}`,
      );
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
    expect(screen.getByTestId("claude-code-card-manual")).toBeDisabled();
    expect(
      screen.getByTestId("claude-code-card-unavailable-note"),
    ).toHaveTextContent("Purchase verification is required");
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
      expect(getDisplayedCommand()).toBe(INSTALLER_SOURCE_COMMAND);
      expect(getDisplayedBootstrapCommand()).toBe(claim.command.split("\n")[1]);
    });
    const copyButton = screen.getByTestId("claude-code-card-copy");
    expect(copyButton).toBeEnabled();
    await user.click(copyButton);

    await waitFor(() => {
      expect(mockWriteText).toHaveBeenCalledWith(claim.command.split("\n")[1]);
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
      expect(getDisplayedCommand()).toBe(INSTALLER_SOURCE_COMMAND);
      expect(getDisplayedBootstrapCommand()).toBe(claim.command.split("\n")[1]);
    });
    expect(screen.getByTestId("claude-code-card-copy")).toBeEnabled();
  });

  it("restores a saved command from the dashboard and flags a redeemed key", () => {
    const savedCommand = makeClaim().command;

    renderCard({ savedCommand, savedCommandClaimed: true });

    expect(getDisplayedCommand()).toBe(savedCommand.split("\n")[0]);
    expect(getDisplayedBootstrapCommand()).toBe(savedCommand.split("\n")[1]);
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
