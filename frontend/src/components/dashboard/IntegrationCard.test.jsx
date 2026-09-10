import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import IntegrationCard from "./IntegrationCard.jsx";

const mockWriteText = jest.fn();
const mockToastSuccess = jest.fn();

jest.mock("sonner", () => ({
  toast: {
    success: (...args) => mockToastSuccess(...args),
  },
}));

const RUNTIME_CARDS = [
  {
    title: "Claude Code",
    metadataKey: "claude_code",
    command:
      "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...abcd",
    testid: "claude-code-card",
  },
  {
    title: "OpenClaw",
    metadataKey: "openclaw",
    command:
      "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user --key ic_install_openclaw_...abcd",
    testid: "openclaw-card",
  },
  {
    title: "Goose",
    metadataKey: "goose",
    command:
      "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user --key ic_install_goose_...mnop",
    testid: "goose-card",
  },
  {
    title: "Gemini CLI",
    metadataKey: "gemini_cli",
    command:
      "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user --key ic_install_gemini_cli_...qrst",
    testid: "gemini_cli-card",
  },
  {
    title: "Cursor",
    metadataKey: "cursor",
    command:
      "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user --key ic_install_cursor_...ijkl",
    testid: "cursor-card",
  },
  {
    title: "GitHub Copilot",
    metadataKey: "copilot",
    command:
      "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user --key ic_install_copilot_...uvwx",
    testid: "copilot-card",
  },
  {
    title: "Hermes",
    metadataKey: "hermes",
    command:
      "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_...abcd",
    testid: "hermes-card",
  },
];

describe("IntegrationCard", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    Object.defineProperty(globalThis.navigator, "clipboard", {
      value: {
        writeText: mockWriteText.mockResolvedValue(undefined),
      },
      configurable: true,
    });
  });

  it("renders each supported runtime label and exact command payload", () => {
    for (const runtime of RUNTIME_CARDS) {
      const { unmount } = render(
        <IntegrationCard
          title={runtime.title}
          command={runtime.command}
          tint="gold"
          testid={runtime.testid}
        />,
      );

      expect(screen.getByText(runtime.title)).toBeInTheDocument();
      expect(screen.getByTestId(runtime.testid)).toHaveTextContent(
        runtime.command,
      );
      expect(screen.getByTestId(`${runtime.testid}-copy`)).toHaveAttribute(
        "aria-label",
        `Copy ${runtime.title} install command`,
      );

      unmount();
    }

    const supportedTitles = RUNTIME_CARDS.map((item) => item.title);
    expect(supportedTitles).toContain("Hermes");
    expect(supportedTitles).not.toContain("Security Guardian");
  });

  it("uses the canonical runtime install commands without placeholders", () => {
    expect(RUNTIME_CARDS).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          title: "Claude Code",
          command:
            "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...abcd",
        }),
        expect.objectContaining({
          title: "OpenClaw",
          command:
            "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent openclaw --scope user --key ic_install_openclaw_...abcd",
        }),
        expect.objectContaining({
          title: "Cursor",
          command:
            "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent cursor --scope user --key ic_install_cursor_...ijkl",
        }),
        expect.objectContaining({
          title: "Goose",
          command:
            "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent goose --scope user --key ic_install_goose_...mnop",
        }),
        expect.objectContaining({
          title: "Gemini CLI",
          command:
            "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent gemini-cli --scope user --key ic_install_gemini_cli_...qrst",
        }),
        expect.objectContaining({
          title: "GitHub Copilot",
          command:
            "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent copilot --scope user --key ic_install_copilot_...uvwx",
        }),
        expect.objectContaining({
          title: "Hermes",
          command:
            "hermes skills install https://ironclaw-security.onrender.com/skills/ironclaw-security/SKILL.md --name ironclaw-security --key ic_install_hermes_...abcd",
        }),
      ]),
    );

    expect(RUNTIME_CARDS.some((item) => item.command.includes("<YOUR_"))).toBe(
      false,
    );
  });

  it("binds to canonical runtime metadata keys and ignores Security Guardian and placeholder values", () => {
    for (const runtime of RUNTIME_CARDS) {
      const { unmount } = render(
        <IntegrationCard
          title={runtime.metadataKey}
          command={runtime.command}
          tint="gold"
          testid={runtime.testid}
        />,
      );

      expect(screen.getByTestId(runtime.testid)).toHaveTextContent(
        runtime.command,
      );
      expect(screen.getByText(runtime.title)).toBeInTheDocument();
      expect(screen.getByText(runtime.title)).not.toHaveTextContent("_");
      unmount();
    }

    const { container: guardianContainer } = render(
      <IntegrationCard
        title="security_guardian"
        command="placeholder install command"
        tint="gold"
        testid="security_guardian-card"
      />,
    );

    expect(guardianContainer.firstChild).toBeNull();

    render(
      <IntegrationCard
        title="claude_code"
        command="gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...abcd"
        tint="gold"
        testid="claude-code-card-placeholder-fallback"
      />,
    );

    expect(
      screen.getByTestId("claude-code-card-placeholder-fallback"),
    ).toHaveTextContent(
      "gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user --key ic_install_claude_code_...abcd",
    );
  });

  it("ignores keyless fallback commands and does not render a copyable install command without --key", () => {
    const { container } = render(
      <IntegrationCard
        title="Claude Code"
        command="gh skill install Enlightenism/IronClaw-Security ironclaw-security --agent claude-code --scope user"
        tint="gold"
        testid="claude-code-card"
      />,
    );

    expect(container.firstChild).toBeNull();
  });

  it("copies the runtime command when the copy button is clicked", async () => {
    const user = userEvent.setup();
    const runtime = RUNTIME_CARDS[RUNTIME_CARDS.length - 1];

    render(
      <IntegrationCard
        title={runtime.title}
        command={runtime.command}
        tint="gold"
        testid={runtime.testid}
      />,
    );

    await user.click(screen.getByTestId(`${runtime.testid}-copy`));

    expect(mockToastSuccess).toHaveBeenCalledWith("Install command copied");
    expect(screen.getByTestId(`${runtime.testid}-copy`)).toBeInTheDocument();
  });

  it("keeps Hermes as a first-class runtime and excludes Security Guardian from the runtime family set", () => {
    const runtimeIds = RUNTIME_CARDS.map((item) => item.testid);

    expect(runtimeIds).toContain("hermes-card");
    expect(runtimeIds).not.toContain("security_guardian-card");
    expect(runtimeIds).not.toContain("security-guardian-card");
    expect(RUNTIME_CARDS.some((item) => item.title === "Hermes")).toBe(true);
    expect(
      RUNTIME_CARDS.some((item) => item.title === "Security Guardian"),
    ).toBe(false);
  });
});
