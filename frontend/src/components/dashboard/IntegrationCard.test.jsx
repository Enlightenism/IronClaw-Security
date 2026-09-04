import React from "react";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import IntegrationCard from "./IntegrationCard";

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
    command:
      "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent claude-code --scope user",
    testid: "claude-code-card",
  },
  {
    title: "OpenClaw",
    command:
      "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent openclaw --scope user",
    testid: "openclaw-card",
  },
  {
    title: "Cursor",
    command:
      "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent cursor --scope user",
    testid: "cursor-card",
  },
  {
    title: "Goose",
    command:
      "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent goose --scope user",
    testid: "goose-card",
  },
  {
    title: "Gemini CLI",
    command:
      "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent gemini-cli --scope user",
    testid: "gemini_cli-card",
  },
  {
    title: "GitHub Copilot",
    command:
      "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent copilot --scope user",
    testid: "copilot-card",
  },
  {
    title: "Hermes",
    command:
      "hermes skills install https://<YOUR_DOMAIN>/skills/<YOUR_SKILL_SLUG>/SKILL.md --name <YOUR_SKILL_NAME>",
    testid: "hermes-card",
  },
];

describe("IntegrationCard", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    Object.defineProperty(window.navigator, "clipboard", {
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
