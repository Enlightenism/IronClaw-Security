import { useState } from "react";
import { Check, Copy, X } from "lucide-react";

const PY_WIN = [
  {
    text: "Install Python. Go to python.org/downloads and download the latest version. Open the file. At the bottom of the first screen, check 'Add python.exe to PATH.' Click Install Now, then Close.",
  },
];

const GIT_WIN = [
  {
    text: "Install Git. Go to git-scm.com/downloads/win. Open the file, click Next on each screen, then click Finish.",
  },
];

const GH_WIN_1 = [
  {
    text: "Install GitHub CLI. Open Windows Terminal or PowerShell and type the line below. Then close it, open a new one, and type gh --version.",
    code: ["winget install --id GitHub.cli"],
  },
];

const GH_WIN_2 = [
  {
    text: "Log in to GitHub. Type gh auth login. Choose GitHub.com, then HTTPS, then Y, then Login with a web browser. Copy the code shown, press Enter, paste it in the browser, click Continue, and approve.",
  },
];

const PY_MAC = [
  {
    text: "Install Python. Go to python.org/downloads and install the macOS version. Use this installer, not Homebrew.",
  },
];

const GIT_MAC = [
  {
    text: "Install Git. Open Terminal and type the line below. Click Install, then Agree. When done, click Done.",
    code: ["xcode-select --install"],
  },
];

const GH_MAC_1 = [
  {
    text: "Install GitHub CLI. Go to cli.github.com, download the macOS installer, and open it. Click Continue, then Install.",
  },
];

const GH_MAC_2 = [
  {
    text: "Log in to GitHub. In Terminal, type gh auth login. Choose GitHub.com, then HTTPS, then Y, then Login with a web browser. Approve in the browser.",
  },
];

const UBU_SETUP = [
  {
    text: "Open Terminal. Type the lines below, pressing Enter after each. Enter your password when asked. It will not show as you type.",
    code: [
      "sudo apt update",
      "sudo apt install -y python3 python3-venv python3-pip git",
    ],
  },
];

const GH_UBU_1 = [
  {
    text: "Install GitHub CLI. Type each line below, pressing Enter after each, and wait for each to finish.",
    code: [
      "sudo mkdir -p -m 755 /etc/apt/keyrings",
      "wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo tee /usr/share/keyrings/githubcli-archive-keyring.gpg > /dev/null",
      "sudo chmod go+r /usr/share/keyrings/githubcli-archive-keyring.gpg",
      'echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list > /dev/null',
      "sudo apt update",
      "sudo apt install -y gh",
    ],
  },
];

const GH_UBU_2 = GH_MAC_2;

const IRON_WIN = [
  {
    text: "Open Windows Terminal or PowerShell. Paste the Install Skill Command from this platform's card and press Enter. Wait for it to finish, which can take a few minutes.",
  },
  {
    text: "Paste the Installer Bootstrap Command from this platform's card and press Enter.",
  },
  {
    text: "Success: the last line says shared skill installed. If you see 'not recognized,' close the terminal, open a new one, and try again.",
  },
];

const IRON_MAC = [
  {
    text: "Open Terminal. Paste the Install Skill Command from this platform's card and press Enter. Wait for it to finish.",
  },
  {
    text: "Paste the Installer Bootstrap Command from this platform's card and press Enter.",
  },
  {
    text: "Success: the last line says shared skill installed. If you see 'command not found: python,' install Python from step 1, then close Terminal and try again.",
  },
];

const IRON_UBU = [
  {
    text: "Open Terminal. Type this line once to create the IronClaw environment, and press Enter.",
    code: ["python3 -m venv ~/ironclaw-venv"],
  },
  {
    text: "Every time you open a new Terminal window, type this line first and press Enter, before anything else.",
    code: ["source ~/ironclaw-venv/bin/activate"],
  },
  {
    text: "Paste the Install Skill Command from this platform's card and press Enter. Wait for it to finish.",
  },
  {
    text: "Paste the Installer Bootstrap Command from this platform's card and press Enter.",
  },
  {
    text: "Success: the last line says shared skill installed. If you see 'No module named venv,' type sudo apt install -y python3-venv, press Enter, then create the environment again.",
  },
];

const CLAUDE_RESTART = [
  {
    text: "If Claude Code was open while you did this, close it and open it again.",
  },
];

const MANUAL_STEPS = {
  claude_code: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...PY_WIN,
        ...GIT_WIN,
        {
          text: "Open Windows Terminal or PowerShell and type the line below. Wait for the cursor to return. Then close it, open a new one, and type claude --version.",
          code: ["irm https://claude.ai/install.ps1 | iex"],
        },
        ...IRON_WIN,
        ...CLAUDE_RESTART,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...PY_MAC,
        ...GIT_MAC,
        {
          text: "Open Terminal and type the line below. Wait for the cursor to return. Close Terminal, open it again, and type claude --version. If you see 'command not found,' type the second line, then close and reopen Terminal.",
          code: [
            "curl -fsSL https://claude.ai/install.sh | bash",
            "echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.zshrc",
          ],
        },
        ...IRON_MAC,
        ...CLAUDE_RESTART,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        {
          text: "Open Terminal and type the line below. Wait for the cursor to return. Close Terminal, open it again, and type claude --version. If you see 'command not found,' type the second line, then close and reopen Terminal.",
          code: [
            "curl -fsSL https://claude.ai/install.sh | bash",
            "echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.bashrc",
          ],
        },
        ...IRON_UBU,
        ...CLAUDE_RESTART,
      ],
    },
  },
  cursor: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...PY_WIN,
        ...GIT_WIN,
        { text: "Go to cursor.com and install Cursor." },
        ...GH_WIN_1,
        ...GH_WIN_2,
        ...IRON_WIN,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...PY_MAC,
        ...GIT_MAC,
        { text: "Go to cursor.com and install Cursor." },
        ...GH_MAC_1,
        ...GH_MAC_2,
        ...IRON_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        { text: "Go to cursor.com and install Cursor." },
        ...GH_UBU_1,
        ...GH_UBU_2,
        ...IRON_UBU,
      ],
    },
  },
  goose: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...PY_WIN,
        ...GIT_WIN,
        {
          text: "Open Windows Terminal or PowerShell and type these lines one at a time, pressing Enter after each.",
          code: [
            "$env:CONFIGURE = 'false'",
            "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/aaif-goose/goose/main/download_cli.ps1' -OutFile 'download_cli.ps1'",
            ".\\download_cli.ps1",
          ],
        },
        { text: "Close it, open a new one, and type goose --version." },
        ...GH_WIN_1,
        ...GH_WIN_2,
        ...IRON_WIN,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...PY_MAC,
        ...GIT_MAC,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type goose --version.",
          code: [
            "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash",
          ],
        },
        ...GH_MAC_1,
        ...GH_MAC_2,
        ...IRON_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type goose --version.",
          code: [
            "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash",
          ],
        },
        ...GH_UBU_1,
        ...GH_UBU_2,
        ...IRON_UBU,
      ],
    },
  },
  antigravity_cli: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...PY_WIN,
        ...GIT_WIN,
        {
          text: "Open Windows Terminal or PowerShell and type the line below. Close it, open a new one, and type agy --version.",
          code: ["irm https://antigravity.google/cli/install.ps1 | iex"],
        },
        ...GH_WIN_1,
        ...GH_WIN_2,
        ...IRON_WIN,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...PY_MAC,
        ...GIT_MAC,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type agy --version.",
          code: ["curl -fsSL https://antigravity.google/cli/install.sh | bash"],
        },
        ...GH_MAC_1,
        ...GH_MAC_2,
        ...IRON_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type agy --version.",
          code: ["curl -fsSL https://antigravity.google/cli/install.sh | bash"],
        },
        ...GH_UBU_1,
        ...GH_UBU_2,
        ...IRON_UBU,
      ],
    },
  },
  copilot: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...PY_WIN,
        ...GIT_WIN,
        {
          text: "You need an active GitHub Copilot subscription at github.com/features/copilot. Open Windows Terminal or PowerShell and type the line below.",
          code: ["winget install GitHub.Copilot"],
        },
        {
          text: "Close it, open a new one, type copilot, and sign in with /login. Then type /exit.",
        },
        ...GH_WIN_1,
        ...GH_WIN_2,
        ...IRON_WIN,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...PY_MAC,
        ...GIT_MAC,
        {
          text: "You need an active GitHub Copilot subscription at github.com/features/copilot. Open Terminal and type the line below. Close Terminal, open it again, type copilot, and sign in with /login. Then type /exit.",
          code: ["curl -fsSL https://gh.io/copilot-install | bash"],
        },
        ...GH_MAC_1,
        ...GH_MAC_2,
        ...IRON_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        {
          text: "You need an active GitHub Copilot subscription at github.com/features/copilot. Open Terminal and type the line below. Close Terminal, open it again, type copilot, and sign in with /login. Then type /exit.",
          code: ["curl -fsSL https://gh.io/copilot-install | bash"],
        },
        ...GH_UBU_1,
        ...GH_UBU_2,
        ...IRON_UBU,
      ],
    },
  },
  hermes: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...PY_WIN,
        ...GIT_WIN,
        {
          text: "Open Windows Terminal or PowerShell and type the line below.",
          code: [
            "& ([scriptblock]::Create((irm https://hermes-agent.nousresearch.com/install.ps1))) -NonInteractive -SkipSetup",
          ],
        },
        { text: "Close it, open a new one, and type hermes --version." },
        {
          text: "Optional, before first use: type hermes setup and answer the questions.",
        },
        ...IRON_WIN,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...PY_MAC,
        ...GIT_MAC,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type hermes --version.",
          code: [
            "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash",
          ],
        },
        {
          text: "Optional, before first use: type hermes setup and answer the questions.",
        },
        ...IRON_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type hermes --version.",
          code: [
            "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash",
          ],
        },
        {
          text: "Optional, before first use: type hermes setup and answer the questions.",
        },
        ...IRON_UBU,
      ],
    },
  },
  openclaw: {
    windows: {
      intro: "Use PowerShell as Administrator, then Ubuntu.",
      steps: [
        {
          text: "Open PowerShell as Administrator. Type the line below, press Enter, and restart when asked.",
          code: ["wsl --install -d Ubuntu"],
        },
        {
          text: "Open Ubuntu from the Start menu and create a username and password. From here on, every step is in the Ubuntu window.",
        },
        ...UBU_SETUP,
        ...GH_UBU_1,
        ...GH_UBU_2,
        {
          text: "Open Terminal and type the line below. It installs Node if needed and may ask for your password. Close Terminal, open it again, and type openclaw --version.",
          code: [
            "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard",
          ],
        },
        ...IRON_UBU,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...PY_MAC,
        ...GIT_MAC,
        ...GH_MAC_1,
        ...GH_MAC_2,
        {
          text: "Open Terminal and type the line below. It installs Node if needed and may ask for your Mac password. Close Terminal, open it again, and type openclaw --version.",
          code: [
            "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard",
          ],
        },
        ...IRON_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        ...GH_UBU_1,
        ...GH_UBU_2,
        {
          text: "Open Terminal and type the line below. It installs Node if needed and may ask for your password. Close Terminal, open it again, and type openclaw --version.",
          code: [
            "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard",
          ],
        },
        ...IRON_UBU,
      ],
    },
  },
};

export default function InstallManual({ program, platformTitle, onClose }) {
  const [copiedCode, setCopiedCode] = useState("");
  const selected = MANUAL_STEPS[program] || MANUAL_STEPS.openclaw;

  const copyCode = async (code, codeId) => {
    try {
      await navigator.clipboard.writeText(code);
    } catch {
      const textarea = document.createElement("textarea");
      textarea.value = code;
      textarea.setAttribute("readonly", "");
      textarea.style.position = "fixed";
      textarea.style.top = "-9999px";
      document.body.appendChild(textarea);
      textarea.select();
      try {
        document.execCommand("copy");
      } finally {
        document.body.removeChild(textarea);
      }
    }
    setCopiedCode(codeId);
    setTimeout(() => setCopiedCode(""), 2000);
  };

  const sections = [
    ["Windows", selected.windows],
    ["Mac", selected.mac],
    ["Ubuntu", selected.ubuntu],
  ];

  return (
    <div
      className="fixed inset-0 z-[100] overflow-y-auto bg-black/80 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label={`${platformTitle} Install Guide`}
    >
      <div className="mx-auto min-h-full max-w-3xl">
        <div className="glass-gold rounded-lg border border-white/10 bg-black/70 p-5">
          <div className="mb-4 flex items-start justify-between gap-4">
            <h2 className="font-tech text-sm font-semibold uppercase tracking-[0.2em] text-[#FFD700]">
              {platformTitle} Install Guide
            </h2>
            <button
              type="button"
              onClick={onClose}
              className="flex h-7 w-7 items-center justify-center rounded-md border border-[#FFD70055] bg-[#FFD70014] text-[#FFD700]"
              aria-label="Close install guide"
            >
              <X size={14} />
            </button>
          </div>

          {sections.map(([heading, section]) => (
            <section
              key={heading}
              className="mb-6 rounded-md border border-white/10 bg-black/40 p-4"
            >
              <h3 className="font-tech mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-[#FFD700]">
                {heading}
              </h3>
              <p className="mb-3 text-[11px] leading-snug text-[#BFC1C2]">
                {section.intro}
              </p>
              <ol className="space-y-4">
                {section.steps.map((step, stepIndex) => (
                  <li
                    key={`${heading}-${stepIndex}`}
                    className="text-[11px] leading-relaxed text-[#BFC1C2]"
                  >
                    <p>
                      <span className="mr-2 font-semibold text-white/80">
                        {stepIndex + 1}.
                      </span>
                      {step.text}
                    </p>
                    {step.code?.length ? (
                      <div className="relative mt-2 rounded-md border border-white/10 bg-black/50">
                        <code className="font-tech block w-full overflow-x-auto whitespace-pre-wrap break-words px-2 pt-2 pb-8 pr-20 text-[10px] leading-relaxed text-white/90">
                          {step.code.join("\n")}
                        </code>
                        <button
                          type="button"
                          onClick={() =>
                            copyCode(
                              step.code.join("\n"),
                              `${heading}-${stepIndex}`,
                            )
                          }
                          className="absolute right-1 bottom-1 flex h-6 items-center justify-center rounded-md border px-2 text-[9px] font-semibold transition"
                          style={{
                            borderColor: "#FFD70055",
                            background: "#FFD70014",
                            color: "#FFD700",
                          }}
                          aria-label="Copy"
                        >
                          {copiedCode === `${heading}-${stepIndex}` ? (
                            <Check size={10} />
                          ) : (
                            <Copy size={10} />
                          )}
                          <span className="ml-1">Copy</span>
                        </button>
                      </div>
                    ) : null}
                  </li>
                ))}
              </ol>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
