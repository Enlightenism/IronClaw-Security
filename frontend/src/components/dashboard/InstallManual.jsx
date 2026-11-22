import { useState } from "react";
import { Check, Copy, X } from "lucide-react";

const WIN_PYTHON = [
  {
    text: "Install Python. Go to python.org/downloads and download the latest version. Open the file. At the bottom of the first screen, check 'Add python.exe to PATH.' Click Install Now, then Close.",
  },
];

const WIN_GIT = [
  {
    text: "Install Git. Go to git-scm.com/downloads/win. Open the file and click Next on each screen. Click Finish.",
  },
];

const WIN_GH = [
  {
    text: "Install GitHub CLI. Open Windows Terminal or PowerShell and type the line below. Then close it, open a new one, and type gh --version.",
    code: ["winget install --id GitHub.cli"],
  },
  {
    text: "Log in to GitHub. Type gh auth login. Choose GitHub.com, then HTTPS, then Y, then Login with a web browser. Copy the code shown, press Enter, paste it in the browser, click Continue, and approve.",
  },
];

const MAC_PYTHON = [
  {
    text: "Install Python. Go to python.org/downloads and install the macOS version. Use this installer, not Homebrew.",
  },
];

const MAC_GIT = [
  {
    text: "Install Git. Open Terminal and type the line below. Click Install, then Agree. When done, click Done.",
    code: ["xcode-select --install"],
  },
];

const MAC_GH = [
  {
    text: "Install GitHub CLI. Go to cli.github.com, download the macOS installer, and open it. Click Continue, then Install.",
  },
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

const UBU_GH = [
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
  {
    text: "Log in to GitHub. Type gh auth login. Choose GitHub.com, then HTTPS, then Y, then Login with a web browser. Approve in the browser.",
  },
];

const IRONCLAW_WINDOWS = [
  {
    text: "Open Windows Terminal or PowerShell and paste this line. Press Enter and wait for it to finish, which can take a few minutes.",
    code: [
      'python -m pip install --upgrade "git+https://github.com/Enlightenism/IronClaw-Security.git@v1.0.3"',
    ],
  },
  {
    text: "Paste this line and press Enter.",
    code: [
      "python -m ironclaw_installer bootstrap --program {PROGRAM} --claim-token {CLAIM_TOKEN}",
    ],
  },
  {
    text: "Success: the last line says shared skill installed. If you see 'not recognized,' close the terminal, open a new one, and try again.",
  },
];

const IRONCLAW_MAC = [
  {
    text: "Open Terminal and paste this line. Press Enter and wait for it to finish.",
    code: [
      'python -m pip install --upgrade "git+https://github.com/Enlightenism/IronClaw-Security.git@v1.0.3"',
    ],
  },
  {
    text: "Paste this line and press Enter.",
    code: [
      "python -m ironclaw_installer bootstrap --program {PROGRAM} --claim-token {CLAIM_TOKEN}",
    ],
  },
  {
    text: "Success: the last line says shared skill installed. If you see 'command not found: python,' install Python from step 1, then close Terminal and try again.",
  },
];

const IRONCLAW_UBUNTU = [
  {
    text: "Open Terminal. Type each line below, pressing Enter after each, and wait for each to finish.",
    code: [
      "python3 -m venv ~/ironclaw-venv",
      '~/ironclaw-venv/bin/python -m pip install --upgrade "git+https://github.com/Enlightenism/IronClaw-Security.git@v1.0.3"',
      "~/ironclaw-venv/bin/python -m ironclaw_installer bootstrap --program {PROGRAM} --claim-token {CLAIM_TOKEN}",
    ],
  },
  {
    text: "Success: the last line says shared skill installed. If you see 'No module named venv,' type sudo apt install -y python3-venv, press Enter, then repeat the first line.",
  },
];

const MANUAL_STEPS = {
  claude_code: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...WIN_PYTHON,
        ...WIN_GIT,
        {
          text: "Open Windows Terminal or PowerShell and type the line below. Wait for the cursor to return. Close it, open a new one, and type claude --version.",
          code: ["irm https://claude.ai/install.ps1 | iex"],
        },
        ...IRONCLAW_WINDOWS,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...MAC_PYTHON,
        ...MAC_GIT,
        {
          text: "Open Terminal and type the line below. Wait for the cursor to return. Close Terminal, open it again, and type claude --version. If you see 'command not found,' type the second line, then close and reopen Terminal.",
          code: [
            "curl -fsSL https://claude.ai/install.sh | bash",
            "echo 'export PATH=\"$HOME/.local/bin:$PATH\"' >> ~/.zshrc",
          ],
        },
        ...IRONCLAW_MAC,
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
        ...IRONCLAW_UBUNTU,
      ],
    },
  },
  cursor: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...WIN_PYTHON,
        ...WIN_GIT,
        ...WIN_GH,
        { text: "Go to cursor.com and install Cursor." },
        ...IRONCLAW_WINDOWS,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...MAC_PYTHON,
        ...MAC_GIT,
        ...MAC_GH,
        { text: "Go to cursor.com and install Cursor." },
        ...IRONCLAW_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        ...UBU_GH,
        {
          text: "Go to cursor.com, download the Linux version, and install it.",
        },
        ...IRONCLAW_UBUNTU,
      ],
    },
  },
  goose: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...WIN_PYTHON,
        ...WIN_GIT,
        ...WIN_GH,
        {
          text: "Open Windows Terminal or PowerShell and type these lines one at a time, pressing Enter after each.",
          code: [
            "$env:CONFIGURE = 'false'",
            "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/aaif-goose/goose/main/download_cli.ps1' -OutFile 'download_cli.ps1'",
            ".\\download_cli.ps1",
          ],
        },
        { text: "Close it, open a new one, and type goose --version." },
        ...IRONCLAW_WINDOWS,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...MAC_PYTHON,
        ...MAC_GIT,
        ...MAC_GH,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type goose --version.",
          code: [
            "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash",
          ],
        },
        ...IRONCLAW_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        ...UBU_GH,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type goose --version.",
          code: [
            "curl -fsSL https://github.com/aaif-goose/goose/releases/download/stable/download_cli.sh | CONFIGURE=false bash",
          ],
        },
        ...IRONCLAW_UBUNTU,
      ],
    },
  },
  antigravity_cli: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...WIN_PYTHON,
        ...WIN_GIT,
        ...WIN_GH,
        {
          text: "Open Windows Terminal or PowerShell and type the line below. Close it, open a new one, and type agy --version.",
          code: ["irm https://antigravity.google/cli/install.ps1 | iex"],
        },
        ...IRONCLAW_WINDOWS,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...MAC_PYTHON,
        ...MAC_GIT,
        ...MAC_GH,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type agy --version.",
          code: ["curl -fsSL https://antigravity.google/cli/install.sh | bash"],
        },
        ...IRONCLAW_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        ...UBU_GH,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type agy --version.",
          code: ["curl -fsSL https://antigravity.google/cli/install.sh | bash"],
        },
        ...IRONCLAW_UBUNTU,
      ],
    },
  },
  copilot: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...WIN_PYTHON,
        ...WIN_GIT,
        ...WIN_GH,
        {
          text: "You need an active GitHub Copilot subscription at github.com/features/copilot. Open Windows Terminal or PowerShell and type the line below.",
          code: ["winget install GitHub.Copilot"],
        },
        {
          text: "Close it, open a new one, type copilot, and sign in with /login. Then type /exit.",
        },
        ...IRONCLAW_WINDOWS,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...MAC_PYTHON,
        ...MAC_GIT,
        ...MAC_GH,
        {
          text: "You need an active GitHub Copilot subscription at github.com/features/copilot. Open Terminal and type the line below. Close Terminal, open it again, type copilot, and sign in with /login. Then type /exit.",
          code: ["curl -fsSL https://gh.io/copilot-install | bash"],
        },
        ...IRONCLAW_MAC,
      ],
    },
    ubuntu: {
      intro: "Use Terminal.",
      steps: [
        ...UBU_SETUP,
        ...UBU_GH,
        {
          text: "You need an active GitHub Copilot subscription at github.com/features/copilot. Open Terminal and type the line below. Close Terminal, open it again, type copilot, and sign in with /login. Then type /exit.",
          code: ["curl -fsSL https://gh.io/copilot-install | bash"],
        },
        ...IRONCLAW_UBUNTU,
      ],
    },
  },
  hermes: {
    windows: {
      intro: "Use Windows Terminal or PowerShell.",
      steps: [
        ...WIN_PYTHON,
        ...WIN_GIT,
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
        ...IRONCLAW_WINDOWS,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...MAC_PYTHON,
        ...MAC_GIT,
        {
          text: "Open Terminal and type the line below. Close Terminal, open it again, and type hermes --version.",
          code: [
            "curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash",
          ],
        },
        {
          text: "Optional, before first use: type hermes setup and answer the questions.",
        },
        ...IRONCLAW_MAC,
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
        ...IRONCLAW_UBUNTU,
      ],
    },
  },
  openclaw: {
    windows: {
      intro: "Use Windows Terminal or PowerShell, then Ubuntu.",
      steps: [
        {
          text: "Open PowerShell as Administrator. Type the line below, press Enter, and restart when asked.",
          code: ["wsl --install -d Ubuntu"],
        },
        {
          text: "Open Ubuntu from the Start menu and create a username and password.",
        },
        ...UBU_SETUP,
        ...UBU_GH,
        {
          text: "Open Terminal and type the line below. It installs Node if needed and may ask for your password. Close Terminal, open it again, and type openclaw --version.",
          code: [
            "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard",
          ],
        },
        ...IRONCLAW_UBUNTU,
      ],
    },
    mac: {
      intro: "Use Terminal.",
      steps: [
        ...MAC_PYTHON,
        ...MAC_GIT,
        ...MAC_GH,
        {
          text: "Open Terminal and type the line below. It installs Node if needed and may ask for your Mac password. Close Terminal, open it again, and type openclaw --version.",
          code: [
            "curl -fsSL https://openclaw.ai/install.sh | bash -s -- --no-onboard",
          ],
        },
        ...IRONCLAW_MAC,
      ],
    },
  },
};

const replacePlaceholders = (value, program, claimToken) =>
  value
    .replaceAll("{PROGRAM}", program)
    .replaceAll("{CLAIM_TOKEN}", claimToken);

export default function InstallManual({
  program,
  platformTitle,
  claimToken,
  onClose,
}) {
  const [copiedCode, setCopiedCode] = useState("");
  const selectedClaimToken =
    typeof claimToken === "string" && claimToken
      ? claimToken
      : "your-claim-token";
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

  const sections =
    program === "openclaw"
      ? [
          ["Windows (runs inside Ubuntu)", selected.windows],
          ["Mac", selected.mac],
        ]
      : [
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
              className="flex h-7 w-7 items-center justify-center rounded-md border border-[#FFD700]/55 bg-[#FFD700]/10 text-[#FFD700] transition"
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
                {section.steps.map((step, stepIndex) => {
                  const code = (step.code || [])
                    .map((line) =>
                      replacePlaceholders(line, program, selectedClaimToken),
                    )
                    .join("\n");
                  const codeId = `${heading}-${stepIndex}`;

                  return (
                    <li
                      key={`${heading}-${stepIndex}`}
                      className="text-[11px] leading-relaxed text-[#BFC1C2]"
                    >
                      <p>
                        <span className="mr-2 font-semibold text-white/80">
                          {stepIndex + 1}.
                        </span>
                        {replacePlaceholders(
                          step.text,
                          program,
                          selectedClaimToken,
                        )}
                      </p>
                      {step.code?.length ? (
                        <div className="relative mt-2">
                          <button
                            type="button"
                            onClick={() => copyCode(code, codeId)}
                            className="absolute -top-7 right-0 flex h-6 items-center justify-center rounded-md border px-2 text-[9px] font-semibold transition"
                            style={{
                              borderColor: "#FFD70055",
                              background: "#FFD70014",
                              color: "#FFD700",
                            }}
                            aria-label="Copy install guide code"
                          >
                            {copiedCode === codeId ? (
                              <Check size={10} />
                            ) : (
                              <Copy size={10} />
                            )}
                            <span className="ml-1">Copy</span>
                          </button>
                          <code className="font-tech block w-full overflow-x-auto whitespace-pre-wrap break-words rounded-md border border-white/10 bg-black/50 px-2 py-2 text-[10px] leading-relaxed text-white/90">
                            {code}
                          </code>
                        </div>
                      ) : null}
                    </li>
                  );
                })}
              </ol>
            </section>
          ))}
        </div>
      </div>
    </div>
  );
}
