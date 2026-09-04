import { useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";
import { toast } from "sonner";

const CANONICAL_RUNTIME_COMMANDS = {
  "Claude Code":
    "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent claude-code --scope user",
  OpenClaw:
    "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent openclaw --scope user",
  Cursor:
    "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent cursor --scope user",
  Goose:
    "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent goose --scope user",
  "Gemini CLI":
    "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent gemini-cli --scope user",
  "GitHub Copilot":
    "gh skill install <YOUR_GH_OWNER>/<YOUR_GH_REPO> <YOUR_SKILL_NAME> --agent copilot --scope user",
  Hermes:
    "hermes skills install https://<YOUR_DOMAIN>/skills/<YOUR_SKILL_SLUG>/SKILL.md --name <YOUR_SKILL_NAME>",
};

const IntegrationCard = ({ title, command, tint = "gold", testid }) => {
  const [copied, setCopied] = useState(false);

  const normalizedTitle = typeof title === "string" ? title.trim() : "";
  const normalizedCommand =
    typeof command === "string" && command.trim()
      ? command.trim()
      : CANONICAL_RUNTIME_COMMANDS[normalizedTitle] || "";

  const isRuntimeCard =
    normalizedTitle &&
    normalizedTitle !== "Security Guardian" &&
    normalizedTitle !== "security_guardian";

  const surface = tint === "gold" ? "glass-gold" : "glass-platinum";
  const accent = tint === "gold" ? "#FFD700" : "#E5E4E2";

  const copy = async () => {
    const payload = normalizedCommand;
    if (!payload) {
      return;
    }

    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(payload);
      } else {
        throw new Error("clipboard unavailable");
      }
    } catch {
      const ta = document.createElement("textarea");
      ta.value = payload;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.top = "-9999px";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } finally {
        document.body.removeChild(ta);
      }
    }
    setCopied(true);
    toast.success("Install command copied");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className={`${surface} rounded-xl p-6`} data-testid={testid}>
      <div className="mb-4 flex items-center gap-2">
        <Terminal size={16} style={{ color: accent }} />
        <h3
          className="font-tech text-sm font-semibold uppercase tracking-[0.25em]"
          style={{ color: accent }}
        >
          {normalizedTitle || "Runtime"}
        </h3>
      </div>

      <p className="mb-3 text-xs text-[#BFC1C2]">
        Drop this one-liner into your agent host. Every unit draw and blocked
        attack from this install streams straight to your dashboard.
      </p>

      <div className="flex items-stretch gap-2">
        <code className="font-tech flex-1 overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-white/10 bg-black/50 px-4 py-3 text-xs leading-relaxed text-white/90">
          {normalizedCommand ||
            (isRuntimeCard ? "loading..." : "Unsupported runtime")}
        </code>
        <button
          type="button"
          onClick={copy}
          disabled={!normalizedCommand}
          data-testid={`${testid}-copy`}
          className="flex w-12 shrink-0 items-center justify-center rounded-lg border transition disabled:cursor-not-allowed disabled:opacity-50"
          style={{
            borderColor: `${accent}55`,
            background: `${accent}14`,
            color: accent,
          }}
          aria-label={`Copy ${normalizedTitle || "runtime"} install command`}
        >
          {copied ? <Check size={18} /> : <Copy size={18} />}
        </button>
      </div>
    </div>
  );
};

export default IntegrationCard;
