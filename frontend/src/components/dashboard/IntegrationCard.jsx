import { useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";
import { toast } from "sonner";

const INSTALL_KEY_PREFIXES = {
  claude_code: "ic_install_claude_code_",
  openclaw: "ic_install_openclaw_",
  cursor: "ic_install_cursor_",
  goose: "ic_install_goose_",
  gemini_cli: "ic_install_gemini_cli_",
  copilot: "ic_install_copilot_",
  hermes: "ic_install_hermes_",
};
const SECURITY_GUARDIAN_ALIASES = new Set([
  "security guardian",
  "security_guardian",
  "security-guardian",
  "securityguardian",
  "security guardian skill",
  "security_guardian_skill",
  "skill",
  "skills",
]);

const RUNTIME_TITLE_ALIASES = {
  "claude code": "Claude Code",
  claude_code: "Claude Code",
  openclaw: "OpenClaw",
  cursor: "Cursor",
  goose: "Goose",
  "gemini cli": "Gemini CLI",
  gemini_cli: "Gemini CLI",
  "github copilot": "GitHub Copilot",
  copilot: "GitHub Copilot",
  hermes: "Hermes",
};

const normalizeRuntimeKey = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  return value
    .trim()
    .toLowerCase()
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
};

const resolveCanonicalTitle = (value) => {
  if (typeof value !== "string") {
    return "";
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return "";
  }

  const normalized = normalizeRuntimeKey(trimmed);
  if (!normalized) {
    return "";
  }

  if (RUNTIME_TITLE_ALIASES[normalized]) {
    return RUNTIME_TITLE_ALIASES[normalized];
  }

  return trimmed;
};

const resolveCanonicalRuntimeKey = (value) => {
  const title = resolveCanonicalTitle(value);
  if (!title) {
    return "";
  }

  const normalized = normalizeRuntimeKey(title);
  const keyMap = {
    "claude code": "claude_code",
    openclaw: "openclaw",
    cursor: "cursor",
    goose: "goose",
    "gemini cli": "gemini_cli",
    "github copilot": "copilot",
    hermes: "hermes",
  };

  return keyMap[normalized] || "";
};

const isSecurityGuardian = (value) => {
  const key = normalizeRuntimeKey(value);
  return Boolean(key) && SECURITY_GUARDIAN_ALIASES.has(key);
};

const GENERIC_TOKEN_PATTERNS = [
  /--token\s*(?:=|\b)/i,
  /token\s+(?:placeholder|loading|example|your|demo)/i,
  /api[-_\s]?key\s*(?:=|\b)/i,
  /gh\s+auth\s+(?:login|status|token)/i,
  /placeholder/i,
  /loading/i,
  /<token>/i,
  /your\s+(?:api|install)\s+(?:key|token)/i,
  /example\s+(?:key|token)/i,
  /\b(?:demo|sample)\b/i,
];

const looksLikeTokenCommand = (value) => {
  if (typeof value !== "string") {
    return true;
  }

  const candidate = value.trim();
  if (!candidate) {
    return true;
  }

  if (GENERIC_TOKEN_PATTERNS.some((pattern) => pattern.test(candidate))) {
    return true;
  }

  return !/--key\s+ic_install_[A-Za-z0-9_./~:-]+/i.test(candidate);
};

const hasEmbeddedInstallKey = (command, runtimeKey) => {
  if (!runtimeKey || typeof command !== "string") {
    return false;
  }

  const candidate = command.trim();
  if (!candidate || looksLikeTokenCommand(candidate)) {
    return false;
  }

  const prefix = INSTALL_KEY_PREFIXES[runtimeKey];
  if (!prefix) {
    return false;
  }

  return new RegExp(
    `--key\\s+${prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[A-Za-z0-9_./~:-]+`,
    "i",
  ).test(candidate);
};

const commandMatchesRuntime = (command, runtimeKey) => {
  if (!runtimeKey || typeof command !== "string") {
    return false;
  }

  const candidate = command.trim();
  if (!candidate || looksLikeTokenCommand(candidate)) {
    return false;
  }

  if (!hasEmbeddedInstallKey(candidate, runtimeKey)) {
    return false;
  }

  switch (runtimeKey) {
    case "claude_code":
      return /^gh\s+skill\s+install\b.*--agent\s+claude-code\b.*--key\s+ic_install_claude_code_[A-Za-z0-9_./~:-]+/i.test(
        candidate,
      );
    case "openclaw":
      return /^gh\s+skill\s+install\b.*--agent\s+openclaw\b.*--key\s+ic_install_openclaw_[A-Za-z0-9_./~:-]+/i.test(
        candidate,
      );
    case "cursor":
      return /^gh\s+skill\s+install\b.*--agent\s+cursor\b.*--key\s+ic_install_cursor_[A-Za-z0-9_./~:-]+/i.test(
        candidate,
      );
    case "goose":
      return /^gh\s+skill\s+install\b.*--agent\s+goose\b.*--key\s+ic_install_goose_[A-Za-z0-9_./~:-]+/i.test(
        candidate,
      );
    case "gemini_cli":
      return /^gh\s+skill\s+install\b.*--agent\s+gemini-cli\b.*--key\s+ic_install_gemini_cli_[A-Za-z0-9_./~:-]+/i.test(
        candidate,
      );
    case "copilot":
      return /^gh\s+skill\s+install\b.*--agent\s+copilot\b.*--key\s+ic_install_copilot_[A-Za-z0-9_./~:-]+/i.test(
        candidate,
      );
    case "hermes":
      return /^hermes\s+skills\s+install\b.*--key\s+ic_install_hermes_[A-Za-z0-9_./~:-]+/i.test(
        candidate,
      );
    default:
      return false;
  }
};

const resolveCommand = (title, command) => {
  const runtimeKey = resolveCanonicalRuntimeKey(title);
  if (!runtimeKey) {
    return "";
  }

  const rawCommand = typeof command === "string" ? command.trim() : "";
  if (!rawCommand) {
    return "";
  }

  return commandMatchesRuntime(rawCommand, runtimeKey) ? rawCommand : "";
};

const IntegrationCard = ({ title, command, tint = "gold", testid }) => {
  const [copied, setCopied] = useState(false);

  const canonicalTitle = resolveCanonicalTitle(title);
  const runtimeKey = resolveCanonicalRuntimeKey(canonicalTitle);

  if (!canonicalTitle || isSecurityGuardian(canonicalTitle) || !runtimeKey) {
    return null;
  }

  const normalizedCommand = resolveCommand(canonicalTitle, command);

  if (!normalizedCommand) {
    return null;
  }

  const surface = tint === "gold" ? "glass-gold" : "glass-platinum";
  const accent = tint === "gold" ? "#FFD700" : "#E5E4E2";

  const copy = async () => {
    try {
      if (navigator?.clipboard?.writeText) {
        await navigator.clipboard.writeText(normalizedCommand);
      } else {
        throw new Error("clipboard unavailable");
      }
    } catch {
      const ta = document.createElement("textarea");
      ta.value = normalizedCommand;
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
          {canonicalTitle}
        </h3>
      </div>

      <p className="mb-3 text-xs text-[#BFC1C2]">
        Drop this one-liner into your agent host. Every unit draw and blocked
        attack from this install streams straight to your dashboard.
      </p>

      <div className="flex items-stretch gap-2">
        <code className="font-tech flex-1 overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-white/10 bg-black/50 px-4 py-3 text-xs leading-relaxed text-white/90">
          {normalizedCommand}
        </code>
        <button
          type="button"
          onClick={copy}
          data-testid={`${testid}-copy`}
          className="flex w-12 shrink-0 items-center justify-center rounded-lg border transition disabled:cursor-not-allowed disabled:opacity-50"
          style={{
            borderColor: `${accent}55`,
            background: `${accent}14`,
            color: accent,
          }}
          aria-label={`Copy ${canonicalTitle} install command`}
        >
          {copied ? <Check size={18} /> : <Copy size={18} />}
        </button>
      </div>
    </div>
  );
};

export default IntegrationCard;
