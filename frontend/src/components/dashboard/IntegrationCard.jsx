import { useEffect, useRef, useState } from "react";
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

const TINT_STYLES = {
  gold: { surface: "glass-gold", accent: "#FFD700" },
  platinum: { surface: "glass-platinum", accent: "#E5E4E2" },
  cyan: { surface: "glass-blue", accent: "#38BDF8" },
  violet: { surface: "glass-violet", accent: "#A855F7" },
  emerald: { surface: "glass-emerald", accent: "#34D399" },
  indigo: { surface: "glass-indigo", accent: "#818CF8" },
  amber: { surface: "glass-amber", accent: "#FDE047" },
};

const DEFAULT_TINT_STYLE = TINT_STYLES.platinum;

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

const PLACEHOLDER_TEXT = "Install key will be generated after purchase";

const prefersReducedMotion = () =>
  typeof window !== "undefined" &&
  typeof window.matchMedia === "function" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const supportsFinePointer = () =>
  typeof window !== "undefined" &&
  typeof window.matchMedia === "function" &&
  window.matchMedia("(hover: hover) and (pointer: fine)").matches;

const IntegrationCard = ({ title, command, tint = "gold", testid }) => {
  const [copied, setCopied] = useState(false);
  const [pressed, setPressed] = useState(false);
  const cardRef = useRef(null);
  const reducedMotionRef = useRef(false);
  const finePointerRef = useRef(false);

  useEffect(() => {
    reducedMotionRef.current = prefersReducedMotion();
    finePointerRef.current = supportsFinePointer();
  }, []);

  const canonicalTitle = resolveCanonicalTitle(title);
  const runtimeKey = resolveCanonicalRuntimeKey(canonicalTitle);

  if (!canonicalTitle || isSecurityGuardian(canonicalTitle) || !runtimeKey) {
    return null;
  }

  const normalizedCommand = resolveCommand(canonicalTitle, command);
  const isLocked = !normalizedCommand;

  const { surface, accent } = TINT_STYLES[tint] || DEFAULT_TINT_STYLE;

  const handlePointerMove = (event) => {
    if (reducedMotionRef.current || !finePointerRef.current) {
      return;
    }

    const node = cardRef.current;
    if (!node) {
      return;
    }

    const rect = node.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width) * 100;
    const y = ((event.clientY - rect.top) / rect.height) * 100;
    const tiltX = ((event.clientY - rect.top) / rect.height - 0.5) * -6;
    const tiltY = ((event.clientX - rect.left) / rect.width - 0.5) * 6;

    node.style.setProperty("--mx", `${x}%`);
    node.style.setProperty("--my", `${y}%`);
    node.style.transform = `perspective(800px) rotateX(${tiltX}deg) rotateY(${tiltY}deg) translateZ(0)`;
  };

  const handlePointerLeave = () => {
    const node = cardRef.current;
    if (!node) {
      return;
    }

    node.style.transform =
      "perspective(800px) rotateX(0deg) rotateY(0deg) translateZ(0)";
    node.style.setProperty("--mx", "50%");
    node.style.setProperty("--my", "50%");
  };

  const handleTouchStart = () => {
    if (reducedMotionRef.current) {
      return;
    }
    setPressed(true);
  };

  const handleTouchEnd = () => {
    setPressed(false);
  };

  const copy = async () => {
    if (isLocked) {
      return;
    }

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
    <div
      ref={cardRef}
      className={`${surface} touch-manipulation rounded-xl p-6 transition-transform duration-200 ease-out will-change-transform ${
        pressed ? "scale-[0.97]" : "scale-100"
      }`}
      style={{
        "--mx": "50%",
        "--my": "50%",
        backgroundImage:
          "radial-gradient(circle at var(--mx) var(--my), rgba(255,255,255,0.06), transparent 55%)",
      }}
      onMouseMove={handlePointerMove}
      onMouseLeave={handlePointerLeave}
      onTouchStart={handleTouchStart}
      onTouchEnd={handleTouchEnd}
      onTouchCancel={handleTouchEnd}
      data-testid={testid}
    >
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
        <code
          className={`font-tech flex-1 overflow-x-auto whitespace-pre-wrap break-words rounded-lg border border-white/10 bg-black/50 px-4 py-3 text-xs leading-relaxed ${
            isLocked ? "italic text-white/40" : "text-white/90"
          }`}
        >
          {isLocked ? PLACEHOLDER_TEXT : normalizedCommand}
        </code>
        <button
          type="button"
          onClick={copy}
          disabled={isLocked}
          data-testid={`${testid}-copy`}
          className="flex w-12 shrink-0 items-center justify-center rounded-lg border transition disabled:cursor-not-allowed disabled:opacity-50"
          style={{
            borderColor: `${accent}55`,
            background: `${accent}14`,
            color: accent,
          }}
          aria-label={
            isLocked
              ? `${canonicalTitle} install command locked until purchase`
              : `Copy ${canonicalTitle} install command`
          }
        >
          {copied ? <Check size={18} /> : <Copy size={18} />}
        </button>
      </div>
    </div>
  );
};

export default IntegrationCard;
