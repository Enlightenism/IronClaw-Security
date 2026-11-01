import { useEffect, useRef, useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";
import { toast } from "sonner";

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

const CLAIM_TOKEN_PATTERN = /^ic_claim_[A-Za-z0-9_-]{20,128}$/;
const RUNTIME_PROGRAM_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;
const INSTALLER_SOURCE_COMMAND =
  "python -m pip install --no-deps --upgrade git+https://github.com/Enlightenism/IronClaw-Security.git";
const PLACEHOLDER_TEXT = "Generate a one-time bootstrap command after purchase";
const CRACK_PATHS = [
  "M74 34 L62 22 L48 14",
  "M62 22 L56 10",
  "M48 14 L40 6",
  "M74 34 L88 27 L97 19",
  "M88 27 L92 14",
  "M74 34 L82 50 L94 60",
  "M82 50 L70 58",
  "M74 34 L56 42 L40 40 L26 47 L14 42",
  "M56 42 L52 30",
  "M40 40 L34 26",
  "M26 47 L24 62",
  "M74 34 L60 56 L52 74 L56 92",
  "M52 74 L38 80",
  "M60 56 L72 62",
  "M96 96 L88 80 L84 70",
  "M88 80 L78 84",
  "M84 70 L92 62",
];
const CRACK_LINE_PROPS = {
  fill: "none",
  strokeLinecap: "round",
  strokeLinejoin: "round",
  vectorEffect: "non-scaling-stroke",
};

const validateInstallClaim = (claim, program, integrationId) => {
  if (
    !claim ||
    claim.program !== program ||
    claim.integration_id !== integrationId ||
    typeof program !== "string" ||
    !RUNTIME_PROGRAM_PATTERN.test(program) ||
    typeof claim.claim_token !== "string" ||
    !CLAIM_TOKEN_PATTERN.test(claim.claim_token) ||
    typeof claim.command !== "string" ||
    claim.command.length > 512 ||
    typeof claim.expires_at !== "string"
  ) {
    return null;
  }

  const expectedCommand = `${INSTALLER_SOURCE_COMMAND}\npython -m ironclaw_installer bootstrap --program ${program} --claim-token ${claim.claim_token}`;
  const expiresAt = Date.parse(claim.expires_at);

  if (
    claim.command !== expectedCommand ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= Date.now()
  ) {
    return null;
  }

  return { command: claim.command.trim(), expiresAt };
};

const prefersReducedMotion = () =>
  typeof window !== "undefined" &&
  typeof window.matchMedia === "function" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

const supportsFinePointer = () =>
  typeof window !== "undefined" &&
  typeof window.matchMedia === "function" &&
  window.matchMedia("(hover: hover) and (pointer: fine)").matches;

const IntegrationCard = ({
  title,
  program,
  integrationId,
  available = false,
  onCreateClaim,
  tint = "gold",
  testid,
}) => {
  const [copied, setCopied] = useState(false);
  const [pressed, setPressed] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [installCommand, setInstallCommand] = useState("");
  const [claimExpiresAt, setClaimExpiresAt] = useState(null);
  const cardRef = useRef(null);
  const reducedMotionRef = useRef(false);
  const finePointerRef = useRef(false);

  useEffect(() => {
    reducedMotionRef.current = prefersReducedMotion();
    finePointerRef.current = supportsFinePointer();
  }, []);

  useEffect(() => {
    if (available) {
      return undefined;
    }

    setInstallCommand("");
    setClaimExpiresAt(null);
    return undefined;
  }, [available]);

  useEffect(() => {
    if (claimExpiresAt === null) {
      return undefined;
    }

    const delay = claimExpiresAt - Date.now();
    if (delay <= 0) {
      setInstallCommand("");
      setClaimExpiresAt(null);
      return undefined;
    }

    const timeout = globalThis.setTimeout(() => {
      setInstallCommand("");
      setClaimExpiresAt(null);
    }, delay);

    return () => globalThis.clearTimeout(timeout);
  }, [claimExpiresAt]);

  const canonicalTitle = typeof title === "string" ? title.trim() : "";
  if (
    !canonicalTitle ||
    typeof program !== "string" ||
    !program ||
    program === "security_guardian" ||
    typeof integrationId !== "string" ||
    !integrationId.trim()
  ) {
    return null;
  }

  const normalizedCommand = available === true ? installCommand : "";
  const isLocked = !normalizedCommand;
  const canGenerate = available === true && typeof onCreateClaim === "function";

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

  const generate = async () => {
    if (!canGenerate || generating) {
      return;
    }

    setGenerating(true);
    try {
      const claim = await onCreateClaim(integrationId);
      const validatedClaim = validateInstallClaim(
        claim,
        program,
        integrationId,
      );
      if (!validatedClaim) {
        throw new Error("The install claim response is invalid.");
      }

      setInstallCommand(validatedClaim.command);
      setClaimExpiresAt(validatedClaim.expiresAt);
      setCopied(false);
      toast.success("One-time install command generated");
    } catch {
      toast.error(
        "Unable to generate a secure install command. Please try again.",
      );
    } finally {
      setGenerating(false);
    }
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
      className={`${surface} relative isolate touch-manipulation rounded-lg p-3 transition-transform duration-200 ease-out will-change-transform ${
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
      {/* Sits under the content: `isolate` scopes -z-10 above the card background. */}
      <svg
        aria-hidden="true"
        data-testid={`${testid}-cracks`}
        viewBox="0 0 100 100"
        preserveAspectRatio="none"
        className="pointer-events-none absolute inset-0 -z-10 h-full w-full"
      >
        <g transform="translate(0.5 0.5)">
          {CRACK_PATHS.map((d) => (
            <path
              key={`shadow-${d}`}
              d={d}
              {...CRACK_LINE_PROPS}
              stroke="rgba(0,0,0,0.5)"
              strokeWidth="1"
            />
          ))}
        </g>
        {CRACK_PATHS.map((d) => (
          <path
            key={`light-${d}`}
            d={d}
            {...CRACK_LINE_PROPS}
            stroke="rgba(255,255,255,0.45)"
            strokeWidth="0.6"
          />
        ))}
      </svg>
      <div className="mb-2 flex items-center gap-1.5">
        <Terminal size={12} style={{ color: accent }} />
        <h3
          className="font-tech text-xs font-semibold uppercase tracking-[0.2em]"
          style={{ color: accent }}
        >
          {canonicalTitle}
        </h3>
      </div>

      <p className="mb-2 text-[11px] leading-snug text-[#BFC1C2]">
        Install commands will be available to generate after purchase, and will
        have a unique user key embedded into the install command for your
        account.
      </p>

      <div className="flex items-stretch gap-1.5">
        <code
          className={`font-tech flex-1 overflow-x-auto whitespace-pre-wrap break-words rounded-md border border-white/10 bg-black/50 px-2 py-1.5 text-[10px] leading-relaxed ${
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
          className="flex w-7 shrink-0 items-center justify-center rounded-md border transition disabled:cursor-not-allowed disabled:opacity-50"
          style={{
            borderColor: `${accent}55`,
            background: `${accent}14`,
            color: accent,
          }}
          aria-label={
            isLocked
              ? canGenerate
                ? `Generate a one-time ${canonicalTitle} install command before copying`
                : `${canonicalTitle} install command locked until purchase`
              : `Copy ${canonicalTitle} install command`
          }
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
        </button>
      </div>
      {claimExpiresAt !== null ? (
        <p className="mt-1 text-[10px] text-white/50">
          This one-time command expires{" "}
          {new Date(claimExpiresAt).toLocaleTimeString()}.
        </p>
      ) : null}
      <button
        type="button"
        onClick={generate}
        disabled={!canGenerate || generating}
        data-testid={`${testid}-generate`}
        className="mt-2 rounded-md border px-2 py-1 text-[10px] font-semibold transition disabled:cursor-not-allowed disabled:opacity-50"
        style={{
          borderColor: `${accent}55`,
          background: `${accent}14`,
          color: accent,
        }}
      >
        {generating
          ? "Generating..."
          : normalizedCommand
            ? "Generate a new one-time command"
            : "Generate one-time install command"}
      </button>
    </div>
  );
};

export default IntegrationCard;
