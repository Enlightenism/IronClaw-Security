import { useEffect, useMemo, useRef, useState } from "react";
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
const hashSeed = (text) => {
  let hash = 2166136261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
};

const createRandom = (seed) => {
  let state = seed;
  return () => {
    state = (state + 0x6d2b79f5) | 0;
    let value = Math.imul(state ^ (state >>> 15), state | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
};

const buildCrackNetwork = (seed, width, height) => {
  const random = createRandom(seed);
  const between = (min, max) => min + (max - min) * random();
  const scale = Math.max(width, height);
  const diagonal = Math.hypot(width, height);
  const impact = [width * between(0.28, 0.72), height * between(0.3, 0.7)];
  const fractures = [];

  const addFracture = (points, kind, strokeWidth) => {
    const middle = points[Math.floor(points.length / 2)];
    const distance = Math.min(
      1,
      Math.hypot(middle[0] - impact[0], middle[1] - impact[1]) /
        (diagonal * 0.6),
    );
    fractures.push({
      id: fractures.length,
      d: points
        .map(
          ([x, y], index) =>
            `${index === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`,
        )
        .join(" "),
      kind,
      strokeWidth,
      delay: 0.1 + distance * 1.3 + random() * 0.15,
      duration: 0.9 + random() * 0.6,
    });
  };

  const grow = (start, heading, length, steps) => {
    const points = [start];
    let cursor = start;
    let direction = heading;
    for (let step = 0; step < steps; step += 1) {
      direction += between(-0.25, 0.25);
      cursor = [
        cursor[0] + (Math.cos(direction) * length) / steps,
        cursor[1] + (Math.sin(direction) * length) / steps,
      ];
      points.push(cursor);
    }
    return points;
  };

  const spokeCount = 6 + Math.floor(random() * 5);
  const baseAngle = random() * Math.PI * 2;
  for (let spoke = 0; spoke < spokeCount; spoke += 1) {
    const heading =
      baseAngle + (spoke / spokeCount) * Math.PI * 2 + between(-0.22, 0.22);
    const spokeLength = diagonal * between(0.55, 0.95);
    const points = grow(
      impact,
      heading,
      spokeLength,
      4 + Math.floor(random() * 3),
    );
    addFracture(points, "spoke", 1.1);
    for (const point of points.slice(2)) {
      if (random() < 0.5) {
        const side = random() < 0.5 ? -1 : 1;
        addFracture(
          grow(
            point,
            heading + side * between(0.5, 0.9),
            spokeLength * between(0.12, 0.22),
            2 + Math.floor(random() * 2),
          ),
          "branch",
          0.7,
        );
      }
    }
  }

  for (let ring = 0; ring < 2; ring += 1) {
    const radius = scale * (0.1 + ring * 0.11 + between(0, 0.04));
    const start = random() * Math.PI * 2;
    const span = between(1.4, 2.6);
    const segments = 6 + Math.floor(random() * 4);
    const points = [];
    for (let segment = 0; segment <= segments; segment += 1) {
      const angle = start + (span * segment) / segments;
      const offset = radius * between(0.92, 1.08);
      points.push([
        impact[0] + Math.cos(angle) * offset,
        impact[1] + Math.sin(angle) * offset,
      ]);
    }
    addFracture(points, "ring", 0.6);
  }

  const edgeCount = 2 + Math.floor(random() * 2);
  for (let edge = 0; edge < edgeCount; edge += 1) {
    const along = between(0, 1);
    const origins = [
      [0, along * height],
      [width, along * height],
      [along * width, 0],
      [along * width, height],
    ];
    const origin = origins[Math.floor(random() * origins.length)];
    const steps = 4 + Math.floor(random() * 3);
    const points = [origin];
    for (let step = 1; step < steps; step += 1) {
      const progress = step / steps;
      points.push([
        origin[0] +
          (impact[0] - origin[0]) * progress +
          between(-scale * 0.03, scale * 0.03),
        origin[1] +
          (impact[1] - origin[1]) * progress +
          between(-scale * 0.03, scale * 0.03),
      ]);
    }
    addFracture(points, "edge", 0.9);
  }

  return { impact, fractures };
};

const crackStyle = (fracture, revealed) => ({
  strokeDasharray: 1,
  strokeDashoffset: revealed ? 0 : 1,
  transition: `stroke-dashoffset ${fracture.duration.toFixed(2)}s cubic-bezier(0.22, 0.61, 0.36, 1) ${fracture.delay.toFixed(2)}s`,
});

const impactStyle = (revealed) => ({
  opacity: revealed ? 1 : 0,
  transition: "opacity 0.6s ease-out 0.05s",
});

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
  const crackRef = useRef(null);
  const [revealed, setRevealed] = useState(false);
  const [size, setSize] = useState({ width: 320, height: 140 });
  const seed = hashSeed(`${String(program)}:${String(integrationId)}`);
  const crackNetwork = useMemo(
    () => buildCrackNetwork(seed, size.width, size.height),
    [seed, size.width, size.height],
  );

  useEffect(() => {
    reducedMotionRef.current = prefersReducedMotion();
    finePointerRef.current = supportsFinePointer();
  }, []);

  useEffect(() => {
    const node = cardRef.current;
    if (!node || typeof ResizeObserver === "undefined") {
      return undefined;
    }

    const observer = new ResizeObserver(() => {
      const width = node.offsetWidth;
      const height = node.offsetHeight;
      if (width > 0 && height > 0) {
        setSize((previous) =>
          previous.width === width && previous.height === height
            ? previous
            : { width, height },
        );
      }
    });
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const node = cardRef.current;
    if (revealed || !node) {
      return undefined;
    }

    if (prefersReducedMotion() || typeof IntersectionObserver === "undefined") {
      setRevealed(true);
      return undefined;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) {
          setRevealed(true);
          observer.disconnect();
        }
      },
      { threshold: 0.35 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [revealed]);

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
    node.style.transform = `perspective(800px) rotateX(${tiltX}deg) rotateY(${tiltY}deg) translateZ(10px)`;
    if (crackRef.current) {
      crackRef.current.style.transform = `translate3d(${(-tiltY * 0.9).toFixed(2)}px, ${(tiltX * 0.9).toFixed(2)}px, 0)`;
    }
  };

  const handlePointerLeave = () => {
    const node = cardRef.current;
    if (!node) {
      return;
    }

    node.style.transform =
      "perspective(800px) rotateX(0deg) rotateY(0deg) translateZ(0)";
    if (crackRef.current) {
      crackRef.current.style.transform = "translate3d(0px, 0px, 0)";
    }
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
        ref={crackRef}
        aria-hidden="true"
        data-testid={`${testid}-cracks`}
        viewBox={`0 0 ${size.width} ${size.height}`}
        className="pointer-events-none absolute inset-0 -z-10 h-full w-full transition-transform duration-200 ease-out"
      >
        <g transform="translate(1 1)">
          {crackNetwork.fractures.map((fracture) => (
            <path
              key={`shadow-${fracture.id}`}
              d={fracture.d}
              pathLength={1}
              fill="none"
              strokeLinecap="round"
              strokeLinejoin="round"
              stroke="rgba(0,0,0,0.5)"
              strokeWidth={fracture.strokeWidth}
              style={crackStyle(fracture, revealed)}
            />
          ))}
        </g>
        {crackNetwork.fractures.map((fracture) => (
          <path
            key={`light-${fracture.id}`}
            d={fracture.d}
            pathLength={1}
            fill="none"
            strokeLinecap="round"
            strokeLinejoin="round"
            stroke="rgba(255,255,255,0.45)"
            strokeWidth={fracture.strokeWidth * 0.6}
            style={crackStyle(fracture, revealed)}
          />
        ))}
        <g style={impactStyle(revealed)}>
          <circle
            cx={crackNetwork.impact[0]}
            cy={crackNetwork.impact[1]}
            r={6}
            fill="none"
            stroke="rgba(255,255,255,0.35)"
            strokeWidth={0.8}
          />
          <circle
            cx={crackNetwork.impact[0]}
            cy={crackNetwork.impact[1]}
            r={2.2}
            fill="rgba(255,255,255,0.7)"
          />
        </g>
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
