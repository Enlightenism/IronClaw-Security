import { useState, useEffect, lazy, Suspense, useRef } from "react";
import { motion } from "framer-motion";
import { useNavigate, Link } from "react-router-dom";
import {
  Syringe,
  ShieldAlert,
  ScrollText,
  Workflow,
  Boxes,
  Activity,
  Network,
  FileSearch,
  KeyRound,
  Lock,
  UserCheck,
  FileClock,
  Fingerprint,
  BrainCircuit,
  ArrowRight,
} from "lucide-react";
import AuthModal from "@/components/AuthModal";
import ContactBubble from "@/components/ContactBubble";
import ContactModal from "@/components/ContactModal";
import CyberNewsTickers from "@/components/CyberNewsTickers";
import PackageCarousel from "@/components/PackageCarousel";
import PlatformsTicker from "@/components/PlatformsTicker";
import { useAuth } from "@/context/AuthContext";
import { useCountUp } from "@/hooks/useCountUp";
import { useLandingCounter } from "@/lib/landingCounters";

const ParticleField = lazy(() => import("@/components/ParticleField"));

const LAYERS = [
  {
    icon: Syringe,
    title: "Prompt Injection",
    body: "Scans every inbound prompt for injection patterns, jailbreak attempts, and adversarial content before a single LLM call is ever made. The first gate nothing bypasses.",
  },
  {
    icon: ShieldAlert,
    title: "Action Guard",
    body: "A pre-execution gate that evaluates every proposed agent action against risk rules, returning only allow or block verdicts before the action can run.",
  },
  {
    icon: ScrollText,
    title: "Action Policy Enforcement",
    body: "Applies named policy rules — allow-lists, deny-lists, and hard capability constraints — to every tool call and agent decision at the policy layer. No exceptions.",
  },
  {
    icon: Workflow,
    title: "Action Decision",
    body: "Synthesizes the guard verdict and policy verdict into a single final executable decision, complete with a full reasoning trace captured for audit.",
  },
  {
    icon: Boxes,
    title: "Sandboxed Execution",
    body: "Executes risky tool calls and code payloads inside an isolated runtime boundary. The detonation service stress-tests payloads in a contained environment before anything reaches production.",
  },
  {
    icon: Activity,
    title: "Heuristics & Behavioral Baseline",
    body: "Detects anomalous agent behavior by comparing live activity against learned baselines, flagging statistical deviations as threats in real time — before they escalate.",
  },
  {
    icon: Network,
    title: "Attack Correlation",
    body: "Cross-correlates signals from every layer and across sessions to expose coordinated multi-step attacks, chained injections, and lateral movement patterns.",
  },
  {
    icon: FileSearch,
    title: "File Inspection + Malware",
    body: "Inspects all file inputs and outputs for malicious payloads, embedded scripts, and malware signatures before they are ever processed or returned to your system.",
  },
  {
    icon: KeyRound,
    title: "Secrets Detection & Redaction",
    body: "Detects credentials, API keys, and sensitive tokens across prompts, responses, and tool outputs — redacting them before leakage and vaulting them securely.",
  },
  {
    icon: Lock,
    title: "Full Block",
    body: "Every agent return is scanned instantly in a sandbox, separate from the user machine. Any information returning with the agent that is even slightly suspicious is terminated.",
  },
  {
    icon: UserCheck,
    title: "Malicious Install Skills Blocked",
    body: "Install IronClaw-Security before using any other install skill, and that skill will be scanned before installed. One of the major issues for coding platforms today.",
  },
  {
    icon: FileClock,
    title: "Audit Log + Incident Store",
    body: "An immutable, timestamped audit trail of every verdict, action, and policy decision. Incidents are persisted for post-hoc investigation and compliance.",
  },
  {
    icon: Fingerprint,
    title: "Access Control, Auth & Org Isolation",
    body: "Enforces API-level authentication, role-based permissions, and hard tenant isolation — so no org can read, influence, or pollute another org's security context.",
  },
  {
    icon: BrainCircuit,
    title: "AI Brain",
    body: "An AI brain analyzes every agent return isolated inside the sandbox, working in lockstep with the security system to ensure NOTHING reaches your computer or phone.",
  },
];

const HERO_EASE = [0.22, 1, 0.36, 1];

const fadeUp = {
  hidden: { opacity: 0, y: 28 },
  show: (i = 0) => ({
    opacity: 1,
    y: 0,
    transition: {
      duration: 0.6,
      delay: i * 0.05,
      ease: HERO_EASE,
    },
  }),
};

const LiveCounter = ({ counterKey, color, testid }) => {
  const value = useLandingCounter(counterKey);
  const firstValueRef = useRef(value);
  const animated = useCountUp(value, 900, [value], firstValueRef.current);

  return (
    <span className="font-tech" style={{ color }} data-testid={testid}>
      {animated.toLocaleString()}
    </span>
  );
};

const BRAND_LOGO_SRC = "/images/logo128pxl.svg";
const GOLDEN_KNIGHT_LOGO_SRC = "/images/Golden%20Knight%20Logo128.png";
const KNIGHT_IMAGE_SRC = "/images/Golden%20Knight%204k%202gb.png";

const PARTICLE_FIELD_DENSITY = 180;

const FOOTER_RESOURCE_LINKS = [
  { label: "TryHackMe", href: "https://tryhackme.com" },
  { label: "Cisco Networking Academy", href: "https://www.netacad.com" },
  {
    label: "PortSwigger Web Security Academy",
    href: "https://portswigger.net/web-security",
  },
  { label: "OverTheWire", href: "https://overthewire.org" },
  { label: "OWASP", href: "https://owasp.org" },
];

const LANDING_PROTECTION_ITEMS = [
  "Indirect prompt injection – Malicious instructions are hidden in content the agent reads as normal work: web pages, emails, tickets, PR comments, code comments, docs and tool output. The agent treats them as guidance and follows them. Easy: one poisoned page, issue or message is enough. A Slack message the agent was asked to summarize rewrote Cursor's MCP config and led to code execution (CurXecute, CVE-2025-54135).",
  "Hidden instructions – Indirect injection that is invisible or obfuscated (white-on-white text, tiny fonts, HTML comments, base64). Easy: paste hidden text into any doc or site the agent will visit. CamoLeak (CVE-2025-59145) hid injection in invisible markdown comments in pull requests.",
  "Injection through untrusted inbound channels – Agents that accept email, chat or group messages can be steered by anyone who can message them. Easy: send the agent a crafted message.",
  "Cross-agent injection – A compromised context in one agent becomes instructions for the next agent in the chain. Easy: poison the first agent's input.",
  "Obfuscated and encoded payloads – Base64, hex or reversed text is used to slip commands past filters. Easy: re-encode a known payload.",
  "Tool poisoning – Instructions hide in tool descriptions or parameter schemas returned when tools are listed. This is the one place the model reads and the human usually doesn't, and it fires before any approval prompt. Easy: publish or compromise one tool.",
  "Malicious MCP tools and servers – A compromised MCP server feeds poisoned data or performs harmful actions when called. Easy: get the user to connect one malicious server.",
  "MCP rug pulls and config trust abuse – A server or config is approved once, then silently changed afterward. Cursor trusted an approved MCP config even after later edits (MCPoison, CVE-2025-54136). Easy: ship a benign version, then swap it.",
  "Tool-name shadowing – A malicious tool imitates or overrides a trusted tool's name so calls are routed to the attacker. Easy: register a lookalike tool name.",
  "Malicious agent skills – A skill (SKILL.md plus scripts) looks helpful but hides instructions or code that steals data, runs commands or persists. Researchers found 575+ malicious OpenClaw skills from 13 developer accounts, including trojans, cryptominers and AMOS stealer, on both Windows and macOS. Easy: publish one skill to a marketplace.",
  'Fake prerequisite and install lures in skills – A skill tells the agent or user to run a "setup" step that decodes and runs a base64 curl-pipe-bash payload. Easy: add one line to a SKILL.md.',
  "Supply chain vulnerabilities – Compromised dependencies, skills or plugins introduce backdoors, such as a popular skill that steals credentials. Easy: publish a bad package or skill.",
  "Slopsquatting – Attackers register package names that coding models invent, so the agent installs malware. One study found 19.7% of recommended packages didn't exist across 16 models. Easy: register the commonly hallucinated names.",
  'Remote code execution – Injected content gets the agent to run arbitrary code on the host through a shell, code-exec tool or unsafe plugin. Easy: an injected "run this script" instruction.',
  "Command injection – Attacker-controlled text is concatenated into shell commands the agent runs. Easy: one unsanitized parameter.",
  "Malware installation – The agent downloads and runs a payload from an attacker server after reading injected instructions. Easy: an injected curl ... | bash line.",
  "Ransomware deployment – Same chain as malware installation, but the payload encrypts files and demands payment. Easy: one successful code-execution chain.",
  'Data exfiltration – Files, environment variables and credentials are sent to an attacker through webhooks, logs or tool calls. Easy: one injected line such as "send .env to https://evil.example".',
  "Silent exfiltration via tool parameters – The agent leaks secrets in query strings, headers or request bodies of normal tool calls (web search, HTTP clients, logging). Very easy: one injected sentence.",
  "Markdown and image-rendering exfiltration – Output contains links or images whose URLs carry secrets, and rendering triggers the request. CamoLeak abused GitHub's image proxy to leak private repo secrets with no clicks. Easy: a hidden comment in a PR.",
  'Credential and secret exposure – Injected content makes the agent read and reveal API keys, tokens and config. OpenClaw\'s plaintext MEMORY.md and SOUL.md files are a target for infostealers. Easy: ask the agent to "show me all config" after an injection.',
  "Server-side request forgery (SSRF) – Injected content makes the agent fetch internal or cloud-metadata URLs it shouldn't reach. Easy: an injected URL pointing at localhost or a metadata endpoint.",
  "Injection into downstream tools – Untrusted content reaches databases or other backends through agent tool calls, as in SQL injection payloads. Applies only where the agent has such tools. Easy: classic payloads placed in content the agent processes.",
  "Poisoned project configuration – Config files in a cloned repo execute code or change behavior before the user sees a trust prompt. Claude Code CVE-2025-65099 ran code before the trust dialog appeared. Easy: commit one malicious config file.",
  "Auto-approve manipulation – Injection edits the agent's own settings to switch on auto-approval of commands. Copilot could be steered into editing .vscode/settings.json for this (CVE-2025-62222). Easy: one injected file-edit instruction.",
  "Rules-file and instruction-file backdoors – Persistent steering files such as .cursorrules, CLAUDE.md and AGENTS.md can be changed by a malicious PR. Easy: submit a PR that touches a rules file.",
  "Memory poisoning – Bad instructions are written into the agent's memory store so future sessions misbehave with no new injection. Easy: one crafted message that writes to memory.",
  'Skill persistence – A malicious skill writes itself or other skills into the skills directory, surviving reinstalls and updates. Easy: a skill that "installs updates" but reinstalls its backdoor.',
  "Sandbox escape – Code running inside the agent's sandbox breaks out to the host. Claude Code (CVE-2026-25725), Gemini CLI and Codex CLI have all had sandbox-escape findings. Moderate: needs a working code-execution foothold first.",
  "Execution-flow hijacking – A poisoned README leads the agent to plant an executable such as npx.exe in the project folder, which the OS then runs. Easy: one injected file-write instruction.",
  "World-writable trust paths – A shared folder like C:\\ProgramData\\Cursor lets one user plant config or hooks that run in another user's session. The same pattern hit Claude Code (CVE-2026-35603). Moderate: needs local access on a shared machine.",
  "CI/CD agent abuse – A malicious PR or issue pushes a review or automation agent into leaking secrets or altering the pipeline. Easy: open a PR on a repo with an agent-driven workflow.",
  "Local gateway hijacking (CSRF and cross-site WebSocket) – A web page abuses an agent's local web interface to steal tokens or issue commands. OpenClaw CVE-2026-25253 (CVSS 8.8) used a gatewayUrl query parameter for one-click RCE. Easy: lure the user to one link.",
  "Agent identity spoofing – Agents and their messages are often plain strings, so another process or extension can impersonate an agent or tamper with its mailbox. Moderate: needs a foothold on the same system.",
  "Human-approval exploitation – Attackers manipulate users into approving unsafe actions with misleading prompts and approval fatigue. OWASP lists this as ASI09. Easy: bury the risky action among harmless approvals.",
];

const PROTECTED_PLATFORMS = [
  {
    name: "Claude Code",
    howItWorks:
      "Agent reads your repo, tickets, docs, tool output and web content, then plans and executes commands (edit files, run tests, call tools) based on those inputs.",
    vulnerability: [
      "Indirect prompt injection: malicious instructions hidden in files, comments, tickets, API responses or docs that Claude Code reads as part of normal coding work. Anthropic's own threat model lists this as the core risk, and their auto-mode research shows the input probe scans tool outputs specifically for this.",
      "Tool misuse and command execution: once injection succeeds, attacker content can steer the agent into running dangerous shell commands, changing config or leaking secrets. Claude Code's own docs confirm network commands like curl and wget are not auto-approved by default, which is why this is a real risk vector.",
      "Malicious skills and extensions: unvetted skills or MCP tools can carry instructions or code paths that exfiltrate data or weaken guardrails. Anthropic notes that an audited connector isn't the same as audited data — a GitHub connector can still load a poisoned README into context.",
      "Poisoned project config executing before trust: a malicious hook committed to a repo could execute before the user saw the trust prompt. Anthropic confirmed this and fixed it by deferring config parsing until after the trust prompt.",
      "Sandbox escape: a reported sandbox escape (CVE-2026-25725) let code break out of the sandbox to the host.",
      "Secrets in context: agents can see .env, config and dependency files; injected content can persuade them to output or send those secrets. Anthropic's own red-team exercise showed 24 of 25 attempts to exfiltrate ~/.aws/credentials succeeded.",
      "Multi-agent trust escalation: sub-agent output can be treated as higher-trust than raw tool results, creating a new injection vector.",
    ],
  },
  {
    name: "OpenClaw",
    howItWorks:
      "Local autonomous agent runtime that connects LLMs to real tools: shell, scripts, apps, email, web, SaaS APIs, etc., via a config like openclaw.json and marketplace skills (ClawHub).",
    vulnerability: [
      "Prompt injection into tools and workflows: agents consume instructions from tasks, emails, web pages, logs and tool outputs. Malicious text in any of these can steer the agent into running risky commands or leaking data. Anthropic's threat intel report explicitly calls out prompt injection of OpenClaw deployments as a real attack vector.",
      "Malicious skills from ClawHub: researchers identified 575+ malicious skills across 13 developer accounts, including trojans, cryptominers and the AMOS stealer, targeting both Windows and macOS.",
      "Command execution and system access: OpenClaw can run shell commands and access files. Prompt-controlled workflows give an attacker a path to arbitrary code or file access if injection succeeds, and the skill payloads found in the 575+ malicious skills confirm this.",
      "Plaintext secrets in config: API keys and credentials often sit in openclaw.json or env vars; indirect injection plus tool misuse can read and exfiltrate them. OpenClaw's plaintext MEMORY.md and SOUL.md are explicitly targeted by infostealers.",
      "Local gateway hijacking (CSRF and cross-site WebSocket): OpenClaw CVE-2026-25253 (CVSS 8.8) used a gatewayUrl query parameter and cross-site WebSocket hijacking to steal an auth token for one-click RCE.",
      "Slopsquatting: attackers register package names that models hallucinate; one study found 19.7% of recommended packages didn't exist across 16 models.",
    ],
  },
  {
    name: "Cursor",
    howItWorks:
      "IDE that runs agents over your codebase, tasks and docs, with auto-run for commands and test runs; Agent Skills extend the agent with domain workflows.",
    vulnerability: [
      "Indirect prompt injection: hidden instructions in code comments, README, wiki pages, external docs or tool responses can hijack Cursor's planning (rewrite this file to send data to X, disable tests, add a backdoor). Confirmed by the CurXecute CVE (CVE-2025-54135), where a Slack message the agent was asked to summarize led to code execution.",
      "Auto-run commands: in Auto-Run mode, Cursor can execute shell commands on its own; injection that slips past its deny list can push malicious commands or modify lockfiles and pipelines. This is the core of the CurXecute attack chain.",
      "Skills as extra attack surface: Agent Skills are just SKILL.md plus scripts and resources; a malicious skill can guide the agent to misuse tools or call shady binaries. This matches the broader skill-supply-chain pattern.",
      "MCP config trust abuse (MCPoison, CVE-2025-54136): Cursor approved an MCP config once and silently trusted later edits, letting an attacker swap in a malicious server after initial approval.",
      "World-writable trust paths: a folder like C:\\ProgramData\\Cursor that any user can create lets one user plant config or hooks that run in another user's session.",
      "Sandbox escape (DuneSlide): Cursor's sandbox could be bypassed by overwriting the sandbox binary.",
      "Secrets in context: agents often see .env, config and dependency files; injected content can persuade them to output or send those secrets elsewhere.",
    ],
  },
  {
    name: "Goose",
    howItWorks:
      "General-purpose agent (CLI, desktop, API) that can edit files, run tests, install software, execute commands, manage workflows, and use any of ~15+ model providers (including local models).",
    vulnerability: [
      "Prompt injection in system-level tasks: Goose agents read tasks, config, logs, web and API responses. Goose's own docs confirm this and describe a prompt-injection detection feature that pauses execution when threats exceed a threshold.",
      "Unvetted third-party skills: since Goose is open-source and skill ecosystems are wide, a malicious skill or plugin can ship shell commands, network code or data exfiltration disguised as helpers. Goose's own security guidance recommends only connecting reviewed MCP extensions.",
      "Pre-task recipe execution (CVE-2026-85623): a shared recipe can contain process-spawning fields (extensions[].cmd, args or retry.checks[].command) that execute before the model even chooses a tool, running as the OS user running Goose.",
      "Arbitrary command execution via goose review (GHSA-r5pp-p5r8-466r): a git core.fsmonitor trick let an attacker run arbitrary commands through the review flow.",
      "Weak isolation is a blast-radius issue, not an attack: Goose's own guidance recommends running in a dedicated VM or container precisely because a compromised session has direct access to home directories, repos and credential stores. This is a consequence, not an attack itself.",
    ],
  },
  {
    name: "Hermes Agent",
    howItWorks:
      "Self-hosted Python agent runtime that orchestrates LLMs through a closed-loop pipeline: reads repo, docs, memory, web/API responses, then plans and executes commands (shell, code, file edits, tool calls) based on those inputs.",
    vulnerability: [
      "Indirect prompt injection via context, memory and skills: instructions hidden in documents, websites, emails or retrieved memory can override intended behavior. Multiple CVEs target the scanners meant to catch this: CVE-2026-9366 (prompt builder), CVE-2026-10223 (memory tool) and CVE-2026-9353 (skills guard).",
      "Unrestricted code execution (execute_code tool): arbitrary Python code can run on the host with the agent's privileges, bypassing terminal safety and approval systems. An independent audit found unrestricted shell execution and containerized approval bypass in the default config.",
      "Sandbox escape and secret leakage: the sandbox injects project root into PYTHONPATH, letting scripts import internal modules (config with API keys, .env paths); output sanitization can be bypassed via base64, hex or reverse encoding to exfiltrate secrets.",
      "Persistent skill injection: the agent can create SKILL.md files in ~/.hermes/skills/ that load in future sessions, acting as persistent injection vectors that survive restarts.",
      "Symlink and path traversal (CVE-2026-7397, CVSS 4.8): a symlink-following flaw in tools/file_tools.py lets a low-privileged local attacker access or manipulate files outside the intended scope.",
      "WebUI path traversal (CVE-2026-6829, CVSS 5.3): authenticated attackers can manipulate workspace path parameters to redirect the session's working context to sensitive system directories like /etc or /home.",
      "WeChat Work adapter path traversal (CVE-2026-7396, CVSS 4.0): unauthenticated remote attackers can traverse the filesystem via the WeChat Work adapter on externally exposed instances.",
      "World-readable config and memory files: before v0.16.0, response_store.db and webhook_subscriptions.json were created with mode 0o644, exposing conversation history and HMAC secrets to local users.",
      "DNS rebinding on WebSocket endpoints: FastAPI middleware doesn't execute for WebSocket upgrades on /api/pty, /api/ws, /api/pub and /api/events, enabling DNS rebinding to inject commands or read terminal output.",
      "Skill marketplace supply chain: community skills can embed unsafe commands or data exfiltration; the project itself notes these are operator-review surfaces, not Hermes trust surfaces.",
    ],
  },
  {
    name: "Gemini CLI",
    howItWorks:
      "CLI that runs Gemini-based agents with tool access and Agent Skills; skills provide bespoke knowledge and workflows for automation and data tasks.",
    vulnerability: [
      "Indirect injection from external data: instructions hidden in web pages, PDFs, docs or tool output can override system prompts, making the agent ignore safety or call dangerous tools. Gemini CLI's own release notes confirm they patched indirect injection via build-file modifications and untrusted flags.",
      "Tool-calling abuse: once an injection convinces the agent this is part of the workflow, it can send unexpected HTTP requests, push config changes or run test scripts with harmful parameters. The comparative study lists CI/CD pipelines, issue titles, pasted logs and copy-pasted web output as injection vectors.",
      "Pre-task RCE (CVE-2026-12537, CVSS 10.0): OS command injection in the container launcher ran attacker code before the sandbox even started, with no prompt injection required, just three lines in .gemini/.env.",
      "Sandbox escape: reported alongside Claude Code and Cursor in the same research.",
      "Skills as supply chain: a malicious skill can embed harmful instructions or scripts under the guise of automation; installed via npx skills add, it becomes trusted logic for the agent.",
      "Credential exposure: agents can see local files and environment variables; injection can ask the agent to print or send them to remote endpoints.",
    ],
  },
  {
    name: "GitHub Copilot Agents + Agent Skills",
    howItWorks:
      "Copilot agents run inside editors and CLI, reading your repo, issues, comments and sometimes external docs; Agent Skills are folders of instructions, scripts and resources that modify agent behavior for specialized tasks.",
    vulnerability: [
      "Prompt injection inside repos and issues: a malicious PR comment, issue description or code comment can instruct Copilot to refactor in ways that introduce backdoors, disable checks or leak sensitive snippets. This matches the broader pattern of repo content as an instruction source.",
      "Auto-approve manipulation (CVE-2025-62222): injection could edit .vscode/settings.json to auto-approve terminal commands, removing the human gate.",
      "Agent hijacking via skills: a compromised or malicious SKILL.md can subtly change how Copilot agents interpret tasks and call tools (run extra commands, send data to a logging endpoint).",
      "CamoLeak (CVE-2025-59145): injection hidden in invisible markdown comments in pull requests, abusing GitHub's image proxy to leak private repo secrets with zero clicks.",
      "Secrets in context: Copilot agents can see .env, config and CI files; injection or bad skills can cause them to echo keys or tokens in comments, logs or remote requests.",
      "No cryptographic agent identity: identities are mostly strings plus configs; there's no default signed-message layer, so any extension or process can potentially impersonate an agent if not sandboxed. This is a design gap that amplifies other attacks rather than an attack itself.",
    ],
  },
];

const Landing = () => {
  const [authOpen, setAuthOpen] = useState(false);
  const [authMode, setAuthMode] = useState("signin");
  const [showParticleField, setShowParticleField] = useState(false);
  const [contactOpen, setContactOpen] = useState(false);
  const [showBelowFold, setShowBelowFold] = useState(true);
  const { user } = useAuth();
  const navigate = useNavigate();
  const particleFieldPaused = authOpen || !showParticleField;

  useEffect(() => {
    const enableHeroEffects = () => setShowParticleField(true);

    if (typeof window !== "undefined" && "requestIdleCallback" in window) {
      const idleId = window.requestIdleCallback(enableHeroEffects, {
        timeout: 1200,
      });
      return () => window.cancelIdleCallback?.(idleId);
    }

    const timeoutId = setTimeout(enableHeroEffects, 300);
    return () => clearTimeout(timeoutId);
  }, []);

  const openAuth = (mode) => {
    if (!showBelowFold) setShowBelowFold(true);

    if (user) {
      navigate("/dashboard");
      return;
    }

    setAuthMode(mode);
    setAuthOpen(true);
  };

  const onCardMove = (e) => {
    const target = e.currentTarget;
    const nextX = e.clientX;
    const nextY = e.clientY;

    if (target.__icGlowFrame) {
      return;
    }

    const paintGlow = () => {
      const r = target.getBoundingClientRect();
      target.style.setProperty("--mx", `${nextX - r.left}px`);
      target.style.setProperty("--my", `${nextY - r.top}px`);
      target.__icGlowFrame = null;
    };

    if (typeof window !== "undefined" && "requestAnimationFrame" in window) {
      target.__icGlowFrame = window.requestAnimationFrame(paintGlow);
      return;
    }

    paintGlow();
  };

  return (
    <div className="relative isolate min-h-screen overflow-x-hidden bg-transparent text-white">
      <div className="pointer-events-none fixed inset-0 z-0 bg-transparent">
        <Suspense fallback={null}>
          {showParticleField ? (
            <ParticleField
              density={PARTICLE_FIELD_DENSITY}
              paused={particleFieldPaused}
            />
          ) : null}
        </Suspense>
      </div>

      <nav className="relative z-20 mx-auto flex max-w-7xl items-center justify-between px-6 py-6 max-sm:flex-col max-sm:justify-center max-sm:gap-4">
        <div className="flex items-center gap-2.5" data-testid="brand-logo">
          <img
            src={BRAND_LOGO_SRC}
            alt="IronClaw-Security"
            className="brand-logo-image"
          />
          <span className="font-tech text-base font-bold tracking-tight sm:text-lg">
            IRONCLAW
            <span className="metal-gold-text">
              <span className="max-sm:hidden">-</span>
              <span className="sm:hidden"> </span>
              SECURITY
            </span>
          </span>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => openAuth("signin")}
            data-testid="nav-signin-btn"
            className="rounded-lg border border-white/15 px-5 py-2 text-sm font-medium text-white/90 transition hover:border-white/40 hover:text-white"
          >
            Sign In
          </button>
          <button
            onClick={() => openAuth("signup")}
            data-testid="nav-signup-btn"
            className="btn-shimmer inline-flex items-center justify-center rounded-lg bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-5 py-2 text-sm font-semibold text-black transition hover:shadow-[0_0_22px_rgba(255,215,0,0.4)]"
          >
            Sign Up
          </button>
        </div>
      </nav>

      <section className="relative z-10 overflow-hidden bg-transparent">
        <div className="pointer-events-none absolute left-1/4 top-20 h-72 w-72 rounded-full bg-[#38BDF8] opacity-20 blur-[120px] animate-float-glow" />
        <div
          className="pointer-events-none absolute right-1/4 top-40 h-72 w-72 rounded-full bg-[#C9A84C] opacity-20 blur-[120px] animate-float-glow"
          style={{ animationDelay: "2s" }}
        />

        <div className="relative z-10 mx-auto max-w-5xl px-6 pb-28 pt-20 text-center">
          <motion.div
            variants={fadeUp}
            initial="hidden"
            animate="show"
            className="mx-auto mb-6 inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/5 px-4 py-1.5 text-xs text-[#BFC1C2]"
          >
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#22C55E]" />
            Enforcement layer for production AI systems
          </motion.div>

          <motion.h1
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={1}
            className="mx-auto max-w-4xl text-4xl font-bold leading-[1.05] tracking-tight sm:text-5xl lg:text-6xl"
          >
            Complete Cyber Security{" "}
            <span className="text-gold-gradient">Frontline Defense</span> For AI
            Agent Platforms.
          </motion.h1>

          <motion.p
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={2}
            className="mx-auto mt-6 max-w-2xl text-base text-[#BFC1C2] sm:text-lg"
          >
            IronClaw-Security sits in front of every agent action, every tool
            call, every inbound return. Every threat intercepted. Every verdict
            auditable.
          </motion.p>

          <motion.div
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={3}
            className="mt-9 flex flex-wrap items-center justify-center gap-x-14 gap-y-6"
          >
            <div className="flex flex-col items-center gap-1">
              <div className="text-xs uppercase tracking-[0.3em] text-[#737373]">
                Threats blocked
              </div>
              <div className="text-4xl font-bold drop-shadow-[0_0_18px_rgba(56,189,248,0.5)]">
                <LiveCounter
                  counterKey="threats_blocked"
                  color="#38BDF8"
                  testid="threat-counter"
                />
              </div>
            </div>
            <div className="hidden h-12 w-px bg-white/10 sm:block" />
            <div className="flex flex-col items-center gap-1">
              <div className="text-xs uppercase tracking-[0.3em] text-[#737373]">
                Engineers protected
              </div>
              <div className="text-4xl font-bold drop-shadow-[0_0_18px_rgba(255,215,0,0.45)]">
                <LiveCounter
                  counterKey="engineers_protected"
                  color="#FFD700"
                  testid="user-counter"
                />
              </div>
            </div>
          </motion.div>

          <motion.div
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={4}
            className="mt-10 flex items-center justify-center gap-4"
          >
            <button
              onClick={() => openAuth("signin")}
              data-testid="hero-signin-btn"
              className="btn-shimmer rounded-xl border border-white/20 bg-white/5 px-8 py-3.5 font-semibold text-white transition hover:border-[#E5E4E2]/60"
            >
              Sign In
            </button>
            <button
              onClick={() => openAuth("signup")}
              data-testid="hero-signup-btn"
              className="btn-shimmer inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-8 py-3.5 font-semibold text-black transition hover:shadow-[0_0_28px_rgba(255,215,0,0.45)]"
            >
              Sign Up <ArrowRight size={18} />
            </button>
          </motion.div>

          <motion.div
            variants={fadeUp}
            initial="hidden"
            animate="show"
            custom={5}
            className="mt-12 flex justify-center"
          >
            <img
              src={KNIGHT_IMAGE_SRC}
              alt="IronClaw-Security knight defender"
              className="hero-image"
            />
          </motion.div>

          <CyberNewsTickers />
        </div>
      </section>

      {showBelowFold ? (
        <>
          <section className="relative z-10 mx-auto max-w-7xl bg-transparent px-6 py-20">
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true, margin: "-80px" }}
              className="mb-14 text-center"
            >
              <div className="mb-3 inline-block rounded-full border border-[#FFD700]/25 bg-[#C9A84C]/10 px-4 py-1 font-tech text-xs uppercase tracking-[0.3em] text-[#FFD700]">
                14 enforcement layers
              </div>
              <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
                Fourteen layers of{" "}
                <span className="metal-gold-text">relentless</span> enforcement
              </h2>
              <p className="mx-auto mt-3 max-w-2xl text-[#BFC1C2]">
                No agent output reaches your workflow without passing every
                gate. No bypass path. No silent pass-through.
              </p>
            </motion.div>

            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
              {LAYERS.map((f, i) => {
                const Icon = f.icon;
                return (
                  <motion.div
                    key={f.title}
                    variants={fadeUp}
                    custom={i % 4}
                    initial="hidden"
                    whileInView="show"
                    viewport={{ once: true, margin: "-40px" }}
                    onMouseMove={onCardMove}
                    className="feature-card rounded-2xl p-6"
                    data-testid={`feature-card-${i}`}
                  >
                    <div className="mb-4 flex items-center justify-between">
                      <div className="metal-gold-icon flex h-11 w-11 items-center justify-center rounded-xl">
                        <Icon className="text-[#FFD700]" size={20} />
                      </div>
                      <span className="layer-tag font-tech text-xs font-semibold tracking-widest text-white/30">
                        L{i + 1}
                      </span>
                    </div>
                    <h3 className="mb-2 text-base font-semibold tracking-tight">
                      <span className="metal-gold-text">Layer {i + 1}</span>
                      <span className="text-white"> — {f.title}</span>
                    </h3>
                    <p className="text-sm leading-relaxed text-[#BFC1C2]">
                      {f.body}
                    </p>
                  </motion.div>
                );
              })}
            </div>
          </section>

          <section className="relative z-10 mx-auto max-w-7xl bg-transparent px-6 py-20">
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true, margin: "-80px" }}
              className="mb-14 text-center"
            >
              <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
                <span className="metal-gold-text">Platforms Protected</span>
              </h2>
            </motion.div>
            <PlatformsTicker />
          </section>

          <section className="relative z-10 mx-auto max-w-6xl bg-transparent px-6 py-8">
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true, margin: "-80px" }}
              className="py-4"
            >
              <h3 className="mb-6 text-2xl font-semibold tracking-tight sm:text-3xl">
                <span className="text-gold-gradient">Protection From:</span>
              </h3>

              <ul className="space-y-3">
                {LANDING_PROTECTION_ITEMS.map((item) => {
                  const [title, ...rest] = item.split(" – ");
                  const description = rest.join(" – ");

                  return (
                    <li
                      key={item}
                      className="flex items-start gap-3 rounded-xl border border-[#FFD700]/10 bg-transparent px-3 py-3 text-left"
                    >
                      <span className="mt-2 inline-flex h-2.5 w-2.5 shrink-0 rounded-full bg-[#FFD700] shadow-[0_0_10px_rgba(255,215,0,0.8)]" />
                      <span className="leading-relaxed">
                        <span className="metal-gold-text block text-lg font-black tracking-tight sm:text-xl">
                          {title}
                        </span>
                        {description ? (
                          <span className="mt-1 block text-sm font-medium text-white sm:text-base">
                            {description}
                          </span>
                        ) : null}
                      </span>
                    </li>
                  );
                })}
              </ul>
            </motion.div>
          </section>

          <section className="relative z-10 mx-auto max-w-6xl bg-transparent px-6 py-20">
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true, margin: "-80px" }}
              className="mb-10 text-center"
            >
              <div className="mb-3 inline-block rounded-full border border-[#FFD700]/30 bg-[#C9A84C]/10 px-4 py-1 font-tech text-xs uppercase tracking-[0.3em] text-[#FFD700]">
                Platform Coverage
              </div>
              <h2 className="text-3xl font-semibold tracking-tight sm:text-4xl">
                Platforms Protected By{" "}
                <span className="metal-gold-text">Gen 1 IronClaw-Security</span>
              </h2>
            </motion.div>

            <ul className="space-y-4">
              {PROTECTED_PLATFORMS.map((platform, index) => (
                <motion.li
                  key={platform.name}
                  variants={fadeUp}
                  custom={index}
                  initial="hidden"
                  whileInView="show"
                  viewport={{ once: true, margin: "-40px" }}
                  className="list-none py-3 text-left"
                >
                  <div className="mb-2 flex items-center gap-3">
                    <span className="font-tech text-[10px] uppercase tracking-[0.28em] text-[#FFD700]">
                      Protected
                    </span>
                    <h3 className="text-2xl font-semibold tracking-tight text-white">
                      <span className="metal-gold-text">{platform.name}</span>
                    </h3>
                  </div>

                  <ul className="space-y-3 text-base leading-relaxed text-[#E5E4E2] sm:text-[15px]">
                    <li className="border-l border-[#FFD700]/30 pl-4">
                      <span className="mb-1 block font-tech text-[10px] uppercase tracking-[0.26em] text-[#BFC1C2]">
                        How it works
                      </span>
                      <span>{platform.howItWorks}</span>
                    </li>
                    <li className="border-l border-[#FFD700]/30 pl-4">
                      <span className="mb-1 block font-tech text-[10px] uppercase tracking-[0.26em] text-[#BFC1C2]">
                        Why it&apos;s vulnerable
                      </span>
                      <ul className="space-y-2">
                        {platform.vulnerability.map((item) => (
                          <li key={item} className="flex gap-2">
                            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[#FFD700]" />
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </li>
                  </ul>
                </motion.li>
              ))}
            </ul>

            <div className="mt-8 text-center text-sm text-[#BFC1C2]">
              <span className="font-tech text-[10px] uppercase tracking-[0.26em] text-[#FFD700]">
                Sources:
              </span>{" "}
              <span className="text-[#E5E4E2]">
                OWASP LLM Top 10, NIST adversarial ML taxonomy.
              </span>
            </div>
          </section>

          <PackageCarousel />
          <section className="relative z-10 mx-auto max-w-4xl bg-transparent px-6 pb-24 pt-10 text-center">
            <motion.div
              variants={fadeUp}
              initial="hidden"
              whileInView="show"
              viewport={{ once: true }}
            >
              <h2 className="mx-auto max-w-2xl text-3xl font-bold tracking-tight sm:text-4xl">
                Start protecting your system against unsafe autonomous agents
                now. Eventually your luck will run out. IronClaw-Security is the
                safety net every production team needs.
              </h2>
              <button
                onClick={() => openAuth("signup")}
                data-testid="footer-getstarted-btn"
                className="btn-shimmer mt-8 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-[#C9A84C] to-[#FFD700] px-10 py-4 text-lg font-semibold text-black transition hover:shadow-[0_0_32px_rgba(255,215,0,0.5)]"
              >
                Get Started <ArrowRight size={20} />
              </button>
            </motion.div>
          </section>

          <footer className="relative z-10 border-t border-white/10 bg-transparent py-8 sm:py-10">
            <div className="mx-auto flex max-w-7xl flex-col items-center gap-3 px-4 text-center sm:px-6">
              <section
                aria-labelledby="footer-resources-title"
                data-testid="footer-resources"
                className="flex w-full max-w-4xl flex-col items-center gap-3 border-b border-white/10 pb-6"
              >
                <h3
                  id="footer-resources-title"
                  className="font-tech text-xs font-bold uppercase tracking-[0.2em] text-white"
                >
                  Free Resources For Learning{" "}
                  <span className="metal-gold-text">Cyber Security</span>
                </h3>
                <ul className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2 text-xs">
                  {FOOTER_RESOURCE_LINKS.map((resource, i) => (
                    <li key={resource.href}>
                      <a
                        href={resource.href}
                        target="_blank"
                        rel="noopener noreferrer"
                        data-testid={`footer-resource-link-${i}`}
                        className="text-[#BFC1C2] transition hover:text-[#FFD700]"
                      >
                        {resource.label}
                      </a>
                    </li>
                  ))}
                </ul>
              </section>
              <div className="flex flex-col items-center gap-2 sm:flex-row sm:gap-2">
                <img
                  src={GOLDEN_KNIGHT_LOGO_SRC}
                  alt="IronClaw-Security"
                  className="footer-brand-logo"
                />
                <span className="font-tech text-sm font-bold tracking-tight">
                  IRONCLAW<span className="metal-gold-text">-SECURITY</span>
                </span>
              </div>
              <div className="flex flex-col items-center gap-2 text-xs sm:flex-row sm:gap-6">
                <Link
                  to="/privacy"
                  data-testid="footer-privacy-link"
                  className="text-[#BFC1C2] transition hover:text-[#FFD700]"
                >
                  Privacy Policy
                </Link>
                <span className="hidden text-white/15 sm:inline">|</span>
                <Link
                  to="/terms"
                  data-testid="footer-terms-link"
                  className="text-[#BFC1C2] transition hover:text-[#FFD700]"
                >
                  Terms of Service
                </Link>
                <span className="hidden text-white/15 sm:inline">|</span>
                <button
                  type="button"
                  onClick={() => setContactOpen(true)}
                  data-testid="footer-contact-link"
                  className="text-[#BFC1C2] transition hover:text-[#FFD700]"
                >
                  CONTACT
                </button>
              </div>
              <ContactModal open={contactOpen} onOpenChange={setContactOpen} />
              <p className="max-w-2xl text-[11px] text-[#737373] sm:text-xs">
                The enforcement layer serious engineers trust with production AI
                systems.
              </p>
              <p
                className="max-w-4xl font-tech text-[10px] leading-relaxed text-[#737373] sm:text-xs"
                data-testid="powered-by"
              >
                <span className="inline-flex flex-wrap items-center justify-center gap-x-1 gap-y-1">
                  Powered by &mdash;{" "}
                  <span className="metal-gold-text">
                    Universal Rejuvenation Inc.
                  </span>{" "}
                  &mdash;{" "}
                  <span className="metal-gold-text">
                    The Enlightenism Organization
                  </span>
                </span>
              </p>
            </div>
          </footer>
        </>
      ) : null}

      <AuthModal
        open={authOpen}
        onClose={() => setAuthOpen(false)}
        initialMode={authMode}
      />
      <ContactBubble />
    </div>
  );
};

export default Landing;
