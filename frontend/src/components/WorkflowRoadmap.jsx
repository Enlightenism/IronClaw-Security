import { useEffect, useRef, useState } from "react";
import "./WorkflowRoadmap.css";

const PLATFORMS = [
  {
    name: "Claude Code",
    logo: "/images/platforms/claude-code.svg",
  },
  {
    name: "OpenClaw",
    logo: "/images/platforms/openclaw.svg",
  },
  {
    name: "Cursor",
    logo: "/images/platforms/cursor.svg",
  },
  {
    name: "Goose",
    logo: "/images/platforms/goose.svg",
  },
  {
    name: "Hermes Agent",
    logo: "/images/platforms/hermes-agent.svg",
  },
  {
    name: "Gemini CLI",
    logo: "/images/platforms/gemini-cli.svg",
  },
  {
    name: "GitHub Copilot",
    logo: "/images/platforms/github-copilot.svg",
  },
  {
    name: "Google Antigravity",
    logo: "/images/platforms/gemini-cli.svg",
  },
];

const STAGES = [
  {
    short: "Platforms",
    title: "Protected platform",
    copy: "Every supported agent runtime enters the same front gate.",
  },
  {
    short: "Task",
    title: "Task enters",
    copy: "The user or platform sends a prompt, request, file, or tool task.",
  },
  {
    short: "Agent",
    title: "Agent executes",
    copy: "The agent plans and generates an untrusted return.",
  },
  {
    short: "Intercept",
    title: "Output intercepted",
    copy: "The original return never reaches the platform or user.",
  },
  {
    short: "Sandbox",
    title: "Fresh isolation",
    copy: "IronClaw creates a fresh read-only, no-network sandbox.",
  },
  {
    short: "Security",
    title: "Security evaluation",
    copy: "Python security, AI Brain, and Prompt Guard inspect the isolated output.",
  },
  {
    short: "Verdict",
    title: "Sandbox verdict",
    copy: "Only ALLOW becomes releasable. Every failure remains BLOCK.",
  },
  {
    short: "Release",
    title: "Platform delivery",
    copy: "Clean output is released; blocked output is replaced or suppressed.",
  },
];

const SECURITY_LAYERS = [
  "Python rules",
  "AI Brain",
  "Llama Prompt Guard 2",
  "Secret scan",
  "File / network",
  "Sanitizer",
];

export default function WorkflowRoadmap() {
  const sectionRef = useRef(null);
  const [visible, setVisible] = useState(false);
  const [progress, setProgress] = useState(0);
  const [activeStage, setActiveStage] = useState(0);

  useEffect(() => {
    const section = sectionRef.current;
    if (!section) return undefined;

    let frameId = 0;
    const prefersReducedMotion =
      typeof window !== "undefined" &&
      window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;

    const update = () => {
      frameId = 0;
      const rect = section.getBoundingClientRect();
      const travel = Math.max(1, rect.height - window.innerHeight);
      const nextProgress = Math.min(1, Math.max(0, -rect.top / travel));
      setProgress(nextProgress);

      if (prefersReducedMotion) {
        setActiveStage(nextProgress >= 0.99 ? STAGES.length - 1 : 0);
        return;
      }

      setActiveStage(
        Math.min(STAGES.length - 1, Math.floor(nextProgress * STAGES.length)),
      );
    };

    const scheduleUpdate = () => {
      if (frameId) return;
      frameId = window.requestAnimationFrame(update);
    };

    let observer;
    if ("IntersectionObserver" in window) {
      observer = new IntersectionObserver(
        ([entry]) => setVisible(entry.isIntersecting),
        { threshold: 0.08 },
      );
      observer.observe(section);
    } else {
      setVisible(true);
    }

    update();
    window.addEventListener("scroll", scheduleUpdate, { passive: true });
    window.addEventListener("resize", scheduleUpdate);

    return () => {
      observer?.disconnect();
      window.removeEventListener("scroll", scheduleUpdate);
      window.removeEventListener("resize", scheduleUpdate);
      if (frameId) window.cancelAnimationFrame(frameId);
    };
  }, []);

  const verdictReached = activeStage >= 6;
  const released = activeStage === STAGES.length - 1;

  return (
    <section
      ref={sectionRef}
      className={`workflow-roadmap-section${visible ? " is-visible" : ""}`}
      aria-labelledby="workflow-roadmap-title"
      data-testid="workflow-roadmap"
    >
      <div className="workflow-roadmap-sticky">
        <div className="workflow-roadmap-canvas">
          <div className="workflow-roadmap-heading">
            <div>
              <span className="workflow-roadmap-kicker">
                One system. Every protected platform.
              </span>
              <h2 id="workflow-roadmap-title">
                The <span className="metal-gold-text">IronClaw Front Gate</span>
              </h2>
            </div>
            <p>
              Agent output is isolated before the Python security system, AI
              Brain, and Llama Prompt Guard can release it.
            </p>
          </div>

          <div
            className="workflow-platform-rail"
            aria-label="Protected platforms"
          >
            {PLATFORMS.map((platform) => (
              <div className="workflow-platform" key={platform.name}>
                <img
                  src={platform.logo}
                  alt=""
                  draggable="false"
                  className="workflow-platform-logo"
                />
                <span>{platform.name}</span>
              </div>
            ))}
          </div>

          <div className="workflow-stage-track" aria-label="Workflow stages">
            <div className="workflow-track-base" />
            <div
              className="workflow-track-progress"
              style={{ width: `${Math.max(2, progress * 100)}%` }}
            />
            {STAGES.map((stage, index) => {
              const complete = index < activeStage;
              const active = index === activeStage;
              return (
                <div
                  className={[
                    "workflow-stage-node",
                    complete ? "is-complete" : "",
                    active ? "is-active" : "",
                  ].join(" ")}
                  key={stage.short}
                  data-testid={`workflow-stage-${index + 1}`}
                >
                  <span className="workflow-stage-number">
                    {String(index + 1).padStart(2, "0")}
                  </span>
                  <span className="workflow-stage-name">{stage.short}</span>
                </div>
              );
            })}
          </div>

          <div className="workflow-roadmap-grid">
            <div className="workflow-roadmap-status">
              <span className="workflow-status-label">Current stage</span>
              <h3>{STAGES[activeStage].title}</h3>
              <p>{STAGES[activeStage].copy}</p>

              <div className="workflow-status-steps">
                {STAGES.map((stage, index) => (
                  <div
                    className={[
                      "workflow-status-step",
                      index < activeStage ? "is-passed" : "",
                      index === activeStage ? "is-current" : "",
                    ].join(" ")}
                    key={stage.title}
                  >
                    <span>{String(index + 1).padStart(2, "0")}</span>
                    <strong>{stage.title}</strong>
                  </div>
                ))}
              </div>
            </div>

            <div className="workflow-sandbox-map">
              <div
                className={[
                  "workflow-output-card",
                  activeStage >= 3 ? "is-intercepted" : "",
                  activeStage >= 6 ? "is-sealed" : "",
                ].join(" ")}
              >
                <span className="workflow-card-kicker">Agent return</span>
                <strong>
                  {activeStage >= 6
                    ? verdictReached
                      ? "Output awaiting verdict"
                      : "Original output"
                    : "Untrusted output"}
                </strong>
                <div className="workflow-output-lines">
                  <span />
                  <span />
                  <span />
                </div>
              </div>

              <div
                className={[
                  "workflow-sandbox",
                  activeStage >= 4 ? "is-active" : "",
                  activeStage >= 6 ? "is-scanned" : "",
                ].join(" ")}
              >
                <div className="workflow-sandbox-header">
                  <span>Fresh sandbox</span>
                  <span className="workflow-sandbox-status">
                    {activeStage >= 6 ? "Scan complete" : "Isolated"}
                  </span>
                </div>

                <div className="workflow-sandbox-specs">
                  <span>Read-only</span>
                  <span>No-network</span>
                  <span>Non-root</span>
                </div>

                <div className="workflow-security-grid">
                  {SECURITY_LAYERS.map((layer, index) => (
                    <div
                      className={[
                        "workflow-security-item",
                        activeStage >= 5 && index <= activeStage - 5
                          ? "is-active"
                          : "",
                      ].join(" ")}
                      key={layer}
                    >
                      <span className="workflow-security-mark" />
                      {layer}
                    </div>
                  ))}
                </div>

                <div className="workflow-scan-beam" />

                <div className="workflow-verdict-row">
                  <div
                    className={[
                      "workflow-verdict workflow-verdict-block",
                      activeStage >= 6 && !released ? "is-pending" : "",
                    ].join(" ")}
                  >
                    <span>BLOCK</span>
                    <strong>Withheld</strong>
                  </div>
                  <div
                    className={[
                      "workflow-verdict workflow-verdict-allow",
                      released ? "is-released" : "",
                    ].join(" ")}
                  >
                    <span>ALLOW</span>
                    <strong>Release</strong>
                  </div>
                </div>
              </div>

              <div
                className={[
                  "workflow-release-card",
                  released ? "is-visible" : "",
                ].join(" ")}
              >
                <span className="workflow-card-kicker">Platform / user</span>
                <strong>
                  {released ? "Approved output delivered" : "Delivery locked"}
                </strong>
              </div>
            </div>
          </div>

          <div
            className="workflow-progress-readout"
            aria-label={`${Math.round(progress * 100)} percent through workflow`}
          >
            <span>Task</span>
            <div>
              <span style={{ width: `${progress * 100}%` }} />
            </div>
            <span>Release</span>
          </div>
        </div>
      </div>
    </section>
  );
}
