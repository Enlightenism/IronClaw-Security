import { useEffect, useRef, useState } from "react";
import "./PlatformTokenCosts.css";

const TOKEN_COST_ROWS = [
  {
    id: "claude-sonnet",
    platform: "Claude Code",
    model: "(Sonnet 4.6, API)",
    cost: "$1,875",
    detail:
      "Subscriptions cap usage, but heavy agent work reaches the limit quickly.",
    logo: "/images/platforms/claude-code.svg",
  },
  {
    id: "claude-opus",
    platform: "Claude Code",
    model: "(Opus 4.8, API)",
    cost: "$3,125",
    logo: "/images/platforms/claude-code.svg",
  },
  {
    id: "cursor",
    platform: "Cursor",
    model: "(third-party models, API rates)",
    cost: "About $1,875 beyond plan credits",
    detail:
      "Your monthly fee covers the included slice, and usage past it bills at full model rates.",
    logo: "/images/platforms/cursor.svg",
  },
  {
    id: "github-copilot",
    platform: "GitHub Copilot",
    model: "(AI Credits, API rates)",
    cost: "About $1,875",
    logo: "/images/platforms/github-copilot.svg",
  },
  {
    id: "google-antigravity",
    platform: "Google Antigravity",
    model: "(AI credits)",
    cost: "An estimated $469, based on $25 per 2,500 credits and a Flash-level output price",
    logo: "/images/platforms/gemini-cli.svg",
  },
  {
    id: "openclaw-sonnet",
    platform: "OpenClaw",
    model: "(Sonnet 4.6, API)",
    cost: "$1,875",
    logo: "/images/platforms/openclaw.svg",
  },
  {
    id: "openclaw-hermes",
    platform: "OpenClaw",
    model: "(Hermes 4 70B, OpenRouter)",
    cost: "$50",
    logo: "/images/platforms/openclaw.svg",
  },
  {
    id: "hermes-sonnet",
    platform: "Hermes Agent",
    model: "(Sonnet 4.6, API)",
    cost: "$1,875",
    logo: "/images/platforms/hermes-agent.svg",
  },
  {
    id: "hermes-openrouter",
    platform: "Hermes Agent",
    model: "(Hermes 4 70B, OpenRouter)",
    cost: "$50",
    logo: "/images/platforms/hermes-agent.svg",
  },
  {
    id: "goose-sonnet",
    platform: "Goose",
    model: "(Sonnet 4.6, API)",
    cost: "$1,875",
    logo: "/images/platforms/goose.svg",
  },
  {
    id: "goose-openrouter",
    platform: "Goose",
    model: "(Hermes 4 70B, OpenRouter)",
    cost: "$50",
    logo: "/images/platforms/goose.svg",
  },
];

export default function PlatformTokenCosts() {
  const [started, setStarted] = useState(false);
  const sectionRef = useRef(null);

  useEffect(() => {
    const node = sectionRef.current;
    if (!node) return undefined;

    if (typeof IntersectionObserver === "undefined") {
      setStarted(true);
      return undefined;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setStarted(true);
          observer.disconnect();
        }
      },
      { threshold: 0.15 },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, []);

  return (
    <section
      ref={sectionRef}
      className={`platform-token-costs ${started ? "is-visible" : ""}`}
      aria-labelledby="platform-token-costs-title"
      data-testid="platform-token-costs"
    >
      <div className="platform-token-costs-inner">
        <div className="platform-token-costs-heading">
          <span className="platform-token-costs-kicker">
            Output token estimate
          </span>
          <h2
            id="platform-token-costs-title"
            className="platform-token-costs-title"
          >
            What 125 Million Output Tokens Costs on Each Platform
          </h2>
        </div>

        <div className="platform-token-costs-list">
          {TOKEN_COST_ROWS.map((row, index) => (
            <div
              key={row.id}
              className="platform-token-cost-row"
              style={{ "--cost-row-delay": `${index * 90}ms` }}
              data-testid={`platform-token-cost-${row.id}`}
            >
              <span className="platform-token-cost-beam" aria-hidden="true" />
              <img
                className="platform-token-cost-logo"
                src={row.logo}
                alt=""
                draggable="false"
              />
              <p className="platform-token-cost-copy">
                <span className="platform-token-cost-name">
                  {row.platform} {row.model}
                </span>{" "}
                <span className="platform-token-cost-value">{row.cost}.</span>
                {row.detail ? (
                  <span className="platform-token-cost-detail">
                    {" "}
                    {row.detail}
                  </span>
                ) : null}
              </p>
            </div>
          ))}
        </div>

        <p className="platform-token-costs-summary">
          Open-source agents are free to install, but the model they run on is
          not. Every token they send is billed by the model provider, so the
          total cost depends mainly on which model you choose.
        </p>
      </div>
    </section>
  );
}
