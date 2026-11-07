import "./PlatformsTicker.css";

const PLATFORMS = [
  {
    name: "Claude Code",
    logo: "/images/platforms/claude-code.svg",
    mono: false,
    styleClass: "platform-style-claude-code",
  },
  {
    name: "OpenClaw",
    logo: "/images/platforms/openclaw.svg",
    mono: false,
    styleClass: "platform-style-openclaw",
  },
  {
    name: "Hermes Agent",
    logo: "/images/platforms/hermes-agent.svg",
    mono: true,
    styleClass: "platform-style-hermes-agent",
  },
  {
    name: "GitHub Copilot",
    logo: "/images/platforms/github-copilot.svg",
    mono: false,
    styleClass: "platform-style-github-copilot",
  },
  {
    name: "Gemini CLI",
    logo: "/images/platforms/gemini-cli.svg",
    mono: false,
    styleClass: "platform-style-gemini-cli",
  },
  {
    name: "Cursor",
    logo: "/images/platforms/cursor.svg",
    mono: true,
    styleClass: "platform-style-cursor",
  },
  {
    name: "Goose",
    logo: "/images/platforms/goose.svg",
    mono: true,
    styleClass: "platform-style-goose",
  },
];

function PlatformItems({ hidden = false }) {
  return (
    <div className="platforms-ticker-group" aria-hidden={hidden || undefined}>
      {PLATFORMS.map((platform) => (
        <span
          className={`platforms-ticker-item ${platform.styleClass}`}
          key={platform.name}
        >
          {platform.mono ? (
            <span
              className="platform-logo platform-logo-mask"
              style={{ "--logo-url": `url(${platform.logo})` }}
              aria-hidden="true"
            />
          ) : (
            <img
              className="platform-logo"
              src={platform.logo}
              alt=""
              draggable="false"
            />
          )}
          <span className="platform-name">{platform.name}</span>
          <span className="platforms-ticker-divider" aria-hidden="true" />
        </span>
      ))}
    </div>
  );
}

export default function PlatformsTicker() {
  return (
    <div
      className="platforms-ticker"
      role="region"
      aria-label="Platforms protected by IronClaw Security"
    >
      <div className="platforms-ticker-box">
        <div className="platforms-ticker-track">
          <PlatformItems />
          <PlatformItems hidden />
        </div>
      </div>
    </div>
  );
}
