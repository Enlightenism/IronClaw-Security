import { useState } from "react";
import { Copy, Check, Terminal } from "lucide-react";
import { toast } from "sonner";

const IntegrationCard = ({ title, command, tint = "gold", testid }) => {
  const [copied, setCopied] = useState(false);

  const surface = tint === "gold" ? "glass-gold" : "glass-platinum";
  const accent = tint === "gold" ? "#FFD700" : "#E5E4E2";

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = command;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
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
          {title}
        </h3>
      </div>

      <p className="mb-3 text-xs text-[#BFC1C2]">
        Drop this one-liner into your agent host. Every unit draw and blocked
        attack from this install streams straight to your dashboard.
      </p>

      <div className="flex items-stretch gap-2">
        <code className="font-tech flex-1 overflow-x-auto whitespace-nowrap rounded-lg border border-white/10 bg-black/50 px-4 py-3 text-xs text-white/90">
          {command || "loading..."}
        </code>
        <button
          onClick={copy}
          disabled={!command}
          data-testid={`${testid}-copy`}
          className="flex w-12 shrink-0 items-center justify-center rounded-lg border transition"
          style={{
            borderColor: `${accent}55`,
            background: `${accent}14`,
            color: accent,
          }}
        >
          {copied ? <Check size={18} /> : <Copy size={18} />}
        </button>
      </div>
    </div>
  );
};

export default IntegrationCard;
