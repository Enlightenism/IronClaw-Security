import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";
import { dashboard } from "@/lib/api";
import {
  COVERAGE_AUDIT,
  COVERAGE_LABELS,
  RUNTIME_GATE_INSTALL,
  RUNTIME_GATE_RETURN,
  getRuntimeCoverage,
} from "@/lib/runtimeCoverage";

const GATE_LABELS = {
  [RUNTIME_GATE_RETURN]: "Return gate",
  [RUNTIME_GATE_INSTALL]: "Install gate",
};

const formatBlockTime = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "Unknown time" : date.toLocaleString();
};

const RuntimeBlocksCard = () => {
  const [state, setState] = useState({ status: "loading", blocks: [] });

  useEffect(() => {
    let active = true;
    dashboard
      .getRuntimeBlocks()
      .then((response) => {
        if (!active) return;
        const blocks = Array.isArray(response?.data?.blocks)
          ? response.data.blocks
          : [];
        setState({ status: "ready", blocks });
      })
      .catch(() => {
        if (active) setState({ status: "error", blocks: [] });
      });
    return () => {
      active = false;
    };
  }, []);

  return (
    <section
      className="glass-platinum rounded-lg p-3"
      data-testid="runtime-blocks-card"
      aria-label="Runtime blocks"
    >
      <div className="mb-2 flex items-center gap-1.5">
        <ShieldAlert size={12} className="text-[#E5E4E2]" />
        <h3 className="font-tech text-xs font-semibold uppercase tracking-[0.2em] text-[#E5E4E2]">
          Runtime blocks
        </h3>
      </div>

      {state.status === "loading" ? (
        <p
          className="text-[11px] text-[#BFC1C2]"
          data-testid="runtime-blocks-loading"
        >
          Loading runtime blocks...
        </p>
      ) : null}

      {state.status === "error" ? (
        <p
          className="text-[11px] text-[#BFC1C2]"
          data-testid="runtime-blocks-error"
        >
          Runtime blocks are unavailable right now.
        </p>
      ) : null}

      {state.status === "ready" && state.blocks.length === 0 ? (
        <p
          className="text-[11px] text-[#BFC1C2]"
          data-testid="runtime-blocks-empty"
        >
          No runtime blocks recorded yet.
        </p>
      ) : null}

      {state.status === "ready" && state.blocks.length > 0 ? (
        <ul className="space-y-2" data-testid="runtime-blocks-list">
          {state.blocks.map((block) => {
            const auditOnly =
              getRuntimeCoverage(block.platform, block.gate) === COVERAGE_AUDIT;
            return (
              <li
                key={block.id}
                className="rounded-md border border-white/10 bg-white/5 p-2 text-[11px] text-[#BFC1C2]"
                data-testid="runtime-block-item"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-[#E5E4E2]">
                    {block.platform}
                  </span>
                  <span>{GATE_LABELS[block.gate] ?? block.gate}</span>
                  {auditOnly ? (
                    <span
                      className="rounded border border-white/20 px-1 text-[10px] uppercase"
                      data-testid="runtime-block-audit-only"
                    >
                      {COVERAGE_LABELS[COVERAGE_AUDIT]}
                    </span>
                  ) : null}
                </div>
                <p className="mt-1 break-words">Reason: {block.reason}</p>
                <p className="mt-1 text-[10px] text-white/50">
                  {formatBlockTime(block.created_at)}
                </p>
              </li>
            );
          })}
        </ul>
      ) : null}
    </section>
  );
};

export default RuntimeBlocksCard;
