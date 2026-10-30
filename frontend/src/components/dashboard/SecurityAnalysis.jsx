import { useEffect, useMemo, useRef, useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  ResponsiveContainer,
  Tooltip,
  CartesianGrid,
  Cell,
} from "recharts";
import { Activity, ShieldAlert } from "lucide-react";
import { useCountUp } from "@/hooks/useCountUp";

const VERDICT_STYLES = {
  ALLOW: "bg-[#22C55E]/10 text-[#22C55E] border-[#22C55E]/25",
  BLOCK: "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/25",
};

const LEGACY_VERDICT_STYLES = {
  WARN: "bg-[#EAB308]/10 text-[#EAB308] border-[#EAB308]/25",
  QUARANTINE: "bg-[#F97316]/10 text-[#F97316] border-[#F97316]/25",
};

const VERDICT_COLORS = {
  ALLOW: "#22C55E",
  BLOCK: "#EF4444",
};

const LEGACY_VERDICT_COLORS = {
  WARN: "#EAB308",
  QUARANTINE: "#F97316",
};

const normalizeVerdict = (verdict) => String(verdict ?? "").toUpperCase();

const verdictStyle = (verdict) => {
  const normalized = normalizeVerdict(verdict);
  return (
    VERDICT_STYLES[normalized] ??
    LEGACY_VERDICT_STYLES[normalized] ??
    "bg-[#737373]/10 text-[#737373] border-[#737373]/25"
  );
};

const verdictColor = (verdict) => {
  const normalized = normalizeVerdict(verdict);
  return (
    VERDICT_COLORS[normalized] ?? LEGACY_VERDICT_COLORS[normalized] ?? "#737373"
  );
};

const fmtTime = (iso) => {
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
};

const CustomTooltip = ({ active, payload }) => {
  if (active && payload && payload.length) {
    return (
      <div className="glass rounded-lg px-3 py-2 text-xs">
        <p className="font-tech text-white">{payload[0].payload.label}</p>
        <p className="text-[#38BDF8]">
          {payload[0].value.toLocaleString()} units
        </p>
      </div>
    );
  }
  return null;
};

const StatBlock = ({ label, value, accent, loading = false }) => {
  const animated = useCountUp(value, 1300, [value]);

  return (
    <div className="rounded-xl border border-white/10 bg-black/30 p-4">
      <div className="text-[10px] uppercase tracking-widest text-[#BFC1C2]">
        {label}
      </div>
      {loading ? (
        <div
          className="mt-2 h-9 w-24 animate-pulse rounded-md bg-white/10"
          data-testid={`skeleton-${label.toLowerCase().replace(/\s+/g, "-")}`}
        />
      ) : (
        <div className="font-tech text-3xl font-bold" style={{ color: accent }}>
          {animated.toLocaleString()}
        </div>
      )}
      <div className="text-[10px] text-[#737373]">units</div>
    </div>
  );
};

const ChartSkeleton = () => (
  <div
    className="mb-6 h-48 w-full animate-pulse rounded-xl border border-white/10 bg-black/20 p-4"
    data-testid="usage-chart-skeleton"
  >
    <div className="flex h-full items-end gap-2">
      {[32, 56, 40, 72, 58, 84, 50].map((height, index) => (
        <div
          key={index}
          className="flex-1 rounded-t bg-[#38BDF8]/20"
          style={{ height: `${height}%` }}
        />
      ))}
    </div>
  </div>
);

const TableSkeleton = () => (
  <div
    className="rounded-xl border border-white/10"
    data-testid="attack-log-skeleton"
  >
    <div className="grid grid-cols-4 gap-4 border-b border-white/5 px-4 py-3 text-[10px] uppercase tracking-wider text-[#737373]">
      <div>Timestamp</div>
      <div>Threat</div>
      <div>Risk</div>
      <div>Verdict</div>
    </div>
    <div className="space-y-3 p-4">
      {[0, 1, 2, 3].map((row) => (
        <div key={row} className="grid grid-cols-4 gap-4">
          <div className="h-4 animate-pulse rounded bg-white/10" />
          <div className="h-4 animate-pulse rounded bg-white/10" />
          <div className="h-4 animate-pulse rounded bg-white/10" />
          <div className="h-4 animate-pulse rounded bg-white/10" />
        </div>
      ))}
    </div>
  </div>
);

const EMPTY_CACHE = {
  unitsToday: 0,
  unitsWeek: 0,
  dailyUsage: [],
  attacks: [],
};

let securityAnalysisCache = null;

const SecurityAnalysis = ({
  unitsToday = 0,
  unitsWeek = 0,
  dailyUsage = [],
  attacks = [],
}) => {
  const hasIncomingData =
    unitsToday > 0 ||
    unitsWeek > 0 ||
    dailyUsage.length > 0 ||
    attacks.length > 0;

  const [cachedData, setCachedData] = useState(
    () => securityAnalysisCache || EMPTY_CACHE,
  );
  const [isHydrating, setIsHydrating] = useState(() => !securityAnalysisCache);
  const hydrationTimerRef = useRef(null);

  useEffect(() => {
    if (hasIncomingData) {
      const nextData = {
        unitsToday,
        unitsWeek,
        dailyUsage,
        attacks,
      };

      securityAnalysisCache = nextData;
      setCachedData(nextData);
      setIsHydrating(false);

      if (hydrationTimerRef.current) {
        clearTimeout(hydrationTimerRef.current);
        hydrationTimerRef.current = null;
      }

      return;
    }

    if (securityAnalysisCache) {
      setCachedData(securityAnalysisCache);
      setIsHydrating(false);
      return;
    }

    setIsHydrating(true);

    hydrationTimerRef.current = setTimeout(() => {
      setIsHydrating(false);
      hydrationTimerRef.current = null;
    }, 800);

    return () => {
      if (hydrationTimerRef.current) {
        clearTimeout(hydrationTimerRef.current);
        hydrationTimerRef.current = null;
      }
    };
  }, [unitsToday, unitsWeek, dailyUsage, attacks, hasIncomingData]);

  const displayData = useMemo(
    () =>
      hasIncomingData
        ? { unitsToday, unitsWeek, dailyUsage, attacks }
        : cachedData,
    [hasIncomingData, unitsToday, unitsWeek, dailyUsage, attacks, cachedData],
  );

  const chartCells = useMemo(
    () =>
      displayData.dailyUsage.map((entry, idx) => (
        <Cell
          key={`${entry.label ?? idx}-${idx}`}
          fill="#38BDF8"
          fillOpacity={
            0.45 + (idx / (displayData.dailyUsage.length || 1)) * 0.5
          }
        />
      )),
    [displayData.dailyUsage],
  );

  const attackRows = useMemo(
    () =>
      displayData.attacks.map((a) => (
        <motion.tr
          key={a.id}
          layout
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.35 }}
          className="border-t border-white/5 hover:bg-white/[0.03]"
        >
          <td className="font-tech px-4 py-2.5 text-[#BFC1C2]">
            {fmtTime(a.timestamp)}
          </td>
          <td className="px-4 py-2.5 text-white">{a.threat_type}</td>
          <td className="px-4 py-2.5">
            <span
              className="font-tech rounded px-2 py-0.5 text-[11px] font-bold"
              style={{
                color: verdictColor(a.verdict),
                background: `${verdictColor(a.verdict)}1a`,
              }}
            >
              {a.risk_score}
            </span>
          </td>
          <td className="px-4 py-2.5">
            <span
              className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${verdictStyle(
                a.verdict,
              )}`}
            >
              {a.verdict}
            </span>
          </td>
        </motion.tr>
      )),
    [displayData.attacks],
  );

  return (
    <div
      className="glass-blue rounded-2xl p-7"
      data-testid="security-analysis-card"
    >
      <div className="mb-6 flex items-center gap-2">
        <Activity size={18} className="text-[#38BDF8]" />
        <h2 className="font-tech text-sm font-semibold uppercase tracking-[0.25em] text-[#38BDF8]">
          Security Analysis
        </h2>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-4">
        <StatBlock
          label="Units used today"
          value={displayData.unitsToday}
          accent="#38BDF8"
          loading={isHydrating}
        />
        <StatBlock
          label="Units used this week"
          value={displayData.unitsWeek}
          accent="#E5E4E2"
          loading={isHydrating}
        />
      </div>

      <div className="mb-2 text-[10px] uppercase tracking-widest text-[#BFC1C2]">
        Daily unit usage &mdash; last 7 days
      </div>

      {isHydrating ? (
        <ChartSkeleton />
      ) : (
        <div className="mb-6 h-48 w-full" data-testid="usage-chart">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={displayData.dailyUsage}
              margin={{ top: 8, right: 4, left: -18, bottom: 0 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="rgba(255,255,255,0.06)"
                vertical={false}
              />
              <XAxis
                dataKey="label"
                tick={{
                  fill: "#737373",
                  fontSize: 11,
                  fontFamily: "JetBrains Mono",
                }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{
                  fill: "#737373",
                  fontSize: 11,
                  fontFamily: "JetBrains Mono",
                }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                content={<CustomTooltip />}
                cursor={{ fill: "rgba(56,189,248,0.08)" }}
              />
              <Bar dataKey="units" radius={[4, 4, 0, 0]}>
                {chartCells}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      <div className="mb-3 flex items-center gap-2 text-[10px] uppercase tracking-widest text-[#BFC1C2]">
        <ShieldAlert size={13} /> Live attack log
      </div>

      {isHydrating ? (
        <TableSkeleton />
      ) : (
        <div
          className="max-h-72 overflow-y-auto rounded-xl border border-white/10"
          data-testid="attack-log"
        >
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 bg-[#0a0b0d]/90 backdrop-blur">
              <tr className="text-[10px] uppercase tracking-wider text-[#737373]">
                <th className="px-4 py-3 font-medium">Timestamp</th>
                <th className="px-4 py-3 font-medium">Threat</th>
                <th className="px-4 py-3 font-medium">Risk</th>
                <th className="px-4 py-3 font-medium">Verdict</th>
              </tr>
            </thead>
            <tbody>
              <AnimatePresence initial={false}>{attackRows}</AnimatePresence>
              {displayData.attacks.length === 0 && (
                <tr>
                  <td
                    colSpan={4}
                    className="px-4 py-8 text-center text-[#737373]"
                  >
                    No threats recorded yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};

export default SecurityAnalysis;
