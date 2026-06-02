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
  WARN: "bg-[#EAB308]/10 text-[#EAB308] border-[#EAB308]/25",
  QUARANTINE: "bg-[#F97316]/10 text-[#F97316] border-[#F97316]/25",
  BLOCK: "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/25",
};

const scoreColor = (s) => {
  if (s < 30) return "#22C55E";
  if (s < 60) return "#EAB308";
  if (s < 85) return "#F97316";
  return "#EF4444";
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

const StatBlock = ({ label, value, accent }) => {
  const animated = useCountUp(value, 1300, [value]);
  return (
    <div className="rounded-xl border border-white/10 bg-black/30 p-4">
      <div className="text-[10px] uppercase tracking-widest text-[#BFC1C2]">
        {label}
      </div>
      <div className="font-tech text-3xl font-bold" style={{ color: accent }}>
        {animated.toLocaleString()}
      </div>
      <div className="text-[10px] text-[#737373]">units</div>
    </div>
  );
};

const SecurityAnalysis = ({
  unitsToday = 0,
  unitsWeek = 0,
  dailyUsage = [],
  attacks = [],
}) => {
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
          value={unitsToday}
          accent="#38BDF8"
        />
        <StatBlock
          label="Units used this week"
          value={unitsWeek}
          accent="#E5E4E2"
        />
      </div>

      <div className="mb-2 text-[10px] uppercase tracking-widest text-[#BFC1C2]">
        Daily unit usage &mdash; last 7 days
      </div>
      <div className="mb-6 h-48 w-full" data-testid="usage-chart">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={dailyUsage}
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
              {dailyUsage.map((entry, idx) => (
                <Cell
                  key={idx}
                  fill="#38BDF8"
                  fillOpacity={0.45 + (idx / (dailyUsage.length || 1)) * 0.5}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      <div className="mb-3 flex items-center gap-2 text-[10px] uppercase tracking-widest text-[#BFC1C2]">
        <ShieldAlert size={13} /> Live attack log
      </div>
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
            <AnimatePresence initial={false}>
              {attacks.map((a) => (
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
                        color: scoreColor(a.risk_score),
                        background: `${scoreColor(a.risk_score)}1a`,
                      }}
                    >
                      {a.risk_score}
                    </span>
                  </td>
                  <td className="px-4 py-2.5">
                    <span
                      className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${VERDICT_STYLES[a.verdict]}`}
                    >
                      {a.verdict}
                    </span>
                  </td>
                </motion.tr>
              ))}
            </AnimatePresence>
            {attacks.length === 0 && (
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
    </div>
  );
};

export default SecurityAnalysis;
