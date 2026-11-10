import React from "react";
import { render, screen, cleanup } from "@testing-library/react";

jest.mock("@/hooks/useCountUp", () => ({
  useCountUp: (value) => value,
}));

jest.mock("framer-motion", () => {
  const React = require("react");

  return {
    AnimatePresence: ({ children }) => <>{children}</>,
    motion: {
      tr: ({ children, ...props }) => {
        const filteredProps = { ...props };
        delete filteredProps.layout;
        delete filteredProps.initial;
        delete filteredProps.animate;
        delete filteredProps.exit;
        delete filteredProps.transition;
        return <tr {...filteredProps}>{children}</tr>;
      },
    },
  };
});

jest.mock("recharts", () => ({
  ResponsiveContainer: ({ children }) => (
    <div data-testid="responsive-container">{children}</div>
  ),
  BarChart: ({ children, data }) => (
    <div data-testid="bar-chart" data-points={data?.length ?? 0}>
      {children}
    </div>
  ),
  Bar: ({ children }) => <div data-testid="bar-series">{children}</div>,
  XAxis: () => <div data-testid="x-axis" />,
  YAxis: () => <div data-testid="y-axis" />,
  Tooltip: () => <div data-testid="chart-tooltip" />,
  CartesianGrid: () => <div data-testid="chart-grid" />,
  Cell: () => <div data-testid="chart-cell" />,
}));

import SecurityAnalysis from "@/components/dashboard/SecurityAnalysis";

const ATTACKS = [
  {
    id: "attack-1",
    timestamp: "2026-07-12T10:15:00.000Z",
    threat_type: "Prompt Injection",
    risk_score: 22,
    verdict: "ALLOW",
  },
  {
    id: "attack-2",
    timestamp: "2026-07-12T11:20:00.000Z",
    threat_type: "Secrets Leakage",
    risk_score: 74,
    verdict: "BLOCK",
  },
  {
    id: "attack-3",
    timestamp: "2026-07-12T12:45:00.000Z",
    threat_type: "Malware File",
    risk_score: 91,
    verdict: "BLOCK",
  },
];

const DAILY_USAGE = [
  { label: "Mon", units: 11 },
  { label: "Tue", units: 17 },
  { label: "Wed", units: 23 },
  { label: "Thu", units: 29 },
  { label: "Fri", units: 31 },
  { label: "Sat", units: 19 },
  { label: "Sun", units: 13 },
];

describe("SecurityAnalysis", () => {
  beforeEach(() => {
    jest.useFakeTimers();
  });

  afterEach(() => {
    jest.clearAllTimers();
    jest.useRealTimers();
    cleanup();
  });

  it("renders the card heading and stat labels", () => {
    render(
      <SecurityAnalysis
        unitsToday={12}
        unitsWeek={45}
        dailyUsage={DAILY_USAGE}
        attacks={ATTACKS}
      />,
    );

    expect(screen.getByTestId("security-analysis-card")).toBeInTheDocument();
    expect(screen.getByText("Security Analysis")).toBeInTheDocument();
    expect(screen.getByText("Units used today")).toBeInTheDocument();
    expect(screen.getByText("Units used this week")).toBeInTheDocument();
  });

  it("renders live values immediately when incoming data is provided", () => {
    render(
      <SecurityAnalysis
        unitsToday={120}
        unitsWeek={840}
        dailyUsage={DAILY_USAGE}
        attacks={ATTACKS}
      />,
    );

    expect(screen.getByText("120")).toBeInTheDocument();
    expect(screen.getByText("840")).toBeInTheDocument();
    expect(screen.getByTestId("usage-chart")).toBeInTheDocument();
    expect(screen.getByTestId("attack-log")).toBeInTheDocument();
    expect(
      screen.queryByTestId("usage-chart-skeleton"),
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId("attack-log-skeleton")).not.toBeInTheDocument();
  });

  it("renders cached populated results when remounted with empty props", () => {
    const { unmount } = render(
      <SecurityAnalysis
        unitsToday={333}
        unitsWeek={999}
        dailyUsage={DAILY_USAGE}
        attacks={ATTACKS}
      />,
    );

    expect(screen.getByText("333")).toBeInTheDocument();
    expect(screen.getByText("999")).toBeInTheDocument();
    expect(screen.getByText("Prompt Injection")).toBeInTheDocument();

    unmount();

    render(
      <SecurityAnalysis
        unitsToday={0}
        unitsWeek={0}
        dailyUsage={[]}
        attacks={[]}
      />,
    );

    expect(
      screen.queryByTestId("usage-chart-skeleton"),
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId("attack-log-skeleton")).not.toBeInTheDocument();
    expect(screen.getByText("333")).toBeInTheDocument();
    expect(screen.getByText("999")).toBeInTheDocument();
    expect(screen.getByText("Prompt Injection")).toBeInTheDocument();
    expect(
      screen.queryByText("No threats recorded yet."),
    ).not.toBeInTheDocument();
  });

  it("updates the cache when newer incoming data arrives", () => {
    const { rerender, unmount } = render(
      <SecurityAnalysis
        unitsToday={10}
        unitsWeek={20}
        dailyUsage={DAILY_USAGE.slice(0, 3)}
        attacks={ATTACKS.slice(0, 1)}
      />,
    );

    expect(screen.getByText("10")).toBeInTheDocument();
    expect(screen.getByText("20")).toBeInTheDocument();
    expect(screen.getByText("Prompt Injection")).toBeInTheDocument();

    rerender(
      <SecurityAnalysis
        unitsToday={500}
        unitsWeek={1500}
        dailyUsage={DAILY_USAGE}
        attacks={ATTACKS}
      />,
    );

    expect(screen.getByText("500")).toBeInTheDocument();
    expect(screen.getByText("1,500")).toBeInTheDocument();
    expect(screen.getByText("Malware File")).toBeInTheDocument();

    unmount();

    render(
      <SecurityAnalysis
        unitsToday={0}
        unitsWeek={0}
        dailyUsage={[]}
        attacks={[]}
      />,
    );

    expect(screen.getByText("500")).toBeInTheDocument();
    expect(screen.getByText("1,500")).toBeInTheDocument();
    expect(screen.getByText("Malware File")).toBeInTheDocument();
  });

  it("renders a chart shell with the same number of cells as usage points", () => {
    render(
      <SecurityAnalysis
        unitsToday={12}
        unitsWeek={45}
        dailyUsage={DAILY_USAGE}
        attacks={ATTACKS}
      />,
    );

    expect(screen.getByTestId("bar-chart")).toHaveAttribute(
      "data-points",
      String(DAILY_USAGE.length),
    );
    expect(screen.getAllByTestId("chart-cell")).toHaveLength(
      DAILY_USAGE.length,
    );
  });

  it("renders attack rows with threat, risk score, and verdict", () => {
    render(
      <SecurityAnalysis
        unitsToday={12}
        unitsWeek={45}
        dailyUsage={DAILY_USAGE}
        attacks={ATTACKS}
      />,
    );

    expect(screen.getByText("Prompt Injection")).toBeInTheDocument();
    expect(screen.getByText("Secrets Leakage")).toBeInTheDocument();
    expect(screen.getByText("Malware File")).toBeInTheDocument();
    expect(screen.getByText("22")).toBeInTheDocument();
    expect(screen.getByText("74")).toBeInTheDocument();
    expect(screen.getByText("91")).toBeInTheDocument();
    expect(screen.getByText("ALLOW")).toBeInTheDocument();
    expect(screen.getAllByText("BLOCK")).toHaveLength(2);
  });

  it("retains styles for legacy verdicts in historical rows", () => {
    const historicalAttacks = [
      {
        id: "legacy-warn",
        timestamp: "2026-07-12T11:20:00.000Z",
        threat_type: "Legacy warning",
        risk_score: 58,
        verdict: "WARN",
      },
      {
        id: "legacy-quarantine",
        timestamp: "2026-07-12T11:25:00.000Z",
        threat_type: "Legacy quarantine",
        risk_score: 69,
        verdict: "QUARANTINE",
      },
    ];

    render(
      <SecurityAnalysis
        unitsToday={12}
        unitsWeek={45}
        dailyUsage={DAILY_USAGE}
        attacks={historicalAttacks}
      />,
    );

    expect(screen.getByText("WARN")).toHaveClass("text-[#EAB308]");
    expect(screen.getByText("QUARANTINE")).toHaveClass("text-[#737373]");
  });

  it("falls back to empty attack state when attacks are empty with live incoming stats", () => {
    render(
      <SecurityAnalysis
        unitsToday={7}
        unitsWeek={21}
        dailyUsage={DAILY_USAGE}
        attacks={[]}
      />,
    );

    expect(screen.getByTestId("attack-log")).toBeInTheDocument();
    expect(screen.getByText("No threats recorded yet.")).toBeInTheDocument();
  });

  it("does not show loading skeletons on a later empty mount after cache has already been populated", () => {
    const { unmount } = render(
      <SecurityAnalysis
        unitsToday={120}
        unitsWeek={840}
        dailyUsage={DAILY_USAGE}
        attacks={ATTACKS}
      />,
    );

    unmount();

    render(
      <SecurityAnalysis
        unitsToday={0}
        unitsWeek={0}
        dailyUsage={[]}
        attacks={[]}
      />,
    );

    expect(
      screen.queryByTestId("skeleton-units-used-today"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("skeleton-units-used-this-week"),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByTestId("usage-chart-skeleton"),
    ).not.toBeInTheDocument();
    expect(screen.queryByTestId("attack-log-skeleton")).not.toBeInTheDocument();
    expect(screen.getByTestId("usage-chart")).toBeInTheDocument();
    expect(screen.getByTestId("attack-log")).toBeInTheDocument();
    expect(screen.getByText("120")).toBeInTheDocument();
    expect(screen.getByText("840")).toBeInTheDocument();
  });
});
