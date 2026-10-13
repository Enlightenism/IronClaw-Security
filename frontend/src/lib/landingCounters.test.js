import { act, renderHook } from "@testing-library/react";
import { supabase } from "@/lib/supabase";
import {
  computeCounterValue,
  getLandingCounterStore,
  hash32,
  LANDING_COUNTER_FALLBACKS,
  resetLandingCounters,
  syncLandingCounters,
  useLandingCounter,
} from "@/lib/landingCounters";

jest.mock("@/lib/supabase", () => ({
  supabase: { rpc: jest.fn() },
}));

const THREATS = LANDING_COUNTER_FALLBACKS.threats_blocked;
const ENGINEERS = LANDING_COUNTER_FALLBACKS.engineers_protected;

const START_MS = Date.UTC(2026, 9, 13, 6, 0, 0);
const TICK_MS = 600 * 1000;
const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const SYNC_MS = 5 * 60 * 1000;

const THREATS_MIN_KEY = "ironclaw:landing-counter-min:threats_blocked";
const ENGINEERS_MIN_KEY = "ironclaw:landing-counter-min:engineers_protected";

// Shared with the SQL migration tests: the SQL hash must produce these values.
const HASH_VECTORS = [
  [1736102489, 0, 3056090455],
  [1736102489, 1, 3622855923],
  [1736102489, 2, 3510258675],
  [1736102489, 3, 2279842973],
  [1736102489, 10, 1574579506],
  [1736102489, 2933333, 2889397415],
  [1736102489, 2933334, 3355178022],
  [1736102489, 4294967295, 3250598578],
  [2406839077, 0, 1995626446],
  [2406839077, 1, 650592004],
  [2406839077, 2, 2890143157],
  [2406839077, 3, 3113384485],
  [2406839077, 10, 1957474908],
  [2406839077, 2933333, 2958952686],
  [2406839077, 2933334, 4012410247],
  [2406839077, 4294967295, 9659748],
];

const VALUE_VECTORS = [
  [0, 732, 344],
  [600 * 1000, 734, 345],
  [6000 * 1000, 754, 354],
  [DAY_MS, 1084, 488],
  [30 * DAY_MS, 11493, 4664],
  [365 * DAY_MS, 131914, 52904],
];

const freezeTimeAt = (nowMs) => {
  jest.useFakeTimers();
  jest.setSystemTime(new Date(nowMs));
};

const flushMicrotasks = async () => {
  for (let i = 0; i < 20; i += 1) {
    await Promise.resolve();
  }
};

const buildRow = (counterKey, serverMs, overrides = {}) => {
  const config = LANDING_COUNTER_FALLBACKS[counterKey];

  return {
    counter_key: counterKey,
    value: computeCounterValue(config, serverMs),
    server_time: new Date(serverMs).toISOString(),
    anchor_value: config.anchorValue,
    anchor_at: new Date(config.anchorAtMs).toISOString(),
    tick_seconds: config.tickMs / 1000,
    step_min: config.stepMin,
    step_max: config.stepMax,
    seed: config.seed,
    ...overrides,
  };
};

const buildRows = (serverMs) => [
  buildRow("threats_blocked", serverMs),
  buildRow("engineers_protected", serverMs),
];

const mockServerAhead = (aheadMs = 0) => {
  supabase.rpc.mockImplementation(async () => ({
    data: buildRows(Date.now() + aheadMs),
    error: null,
  }));
};

const setVisibility = (state) => {
  Object.defineProperty(document, "visibilityState", {
    value: state,
    configurable: true,
  });
};

const walkTicks = (config, ticks) => {
  let value = config.anchorValue;
  let tickStartMs = config.anchorAtMs;
  let regressions = 0;
  const deltas = new Set();

  for (let i = 0; i < ticks; i += 1) {
    const nextMs = tickStartMs + config.tickMs;
    const next = computeCounterValue(
      { ...config, anchorValue: value, anchorAtMs: tickStartMs },
      nextMs,
    );

    if (next <= value) {
      regressions += 1;
    }

    deltas.add(next - value);
    value = next;
    tickStartMs = nextMs;
  }

  return { value, regressions, deltas: [...deltas].sort((a, b) => a - b) };
};

beforeEach(() => {
  jest.clearAllMocks();
  resetLandingCounters();
  window.localStorage.clear();
  setVisibility("visible");
  supabase.rpc.mockReset();
  supabase.rpc.mockResolvedValue({ data: [], error: null });
});

afterEach(() => {
  resetLandingCounters();
  jest.useRealTimers();
  jest.restoreAllMocks();
  window.localStorage.clear();
});

describe("fallback configuration", () => {
  it("matches the database seed rows exactly", () => {
    expect(THREATS).toEqual({
      anchorValue: 732,
      anchorAtMs: Date.UTC(2026, 9, 13, 6, 0, 0),
      tickMs: 600000,
      stepMin: 2,
      stepMax: 3,
      seed: 1736102489,
    });
    expect(ENGINEERS).toEqual({
      anchorValue: 344,
      anchorAtMs: Date.UTC(2026, 9, 13, 6, 0, 0),
      tickMs: 600000,
      stepMin: 1,
      stepMax: 1,
      seed: 2406839077,
    });
  });

  it("is immutable and aligned to the shared tick boundary", () => {
    expect(Object.isFrozen(LANDING_COUNTER_FALLBACKS)).toBe(true);
    expect(Object.isFrozen(THREATS)).toBe(true);
    expect(Object.isFrozen(ENGINEERS)).toBe(true);
    expect(THREATS.anchorAtMs % THREATS.tickMs).toBe(0);
    expect(ENGINEERS.anchorAtMs % ENGINEERS.tickMs).toBe(0);
  });
});

describe("hash32", () => {
  it.each(HASH_VECTORS)(
    "returns the fixed SQL-compatible value for seed %i tick %i",
    (seed, tick, expected) => {
      expect(hash32(seed, tick)).toBe(expected);
    },
  );

  it("always returns an unsigned 32-bit integer", () => {
    for (let tick = 0; tick < 5000; tick += 1) {
      const hashed = hash32(THREATS.seed, tick);

      expect(Number.isInteger(hashed)).toBe(true);
      expect(hashed).toBeGreaterThanOrEqual(0);
      expect(hashed).toBeLessThanOrEqual(0xffffffff);
    }
  });
});

describe("computeCounterValue", () => {
  it.each(VALUE_VECTORS)(
    "matches the fixed vectors at anchor + %i ms",
    (offsetMs, threats, engineers) => {
      expect(computeCounterValue(THREATS, START_MS + offsetMs)).toBe(threats);
      expect(computeCounterValue(ENGINEERS, START_MS + offsetMs)).toBe(
        engineers,
      );
    },
  );

  it("returns the anchor value before the first tick and for invalid clocks", () => {
    expect(computeCounterValue(THREATS, START_MS - 400 * DAY_MS)).toBe(732);
    expect(computeCounterValue(ENGINEERS, START_MS - 400 * DAY_MS)).toBe(344);
    expect(computeCounterValue(THREATS, START_MS + TICK_MS - 1)).toBe(732);
    expect(computeCounterValue(THREATS, Number.NaN)).toBe(732);
    expect(computeCounterValue(ENGINEERS, Number.POSITIVE_INFINITY)).toBe(344);
  });

  it("adds a step only when a shared tick boundary is crossed", () => {
    expect(computeCounterValue(THREATS, START_MS + TICK_MS)).toBe(734);
    expect(computeCounterValue(THREATS, START_MS + 2 * TICK_MS - 1)).toBe(734);
    expect(computeCounterValue(ENGINEERS, START_MS + TICK_MS)).toBe(345);
    expect(computeCounterValue(ENGINEERS, START_MS + 2 * TICK_MS - 1)).toBe(
      345,
    );
  });

  it("keeps threat steps in the 2-3 band and engineer steps at exactly 1", () => {
    const threats = walkTicks(THREATS, 20000);
    const engineers = walkTicks(ENGINEERS, 20000);

    expect(threats.deltas).toEqual([2, 3]);
    expect(engineers.deltas).toEqual([1]);
  });

  it("only increases over 100,000 ticks and matches the direct formula", () => {
    const threats = walkTicks(THREATS, 100000);
    const engineers = walkTicks(ENGINEERS, 100000);
    const endMs = START_MS + 100000 * TICK_MS;

    expect(threats.regressions).toBe(0);
    expect(engineers.regressions).toBe(0);
    expect(threats.value).toBe(computeCounterValue(THREATS, endMs));
    expect(engineers.value).toBe(computeCounterValue(ENGINEERS, endMs));
    expect(engineers.value).toBe(344 + 100000);
  });

  it("never resets after more than 24 hours", () => {
    const afterOneHour = computeCounterValue(THREATS, START_MS + HOUR_MS);
    const afterDay = computeCounterValue(THREATS, START_MS + 25 * HOUR_MS);
    const afterWeek = computeCounterValue(THREATS, START_MS + 7 * DAY_MS);

    expect(afterOneHour).toBeGreaterThan(732);
    expect(afterDay).toBeGreaterThan(afterOneHour);
    expect(afterWeek).toBeGreaterThan(afterDay);
    expect(computeCounterValue(ENGINEERS, START_MS + 25 * HOUR_MS)).toBe(
      344 + 150,
    );
  });

  it("returns identical values for identical instants on any device", () => {
    const nowMs = START_MS + 3 * DAY_MS + 123456;

    expect(computeCounterValue({ ...THREATS }, nowMs)).toBe(
      computeCounterValue(THREATS, nowMs),
    );
    expect(computeCounterValue(THREATS, nowMs)).toBe(
      computeCounterValue(THREATS, nowMs - 123456),
    );
  });
});

describe("landing counter store", () => {
  it("returns one shared store per counter key", () => {
    expect(getLandingCounterStore("threats_blocked")).toBe(
      getLandingCounterStore("threats_blocked"),
    );
    expect(getLandingCounterStore("engineers_protected")).not.toBe(
      getLandingCounterStore("threats_blocked"),
    );
  });

  it("returns an inert zero store for unknown or prototype keys", () => {
    const unknown = getLandingCounterStore("not_a_counter");
    const unsubscribe = unknown.subscribe(jest.fn());

    expect(unknown.getSnapshot()).toBe(0);
    expect(getLandingCounterStore("constructor")).toBe(unknown);
    expect(getLandingCounterStore("__proto__")).toBe(unknown);
    expect(getLandingCounterStore(undefined)).toBe(unknown);
    expect(supabase.rpc).not.toHaveBeenCalled();

    unsubscribe();
  });

  it("starts from the local formula, never from 732/344, after the start time", () => {
    freezeTimeAt(START_MS + 25 * HOUR_MS);

    const threats = getLandingCounterStore("threats_blocked").getSnapshot();
    const engineers = getLandingCounterStore(
      "engineers_protected",
    ).getSnapshot();

    expect(threats).toBe(computeCounterValue(THREATS, START_MS + 25 * HOUR_MS));
    expect(engineers).toBe(
      computeCounterValue(ENGINEERS, START_MS + 25 * HOUR_MS),
    );
    expect(threats).toBeGreaterThan(732);
    expect(engineers).toBeGreaterThan(344);
  });

  it("shows the anchor values before the start time", () => {
    freezeTimeAt(START_MS - HOUR_MS);

    expect(getLandingCounterStore("threats_blocked").getSnapshot()).toBe(732);
    expect(getLandingCounterStore("engineers_protected").getSnapshot()).toBe(
      344,
    );
  });

  it("ticks on the shared 10-minute boundary instead of from page load", async () => {
    const loadMs = START_MS + 2 * HOUR_MS + 90 * 1000;
    freezeTimeAt(loadMs);

    const store = getLandingCounterStore("threats_blocked");
    const listener = jest.fn();
    const unsubscribe = store.subscribe(listener);
    await flushMicrotasks();

    const firstValue = store.getSnapshot();
    expect(firstValue).toBe(computeCounterValue(THREATS, loadMs));

    jest.advanceTimersByTime(510 * 1000 - 1);
    expect(listener).not.toHaveBeenCalled();
    expect(store.getSnapshot()).toBe(firstValue);

    jest.advanceTimersByTime(1);
    expect(listener).toHaveBeenCalledTimes(1);
    expect(store.getSnapshot()).toBe(
      computeCounterValue(THREATS, loadMs + 510 * 1000),
    );

    jest.advanceTimersByTime(TICK_MS);
    expect(listener).toHaveBeenCalledTimes(2);
    expect(store.getSnapshot()).toBe(
      computeCounterValue(THREATS, loadMs + 510 * 1000 + TICK_MS),
    );

    unsubscribe();
  });

  it("corrects for a device clock that is behind the server", async () => {
    const deviceMs = START_MS + 2 * HOUR_MS + 90 * 1000;
    const serverAheadMs = 3 * HOUR_MS;
    freezeTimeAt(deviceMs);
    mockServerAhead(serverAheadMs);

    const store = getLandingCounterStore("threats_blocked");
    expect(store.getSnapshot()).toBe(computeCounterValue(THREATS, deviceMs));

    const unsubscribe = store.subscribe(jest.fn());
    await expect(syncLandingCounters()).resolves.toBe(true);

    const serverMs = deviceMs + serverAheadMs;
    const syncedValue = store.getSnapshot();
    expect(syncedValue).toBe(computeCounterValue(THREATS, serverMs));

    jest.advanceTimersByTime(510 * 1000 - 1);
    expect(store.getSnapshot()).toBe(syncedValue);

    jest.advanceTimersByTime(1);
    expect(store.getSnapshot()).toBe(
      computeCounterValue(THREATS, serverMs + 510 * 1000),
    );

    unsubscribe();
  });

  it("converges devices whose clocks are behind or aligned with the server", async () => {
    const serverMs = START_MS + 6 * HOUR_MS + 45 * 1000;
    const shown = [];

    for (const deviceOffsetMs of [-2 * HOUR_MS, 0]) {
      resetLandingCounters();
      window.localStorage.clear();
      freezeTimeAt(serverMs + deviceOffsetMs);
      mockServerAhead(-deviceOffsetMs);

      const store = getLandingCounterStore("threats_blocked");
      const unsubscribe = store.subscribe(jest.fn());
      await syncLandingCounters();

      shown.push(store.getSnapshot());
      unsubscribe();
      jest.useRealTimers();
    }

    expect(new Set(shown).size).toBe(1);
    expect(shown[0]).toBe(computeCounterValue(THREATS, serverMs));
  });

  it("never lowers the display of a device whose clock is ahead of the server", async () => {
    const serverMs = START_MS + 6 * HOUR_MS + 45 * 1000;
    const deviceMs = serverMs + 5 * HOUR_MS;
    freezeTimeAt(deviceMs);
    mockServerAhead(-5 * HOUR_MS);

    const store = getLandingCounterStore("threats_blocked");
    const localValue = computeCounterValue(THREATS, deviceMs);
    const unsubscribe = store.subscribe(jest.fn());
    await syncLandingCounters();

    expect(computeCounterValue(THREATS, serverMs)).toBeLessThan(localValue);
    expect(store.getSnapshot()).toBe(localValue);

    unsubscribe();
  });

  it("shows the same value on two fresh devices at the same time", () => {
    const nowMs = START_MS + 3 * DAY_MS + 123456;
    freezeTimeAt(nowMs);

    const deviceA = getLandingCounterStore("threats_blocked").getSnapshot();

    resetLandingCounters();
    window.localStorage.clear();

    const deviceB = getLandingCounterStore("threats_blocked").getSnapshot();

    expect(deviceB).toBe(deviceA);
    expect(deviceA).toBe(computeCounterValue(THREATS, nowMs));
  });

  it("applies the server value and never goes lower afterwards", async () => {
    const nowMs = START_MS + HOUR_MS;
    freezeTimeAt(nowMs);
    supabase.rpc.mockResolvedValue({
      data: [
        buildRow("threats_blocked", nowMs, { value: 500000 }),
        buildRow("engineers_protected", nowMs, { value: 250000 }),
      ],
      error: null,
    });

    const store = getLandingCounterStore("threats_blocked");
    await expect(syncLandingCounters()).resolves.toBe(true);

    expect(supabase.rpc).toHaveBeenCalledWith("get_landing_counters");
    expect(store.getSnapshot()).toBe(500000);
    expect(getLandingCounterStore("engineers_protected").getSnapshot()).toBe(
      250000,
    );

    supabase.rpc.mockResolvedValue({
      data: [buildRow("threats_blocked", nowMs, { value: 1000 })],
      error: null,
    });
    await expect(syncLandingCounters()).resolves.toBe(true);

    expect(store.getSnapshot()).toBe(500000);
  });

  it("follows a re-anchored server configuration for future ticks", async () => {
    const nowMs = START_MS + HOUR_MS;
    freezeTimeAt(nowMs);
    supabase.rpc.mockResolvedValue({
      data: [
        buildRow("threats_blocked", nowMs, {
          value: 100000,
          anchor_value: 100000,
          anchor_at: new Date(nowMs).toISOString(),
        }),
      ],
      error: null,
    });

    const store = getLandingCounterStore("threats_blocked");
    const unsubscribe = store.subscribe(jest.fn());
    await syncLandingCounters();

    expect(store.getSnapshot()).toBe(100000);

    jest.advanceTimersByTime(TICK_MS);

    expect(store.getSnapshot()).toBe(
      computeCounterValue(
        { ...THREATS, anchorValue: 100000, anchorAtMs: nowMs },
        nowMs + TICK_MS,
      ),
    );

    unsubscribe();
  });

  it("falls back to the local formula, never 732/344, when the request fails", async () => {
    const nowMs = START_MS + 25 * HOUR_MS;
    freezeTimeAt(nowMs);

    const store = getLandingCounterStore("threats_blocked");
    const expected = computeCounterValue(THREATS, nowMs);

    supabase.rpc.mockRejectedValue(new Error("offline"));
    await expect(syncLandingCounters()).resolves.toBe(false);
    expect(store.getSnapshot()).toBe(expected);

    supabase.rpc.mockResolvedValue({
      data: null,
      error: { message: "boom" },
    });
    await expect(syncLandingCounters()).resolves.toBe(false);
    expect(store.getSnapshot()).toBe(expected);
    expect(store.getSnapshot()).toBeGreaterThan(732);
  });

  it("ignores unknown, malformed and invalid server rows", async () => {
    const nowMs = START_MS + HOUR_MS;
    freezeTimeAt(nowMs);

    const store = getLandingCounterStore("threats_blocked");
    const expected = computeCounterValue(THREATS, nowMs);

    supabase.rpc.mockResolvedValue({
      data: [
        buildRow("threats_blocked", nowMs, { counter_key: "other_counter" }),
        buildRow("threats_blocked", nowMs, { tick_seconds: 0 }),
        buildRow("threats_blocked", nowMs, { tick_seconds: 1.5 }),
        buildRow("threats_blocked", nowMs, { step_min: 5, step_max: 1 }),
        buildRow("threats_blocked", nowMs, { seed: 4294967296 }),
        buildRow("threats_blocked", nowMs, { value: null }),
        buildRow("threats_blocked", nowMs, { server_time: "not-a-date" }),
        buildRow("threats_blocked", nowMs, { anchor_at: "not-a-date" }),
        null,
        "garbage",
      ],
      error: null,
    });

    await expect(syncLandingCounters()).resolves.toBe(false);
    expect(store.getSnapshot()).toBe(expected);

    supabase.rpc.mockResolvedValue({ data: "not-an-array", error: null });
    await expect(syncLandingCounters()).resolves.toBe(false);
    expect(store.getSnapshot()).toBe(expected);
  });

  it("shares one in-flight request between concurrent syncs", async () => {
    freezeTimeAt(START_MS + HOUR_MS);

    const first = syncLandingCounters();
    const second = syncLandingCounters();

    expect(second).toBe(first);
    await first;
    expect(supabase.rpc).toHaveBeenCalledTimes(1);
  });

  it("gives up on a request that never answers", async () => {
    freezeTimeAt(START_MS + HOUR_MS);
    supabase.rpc.mockReturnValue(new Promise(() => undefined));

    const pending = syncLandingCounters();
    jest.advanceTimersByTime(10 * 1000);

    await expect(pending).resolves.toBe(false);
  });
});

describe("saved minimum", () => {
  it("never shows less than the saved minimum, with no expiry", () => {
    freezeTimeAt(START_MS + 60 * DAY_MS);
    window.localStorage.setItem(THREATS_MIN_KEY, "9999999");
    window.localStorage.setItem(ENGINEERS_MIN_KEY, "8888888");

    expect(getLandingCounterStore("threats_blocked").getSnapshot()).toBe(
      9999999,
    );
    expect(getLandingCounterStore("engineers_protected").getSnapshot()).toBe(
      8888888,
    );
  });

  it("keeps the saved minimum through server syncs and ticks", async () => {
    const nowMs = START_MS + HOUR_MS;
    freezeTimeAt(nowMs);
    window.localStorage.setItem(THREATS_MIN_KEY, "7654321");
    mockServerAhead(0);

    const store = getLandingCounterStore("threats_blocked");
    const unsubscribe = store.subscribe(jest.fn());
    await syncLandingCounters();
    jest.advanceTimersByTime(TICK_MS);

    expect(store.getSnapshot()).toBe(7654321);

    unsubscribe();
  });

  it("persists rising values as the new minimum", async () => {
    const nowMs = START_MS + HOUR_MS;
    freezeTimeAt(nowMs);

    const store = getLandingCounterStore("threats_blocked");

    expect(window.localStorage.getItem(THREATS_MIN_KEY)).toBe(
      String(computeCounterValue(THREATS, nowMs)),
    );

    supabase.rpc.mockResolvedValue({
      data: [buildRow("threats_blocked", nowMs, { value: 600000 })],
      error: null,
    });
    await syncLandingCounters();

    expect(store.getSnapshot()).toBe(600000);
    expect(window.localStorage.getItem(THREATS_MIN_KEY)).toBe("600000");
  });

  it("ignores invalid saved minimums and the old counter storage keys", () => {
    const nowMs = START_MS + 5 * HOUR_MS;
    freezeTimeAt(nowMs);
    window.localStorage.setItem(THREATS_MIN_KEY, "not-a-number");
    window.localStorage.setItem(ENGINEERS_MIN_KEY, "-50");
    window.localStorage.setItem(
      "ic_threats_blocked",
      JSON.stringify({ value: 99999999, updatedAt: Date.now() }),
    );

    expect(getLandingCounterStore("threats_blocked").getSnapshot()).toBe(
      computeCounterValue(THREATS, nowMs),
    );
    expect(getLandingCounterStore("engineers_protected").getSnapshot()).toBe(
      computeCounterValue(ENGINEERS, nowMs),
    );
  });

  it("survives unavailable storage", () => {
    const nowMs = START_MS + 5 * HOUR_MS;
    freezeTimeAt(nowMs);
    jest.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("denied");
    });
    jest.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("denied");
    });

    expect(getLandingCounterStore("threats_blocked").getSnapshot()).toBe(
      computeCounterValue(THREATS, nowMs),
    );
  });
});

describe("sync scheduling", () => {
  it("syncs on first subscribe and then every five minutes", async () => {
    freezeTimeAt(START_MS + HOUR_MS);

    const unsubscribe = getLandingCounterStore("threats_blocked").subscribe(
      jest.fn(),
    );
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(1);

    jest.advanceTimersByTime(SYNC_MS);
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(2);

    jest.advanceTimersByTime(SYNC_MS);
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(3);

    unsubscribe();
  });

  it("syncs again on focus, online and when the tab becomes visible", async () => {
    freezeTimeAt(START_MS + HOUR_MS);

    const unsubscribe = getLandingCounterStore("threats_blocked").subscribe(
      jest.fn(),
    );
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(1);

    window.dispatchEvent(new Event("focus"));
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(2);

    window.dispatchEvent(new Event("online"));
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(3);

    setVisibility("hidden");
    document.dispatchEvent(new Event("visibilitychange"));
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(3);

    setVisibility("visible");
    document.dispatchEvent(new Event("visibilitychange"));
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(4);

    unsubscribe();
  });

  it("recomputes immediately when the tab resumes after a long sleep", async () => {
    freezeTimeAt(START_MS + HOUR_MS);

    const store = getLandingCounterStore("threats_blocked");
    const unsubscribe = store.subscribe(jest.fn());
    await flushMicrotasks();

    jest.setSystemTime(new Date(START_MS + 30 * HOUR_MS));
    window.dispatchEvent(new Event("focus"));

    expect(store.getSnapshot()).toBe(
      computeCounterValue(THREATS, START_MS + 30 * HOUR_MS),
    );

    unsubscribe();
  });

  it("shares one runtime across subscribers and cleans up completely", async () => {
    freezeTimeAt(START_MS + HOUR_MS);
    const addSpy = jest.spyOn(window, "addEventListener");
    const removeSpy = jest.spyOn(window, "removeEventListener");

    const unsubscribeThreats = getLandingCounterStore(
      "threats_blocked",
    ).subscribe(jest.fn());
    const unsubscribeEngineers = getLandingCounterStore(
      "engineers_protected",
    ).subscribe(jest.fn());
    await flushMicrotasks();

    expect(supabase.rpc).toHaveBeenCalledTimes(1);
    expect(addSpy).toHaveBeenCalledWith("focus", expect.any(Function));
    expect(addSpy).toHaveBeenCalledWith("online", expect.any(Function));

    unsubscribeThreats();
    unsubscribeThreats();
    expect(removeSpy).not.toHaveBeenCalledWith("focus", expect.any(Function));

    unsubscribeEngineers();
    expect(removeSpy).toHaveBeenCalledWith("focus", expect.any(Function));
    expect(removeSpy).toHaveBeenCalledWith("online", expect.any(Function));
    expect(jest.getTimerCount()).toBe(0);

    window.dispatchEvent(new Event("focus"));
    await flushMicrotasks();
    expect(supabase.rpc).toHaveBeenCalledTimes(1);
  });
});

describe("useLandingCounter", () => {
  it("returns the formula value, then the server value after a sync", async () => {
    const nowMs = START_MS + HOUR_MS;
    freezeTimeAt(nowMs);
    supabase.rpc.mockResolvedValue({
      data: [buildRow("threats_blocked", nowMs, { value: 424242 })],
      error: null,
    });

    const { result, unmount } = renderHook(() =>
      useLandingCounter("threats_blocked"),
    );

    expect(result.current).toBeGreaterThanOrEqual(
      computeCounterValue(THREATS, nowMs),
    );

    await act(async () => {
      await syncLandingCounters();
    });

    expect(result.current).toBe(424242);

    unmount();
    expect(jest.getTimerCount()).toBe(0);
  });

  it("advances on the shared tick boundary", async () => {
    const nowMs = START_MS + 2 * HOUR_MS + 30 * 1000;
    freezeTimeAt(nowMs);

    const { result, unmount } = renderHook(() =>
      useLandingCounter("engineers_protected"),
    );
    await act(async () => {
      await flushMicrotasks();
    });

    const before = result.current;
    expect(before).toBe(computeCounterValue(ENGINEERS, nowMs));

    act(() => {
      jest.advanceTimersByTime(570 * 1000);
    });

    expect(result.current).toBe(before + 1);

    unmount();
  });

  it("returns 0 for an unknown counter key", () => {
    const { result } = renderHook(() => useLandingCounter("not_a_counter"));

    expect(result.current).toBe(0);
  });
});
