import { useSyncExternalStore } from "react";
import { supabase } from "@/lib/supabase";

const SYNC_INTERVAL_MS = 5 * 60 * 1000;
const SYNC_TIMEOUT_MS = 10 * 1000;
const STORAGE_PREFIX = "ironclaw:landing-counter-min:";
const UINT32_MAX = 0xffffffff;

// Must match the seed rows in 011_landing_page_counters.sql.
const SEED_ANCHOR_AT_MS = Date.UTC(2026, 9, 13, 6, 0, 0);

export const LANDING_COUNTER_FALLBACKS = Object.freeze({
  threats_blocked: Object.freeze({
    anchorValue: 732,
    anchorAtMs: SEED_ANCHOR_AT_MS,
    tickMs: 600 * 1000,
    stepMin: 2,
    stepMax: 3,
    seed: 1736102489,
  }),
  engineers_protected: Object.freeze({
    anchorValue: 344,
    anchorAtMs: SEED_ANCHOR_AT_MS,
    tickMs: 600 * 1000,
    stepMin: 1,
    stepMax: 1,
    seed: 2406839077,
  }),
});

const hasFallback = (counterKey) =>
  typeof counterKey === "string" &&
  Object.prototype.hasOwnProperty.call(LANDING_COUNTER_FALLBACKS, counterKey);

/**
 * 32-bit integer hash. Mirrors public.landing_counter_hash32 in SQL exactly:
 * every intermediate value is kept as an unsigned 32-bit integer.
 */
export const hash32 = (seed, tick) => {
  let h = (Math.imul(tick >>> 0, 0x9e3779b1) + seed) >>> 0;
  h = (h ^ (h >>> 16)) >>> 0;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h = (h ^ (h >>> 13)) >>> 0;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
};

/**
 * Mirrors public.landing_counter_compute. Ticks use the absolute index
 * floor(epochMs / tickMs); the anchor value already includes its own tick.
 */
export const computeCounterValue = (config, nowMs) => {
  const { anchorValue, anchorAtMs, tickMs, stepMin, stepMax, seed } = config;

  if (!Number.isFinite(nowMs)) {
    return anchorValue;
  }

  const firstTick = Math.floor(anchorAtMs / tickMs) + 1;
  const lastTick = Math.floor(nowMs / tickMs);
  const span = stepMax - stepMin + 1;
  let value = anchorValue;

  for (let tick = firstTick; tick <= lastTick; tick += 1) {
    value += stepMin + (hash32(seed, tick) % span);
  }

  return value;
};

const toNumber = (raw) =>
  raw === null || raw === undefined || raw === "" ? Number.NaN : Number(raw);

const isNonNegativeInteger = (value) => Number.isInteger(value) && value >= 0;

const parseCounterRow = (row) => {
  if (!row || typeof row !== "object" || !hasFallback(row.counter_key)) {
    return null;
  }

  const value = toNumber(row.value);
  const anchorValue = toNumber(row.anchor_value);
  const tickSeconds = toNumber(row.tick_seconds);
  const stepMin = toNumber(row.step_min);
  const stepMax = toNumber(row.step_max);
  const seed = toNumber(row.seed);
  const anchorAtMs = Date.parse(row.anchor_at);
  const serverMs = Date.parse(row.server_time);

  const valid =
    isNonNegativeInteger(value) &&
    isNonNegativeInteger(anchorValue) &&
    Number.isInteger(tickSeconds) &&
    tickSeconds > 0 &&
    isNonNegativeInteger(stepMin) &&
    Number.isInteger(stepMax) &&
    stepMax >= stepMin &&
    isNonNegativeInteger(seed) &&
    seed <= UINT32_MAX &&
    Number.isFinite(anchorAtMs) &&
    Number.isFinite(serverMs);

  if (!valid) {
    return null;
  }

  return {
    counterKey: row.counter_key,
    value,
    serverMs,
    config: {
      anchorValue,
      anchorAtMs,
      tickMs: tickSeconds * 1000,
      stepMin,
      stepMax,
      seed,
    },
  };
};

const readPersistedMinimum = (counterKey) => {
  try {
    const value = toNumber(
      window.localStorage.getItem(`${STORAGE_PREFIX}${counterKey}`),
    );
    return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
  } catch {
    return 0;
  }
};

const writePersistedMinimum = (counterKey, value) => {
  try {
    window.localStorage.setItem(
      `${STORAGE_PREFIX}${counterKey}`,
      String(value),
    );
  } catch {
    // Storage may be unavailable (private mode, quota); formula still works.
  }
};

const stores = new Map();
let clockOffsetMs = 0;
let runtimeSubscribers = 0;
let syncIntervalId = null;
let syncInFlight = null;

const deviceNowMs = () => Date.now() + clockOffsetMs;

const createStore = (counterKey) => {
  const listeners = new Set();
  let config = LANDING_COUNTER_FALLBACKS[counterKey];
  let timerId = null;
  let value = Math.max(
    readPersistedMinimum(counterKey),
    computeCounterValue(config, deviceNowMs()),
  );

  writePersistedMinimum(counterKey, value);

  const commit = (candidate) => {
    if (!Number.isFinite(candidate) || candidate <= value) {
      return;
    }

    value = candidate;
    writePersistedMinimum(counterKey, value);
    listeners.forEach((listener) => listener());
  };

  const refresh = () => commit(computeCounterValue(config, deviceNowMs()));

  const clearTick = () => {
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
  };

  const scheduleTick = () => {
    clearTick();
    const delay = Math.max(1, config.tickMs - (deviceNowMs() % config.tickMs));
    timerId = setTimeout(() => {
      timerId = null;
      refresh();
      if (listeners.size > 0) {
        scheduleTick();
      }
    }, delay);
  };

  const resume = () => {
    refresh();
    if (listeners.size > 0) {
      scheduleTick();
    }
  };

  return {
    getSnapshot: () => value,
    subscribe: (listener) => {
      if (listeners.size === 0) {
        refresh();
      }

      listeners.add(listener);

      if (listeners.size === 1) {
        scheduleTick();
        startRuntime();
      }

      return () => {
        if (!listeners.delete(listener)) {
          return;
        }

        if (listeners.size === 0) {
          clearTick();
          stopRuntime();
        }
      };
    },
    applyServerState: (next) => {
      config = next.config;
      commit(next.value);
      resume();
    },
    resume,
    destroy: () => {
      listeners.clear();
      clearTick();
    },
  };
};

const EMPTY_STORE = Object.freeze({
  getSnapshot: () => 0,
  subscribe: () => () => undefined,
});

export const getLandingCounterStore = (counterKey) => {
  if (!hasFallback(counterKey)) {
    return EMPTY_STORE;
  }

  if (!stores.has(counterKey)) {
    stores.set(counterKey, createStore(counterKey));
  }

  return stores.get(counterKey);
};

const fetchCounterRows = async () => {
  let timeoutId = null;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(
      () => reject(new Error("get_landing_counters timed out")),
      SYNC_TIMEOUT_MS,
    );
  });

  try {
    const sentAt = Date.now();
    const { data, error } = await Promise.race([
      supabase.rpc("get_landing_counters"),
      timeout,
    ]);

    if (error) {
      throw error;
    }

    return {
      rows: Array.isArray(data) ? data : [],
      midpointMs: (sentAt + Date.now()) / 2,
    };
  } finally {
    clearTimeout(timeoutId);
  }
};

const applyCounterRows = ({ rows, midpointMs }) => {
  const parsed = rows.map(parseCounterRow).filter(Boolean);

  if (parsed.length === 0) {
    return false;
  }

  clockOffsetMs = parsed[0].serverMs - midpointMs;

  parsed.forEach((state) => {
    getLandingCounterStore(state.counterKey).applyServerState(state);
  });

  return true;
};

/** Resolves true when server state was applied. Never rejects. */
export const syncLandingCounters = () => {
  if (!syncInFlight) {
    syncInFlight = fetchCounterRows()
      .then(applyCounterRows)
      .catch(() => false)
      .finally(() => {
        syncInFlight = null;
      });
  }

  return syncInFlight;
};

const resumeStores = () => {
  stores.forEach((store) => store.resume());
};

const handleResume = () => {
  resumeStores();
  syncLandingCounters();
};

const handleVisibilityChange = () => {
  if (document.visibilityState === "visible") {
    handleResume();
  }
};

function startRuntime() {
  runtimeSubscribers += 1;

  if (runtimeSubscribers !== 1 || typeof window === "undefined") {
    return;
  }

  window.addEventListener("focus", handleResume);
  window.addEventListener("online", handleResume);
  document.addEventListener("visibilitychange", handleVisibilityChange);
  syncIntervalId = setInterval(syncLandingCounters, SYNC_INTERVAL_MS);
  syncLandingCounters();
}

function stopRuntime() {
  runtimeSubscribers = Math.max(0, runtimeSubscribers - 1);

  if (runtimeSubscribers !== 0 || typeof window === "undefined") {
    return;
  }

  window.removeEventListener("focus", handleResume);
  window.removeEventListener("online", handleResume);
  document.removeEventListener("visibilitychange", handleVisibilityChange);

  if (syncIntervalId !== null) {
    clearInterval(syncIntervalId);
    syncIntervalId = null;
  }
}

/** Clears all module state. Intended for tests only. */
export const resetLandingCounters = () => {
  stores.forEach((store) => store.destroy());
  stores.clear();

  if (typeof window !== "undefined") {
    window.removeEventListener("focus", handleResume);
    window.removeEventListener("online", handleResume);
    document.removeEventListener("visibilitychange", handleVisibilityChange);
  }

  if (syncIntervalId !== null) {
    clearInterval(syncIntervalId);
    syncIntervalId = null;
  }

  runtimeSubscribers = 0;
  clockOffsetMs = 0;
  syncInFlight = null;
};

export function useLandingCounter(counterKey) {
  const store = getLandingCounterStore(counterKey);
  return useSyncExternalStore(
    store.subscribe,
    store.getSnapshot,
    store.getSnapshot,
  );
}
