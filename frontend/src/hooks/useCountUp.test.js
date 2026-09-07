import { renderHook, act } from "@testing-library/react";
import { useCountUp } from "@/hooks/useCountUp";

let rafId = 0;
let rafHandles = new Map();

function setReducedMotion(value) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query) => ({
      matches: query === "(prefers-reduced-motion: reduce)" ? value : false,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    }),
  });
}

function installRafMock() {
  jest.spyOn(window, "requestAnimationFrame").mockImplementation((cb) => {
    rafId += 1;
    const id = rafId;

    const handle = setTimeout(() => {
      rafHandles.delete(id);
      cb(performance.now());
    }, 16);

    rafHandles.set(id, handle);
    return id;
  });

  jest.spyOn(window, "cancelAnimationFrame").mockImplementation((id) => {
    const handle = rafHandles.get(id);
    if (handle) {
      clearTimeout(handle);
      rafHandles.delete(id);
    }
  });
}

function advance(ms) {
  act(() => {
    jest.advanceTimersByTime(ms);
  });
}

beforeEach(() => {
  jest.useFakeTimers();
  rafId = 0;
  rafHandles = new Map();
  installRafMock();
  setReducedMotion(false);
});

afterEach(() => {
  rafHandles.forEach((handle) => clearTimeout(handle));
  rafHandles.clear();
  jest.restoreAllMocks();
  jest.useRealTimers();
});

describe("useCountUp", () => {
  it("starts at the provided starting value and resolves to the target without overshoot", () => {
    const { result } = renderHook(() => useCountUp(100, 1000, [], 0));

    expect(result.current).toBe(0);

    advance(500);
    expect(result.current).toBeGreaterThan(0);
    expect(result.current).toBeLessThan(100);

    advance(600);
    expect(result.current).toBe(100);
  });

  it("never moves backward when the target is monotonic upward", () => {
    const { result, rerender } = renderHook(
      ({ end }) => useCountUp(end, 500, [end], 0),
      { initialProps: { end: 10 } },
    );

    expect(result.current).toBe(0);

    rerender({ end: 50 });
    advance(100);
    expect(result.current).toBeGreaterThanOrEqual(10);
    expect(result.current).toBeLessThanOrEqual(50);

    advance(500);
    expect(result.current).toBe(50);
  });

  it("handles a slow incremental target change without jitter or backward drift", () => {
    const { result, rerender } = renderHook(
      ({ end }) => useCountUp(end, 800, [end], 0),
      { initialProps: { end: 12 } },
    );

    advance(900);
    expect(result.current).toBe(12);

    rerender({ end: 14 });
    advance(600);
    expect(result.current).toBeGreaterThan(12);
    expect(result.current).toBeLessThanOrEqual(14);

    advance(300);
    expect(result.current).toBe(14);
  });

  it("recomputes correctly when dependency-driven target updates arrive", () => {
    const { result, rerender } = renderHook(
      ({ end, deps }) => useCountUp(end, 600, deps, 0),
      { initialProps: { end: 12, deps: [12] } },
    );

    expect(result.current).toBe(0);

    rerender({ end: 18, deps: [18] });
    advance(700);
    expect(result.current).toBe(18);
  });

  it("holds the current display value when a stale lower target arrives", () => {
    const { result, rerender } = renderHook(
      ({ end }) => useCountUp(end, 500, [end], 0),
      { initialProps: { end: 100 } },
    );

    advance(600);
    expect(result.current).toBe(100);

    rerender({ end: 72 });
    expect(result.current).toBe(100);
  });

  it("never falls back to the starting value when the live target is already above it", () => {
    const { result, rerender } = renderHook(
      ({ end }) => useCountUp(end, 600, [end], 100),
      { initialProps: { end: 120 } },
    );

    advance(700);
    expect(result.current).toBe(120);

    rerender({ end: 110 });
    expect(result.current).toBe(120);
  });

  it("returns the target immediately when reduced motion is enabled", () => {
    setReducedMotion(true);
    const spy = jest.spyOn(window, "requestAnimationFrame");

    const { result } = renderHook(() => useCountUp(75, 1000, [], 0));

    expect(result.current).toBe(75);
    expect(spy).not.toHaveBeenCalled();
  });

  it("treats NaN and equal values as stable targets without scheduling animation", () => {
    const spy = jest.spyOn(window, "requestAnimationFrame");

    const { result: equalResult } = renderHook(() =>
      useCountUp(42, 1000, [], 42),
    );
    expect(equalResult.current).toBe(42);
    expect(spy).not.toHaveBeenCalled();

    const { result: nanResult } = renderHook(() =>
      useCountUp(NaN, 1000, [], NaN),
    );
    expect(nanResult.current).toBe(0);
    expect(spy).not.toHaveBeenCalled();
  });

  it("cleans up any active animation frame on unmount", () => {
    const cafSpy = jest.spyOn(window, "cancelAnimationFrame");

    const { unmount } = renderHook(() => useCountUp(100, 2000, [], 0));
    advance(500);
    unmount();

    expect(cafSpy).toHaveBeenCalled();
  });

  it("defaults to the correct deterministic behavior when no from value is supplied", () => {
    const { result } = renderHook(() => useCountUp(80, 500));

    expect(result.current).toBe(0);

    advance(600);
    expect(result.current).toBe(80);
  });
});
