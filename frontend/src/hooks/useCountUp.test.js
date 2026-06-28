import { renderHook, act } from "@testing-library/react";
import { useCountUp } from "@/hooks/useCountUp";

// ---------------------------------------------------------------------------
// rAF / cAF mock — runs callbacks synchronously so fake timers can drive them
// ---------------------------------------------------------------------------
let rafCallbacks = [];
let rafId = 0;

function mockRaf(cb) {
  rafId += 1;
  rafCallbacks.push({ id: rafId, cb });
  return rafId;
}

function mockCaf(id) {
  rafCallbacks = rafCallbacks.filter((entry) => entry.id !== id);
}

function flushRaf(timestamp) {
  const pending = [...rafCallbacks];
  rafCallbacks = [];
  pending.forEach(({ cb }) => cb(timestamp));
}

// ---------------------------------------------------------------------------
// prefers-reduced-motion helper
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Setup / teardown
// ---------------------------------------------------------------------------
beforeEach(() => {
  rafCallbacks = [];
  rafId = 0;
  jest.spyOn(window, "requestAnimationFrame").mockImplementation(mockRaf);
  jest.spyOn(window, "cancelAnimationFrame").mockImplementation(mockCaf);
  setReducedMotion(false);
});

afterEach(() => {
  jest.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------
describe("useCountUp", () => {
  // -------------------------------------------------------------------------
  // (1) Animates from `from` to `end` and resolves to `end` after duration
  // -------------------------------------------------------------------------
  describe("animation: from → end", () => {
    it("starts at `from` and resolves to `end` after full duration", () => {
      const { result } = renderHook(() => useCountUp(100, 1000, [], 0));

      // Initial value is `from` (0)
      expect(result.current).toBe(0);

      // Simulate frames progressing to 50 % of duration
      act(() => flushRaf(0));
      act(() => flushRaf(500));
      const mid = result.current;
      expect(mid).toBeGreaterThan(0);
      expect(mid).toBeLessThan(100);

      // Simulate reaching full duration
      act(() => flushRaf(1000));
      expect(result.current).toBe(100);
    });

    it("resolves exactly to `end` — never overshoots", () => {
      const { result } = renderHook(() => useCountUp(50, 500, [], 0));
      act(() => flushRaf(0));
      act(() => flushRaf(600)); // past duration
      expect(result.current).toBe(50);
    });

    it("uses Math.round so value is always an integer", () => {
      const { result } = renderHook(() => useCountUp(99, 1000, [], 0));
      act(() => flushRaf(0));
      act(() => flushRaf(250));
      expect(Number.isInteger(result.current)).toBe(true);
    });

    it("handles non-integer `end` by coercing to number", () => {
      const { result } = renderHook(() => useCountUp("200", 500, [], 0));
      act(() => flushRaf(0));
      act(() => flushRaf(600));
      expect(result.current).toBe(200);
    });

    it("handles NaN `end` by treating it as 0", () => {
      const { result } = renderHook(() => useCountUp(NaN, 500, [], 0));
      act(() => flushRaf(0));
      act(() => flushRaf(600));
      expect(result.current).toBe(0);
    });
  });

  // -------------------------------------------------------------------------
  // (2) Returns `end` immediately when prefers-reduced-motion: reduce
  // -------------------------------------------------------------------------
  describe("prefers-reduced-motion: reduce", () => {
    it("returns `end` on first render without scheduling any rAF", () => {
      setReducedMotion(true);
      const spy = jest.spyOn(window, "requestAnimationFrame");

      const { result } = renderHook(() => useCountUp(75, 1000, [], 0));

      expect(result.current).toBe(75);
      expect(spy).not.toHaveBeenCalled();
    });

    it("returns `end` immediately even when `from` differs", () => {
      setReducedMotion(true);
      const { result } = renderHook(() => useCountUp(500, 2000, [], 100));
      expect(result.current).toBe(500);
    });
  });

  // -------------------------------------------------------------------------
  // (3) Returns `end` immediately when end === from — no rAF fired
  // -------------------------------------------------------------------------
  describe("end === from: no animation", () => {
    it("returns `end` synchronously and fires no rAF when values are equal", () => {
      const spy = jest.spyOn(window, "requestAnimationFrame");
      const { result } = renderHook(() => useCountUp(42, 1000, [], 42));

      // useEffect runs after render; flush it
      act(() => {});

      expect(result.current).toBe(42);
      expect(spy).not.toHaveBeenCalled();
    });

    it("treats both as 0 when both are NaN — no rAF fired", () => {
      const spy = jest.spyOn(window, "requestAnimationFrame");
      renderHook(() => useCountUp(NaN, 1000, [], NaN));
      act(() => {});
      expect(spy).not.toHaveBeenCalled();
    });
  });

  // -------------------------------------------------------------------------
  // (4) Re-triggers animation when `end` changes
  // -------------------------------------------------------------------------
  describe("re-triggers when `end` changes", () => {
    it("restarts animation when `end` prop is updated", () => {
      const { result, rerender } = renderHook(
        ({ end }) => useCountUp(end, 500, [end], 0),
        { initialProps: { end: 50 } },
      );

      // Complete first animation
      act(() => flushRaf(0));
      act(() => flushRaf(600));
      expect(result.current).toBe(50);

      // Update `end` — animation must restart
      rerender({ end: 200 });
      act(() => flushRaf(0));
      act(() => flushRaf(300));
      const inProgress = result.current;
      expect(inProgress).toBeGreaterThan(50);
      expect(inProgress).toBeLessThan(200);

      act(() => flushRaf(600));
      expect(result.current).toBe(200);
    });

    it("re-triggers when extra `deps` entry changes", () => {
      let trigger = 0;
      const { result, rerender } = renderHook(
        () => useCountUp(100, 500, [trigger], 0),
        { initialProps: {} },
      );

      act(() => flushRaf(0));
      act(() => flushRaf(600));
      expect(result.current).toBe(100);

      // Mutate dep — should relaunch animation from 0
      trigger = 1;
      rerender({});
      act(() => flushRaf(0));
      act(() => flushRaf(300));
      expect(result.current).toBeGreaterThan(0);
      expect(result.current).toBeLessThan(100);
    });
  });

  // -------------------------------------------------------------------------
  // (5) Cleans up cancelAnimationFrame on unmount
  // -------------------------------------------------------------------------
  describe("cleanup on unmount", () => {
    it("calls cancelAnimationFrame when unmounted mid-animation", () => {
      const cafSpy = jest.spyOn(window, "cancelAnimationFrame");

      const { unmount } = renderHook(() => useCountUp(100, 2000, [], 0));
      act(() => flushRaf(0)); // kick off first frame
      act(() => flushRaf(500)); // mid-animation

      unmount();

      expect(cafSpy).toHaveBeenCalled();
    });

    it("does not throw when unmounted before first rAF fires", () => {
      const { unmount } = renderHook(() => useCountUp(100, 1000, [], 0));
      expect(() => unmount()).not.toThrow();
    });

    it("leaves no pending rAF callbacks after unmount", () => {
      const { unmount } = renderHook(() => useCountUp(200, 1000, [], 0));
      act(() => flushRaf(0));
      unmount();
      expect(rafCallbacks).toHaveLength(0);
    });
  });

  // -------------------------------------------------------------------------
  // Edge cases
  // -------------------------------------------------------------------------
  describe("edge cases", () => {
    it("animates from a positive `from` value correctly", () => {
      const { result } = renderHook(() => useCountUp(100, 500, [], 50));
      act(() => flushRaf(0));
      act(() => flushRaf(600));
      expect(result.current).toBe(100);
    });

    it("animates downward (end < from)", () => {
      const { result } = renderHook(() => useCountUp(0, 500, [], 100));
      act(() => flushRaf(0));
      act(() => flushRaf(600));
      expect(result.current).toBe(0);
    });

    it("defaults `from` to 0 when not provided", () => {
      const { result } = renderHook(() => useCountUp(80, 500));
      expect(result.current).toBe(0);
      act(() => flushRaf(0));
      act(() => flushRaf(600));
      expect(result.current).toBe(80);
    });

    it("defaults `duration` to 1400 when not provided", () => {
      const { result } = renderHook(() => useCountUp(50));
      act(() => flushRaf(0));
      act(() => flushRaf(700)); // half of 1400
      const mid = result.current;
      expect(mid).toBeGreaterThan(0);
      expect(mid).toBeLessThan(50);
    });
  });
});
