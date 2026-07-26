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
  describe("animation: from → end", () => {
    it("starts at `from` and resolves to `end` after full duration", () => {
      const { result } = renderHook(() => useCountUp(100, 1000, [], 0));

      expect(result.current).toBe(0);

      advance(500);
      const mid = result.current;

      expect(mid).toBeGreaterThan(0);
      expect(mid).toBeLessThan(100);

      advance(600);
      expect(result.current).toBe(100);
    });

    it("resolves exactly to `end` — never overshoots", () => {
      const { result } = renderHook(() => useCountUp(50, 500, [], 0));

      advance(600);
      expect(result.current).toBe(50);
    });

    it("uses Math.round so value is always an integer", () => {
      const { result } = renderHook(() => useCountUp(99, 1000, [], 0));

      advance(250);
      expect(Number.isInteger(result.current)).toBe(true);
    });

    it("handles non-integer `end` by coercing to number", () => {
      const { result } = renderHook(() => useCountUp("200", 500, [], 0));

      advance(600);
      expect(result.current).toBe(200);
    });

    it("handles NaN `end` by treating it as 0", () => {
      const { result } = renderHook(() => useCountUp(NaN, 500, [], 0));

      advance(600);
      expect(result.current).toBe(0);
    });
  });

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

  describe("end === from: no animation", () => {
    it("returns `end` synchronously and fires no rAF when values are equal", () => {
      const spy = jest.spyOn(window, "requestAnimationFrame");
      const { result } = renderHook(() => useCountUp(42, 1000, [], 42));

      expect(result.current).toBe(42);
      expect(spy).not.toHaveBeenCalled();
    });

    it("treats both as 0 when both are NaN — no rAF fired", () => {
      const spy = jest.spyOn(window, "requestAnimationFrame");

      renderHook(() => useCountUp(NaN, 1000, [], NaN));

      expect(spy).not.toHaveBeenCalled();
    });
  });

  describe("re-triggers when `end` changes", () => {
    it("restarts animation when `end` prop is updated", () => {
      const { result, rerender } = renderHook(
        ({ end }) => useCountUp(end, 500, [end], 0),
        { initialProps: { end: 50 } },
      );

      advance(600);
      expect(result.current).toBe(50);

      rerender({ end: 200 });

      expect(result.current).toBe(50);

      advance(300);
      const inProgress = result.current;
      expect(inProgress).toBeGreaterThan(50);
      expect(inProgress).toBeLessThan(200);

      advance(300);
      expect(result.current).toBe(200);
    });

    it("re-triggers when extra `deps` entry changes", () => {
      const { result, rerender } = renderHook(
        ({ trigger }) => useCountUp(100, 500, [trigger], 0),
        { initialProps: { trigger: 0 } },
      );

      advance(600);
      expect(result.current).toBe(100);

      rerender({ trigger: 1 });

      expect(result.current).toBe(100);

      advance(300);
      const inProgress = result.current;
      expect(inProgress).toBeGreaterThan(0);
      expect(inProgress).toBeLessThan(100);

      advance(300);
      expect(result.current).toBe(100);
    });
  });

  describe("cleanup on unmount", () => {
    it("calls cancelAnimationFrame when unmounted mid-animation", () => {
      const cafSpy = jest.spyOn(window, "cancelAnimationFrame");

      const { unmount } = renderHook(() => useCountUp(100, 2000, [], 0));

      advance(500);
      unmount();

      expect(cafSpy).toHaveBeenCalled();
    });

    it("does not throw when unmounted before first rAF fires", () => {
      const { unmount } = renderHook(() => useCountUp(100, 1000, [], 0));

      expect(() => unmount()).not.toThrow();
    });

    it("leaves no pending rAF callbacks after unmount", () => {
      const { unmount } = renderHook(() => useCountUp(200, 1000, [], 0));

      advance(16);
      unmount();

      expect(rafHandles.size).toBe(0);
    });
  });

  describe("edge cases", () => {
    it("animates from a positive `from` value correctly", () => {
      const { result } = renderHook(() => useCountUp(100, 500, [], 50));

      expect(result.current).toBe(50);

      advance(600);
      expect(result.current).toBe(100);
    });

    it("animates downward (end < from)", () => {
      const { result } = renderHook(() => useCountUp(0, 500, [], 100));

      expect(result.current).toBe(100);

      advance(600);
      expect(result.current).toBe(0);
    });

    it("defaults `from` to 0 when not provided", () => {
      const { result } = renderHook(() => useCountUp(80, 500));

      expect(result.current).toBe(0);

      advance(600);
      expect(result.current).toBe(80);
    });

    it("defaults `duration` to 1400 when not provided", () => {
      const { result } = renderHook(() => useCountUp(50));

      advance(700);

      const mid = result.current;
      expect(mid).toBeGreaterThan(0);
      expect(mid).toBeLessThan(50);
    });
  });
});
