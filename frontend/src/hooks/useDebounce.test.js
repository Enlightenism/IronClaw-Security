import { renderHook, act } from "@testing-library/react";
import { useDebounce } from "@/hooks/useDebounce";

// ---------------------------------------------------------------------------
// Fake-timer lifecycle
// ---------------------------------------------------------------------------
// jest.useFakeTimers replaces setTimeout/clearTimeout with synchronous Jest
// controls. This is the correct approach for debounce tests — no RAF mocking
// needed, unlike useCountUp which drives requestAnimationFrame.
// ---------------------------------------------------------------------------

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.runOnlyPendingTimers();
  jest.useRealTimers();
});

// ---------------------------------------------------------------------------
// useDebounce — test suite
// ---------------------------------------------------------------------------

describe("useDebounce", () => {
  // -------------------------------------------------------------------------
  // 1. Initial render
  // -------------------------------------------------------------------------
  describe("initial render", () => {
    it("returns the initial value immediately without waiting for the delay", () => {
      const { result } = renderHook(() => useDebounce("ironclaw", 400));

      expect(result.current).toBe("ironclaw");
    });

    it("returns undefined as the initial debounced value when value is undefined", () => {
      const { result } = renderHook(() => useDebounce(undefined, 400));

      expect(result.current).toBeUndefined();
    });
  });

  // -------------------------------------------------------------------------
  // 2. Delay behaviour — does NOT fire early
  // -------------------------------------------------------------------------
  describe("does not update before the delay has elapsed", () => {
    it("keeps the stale debounced value while the timer is still pending", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: "initial" } },
      );

      rerender({ value: "updated" });

      // Advance time to just before the delay fires.
      act(() => {
        jest.advanceTimersByTime(399);
      });

      expect(result.current).toBe("initial");
    });
  });

  // -------------------------------------------------------------------------
  // 3. Delay behaviour — DOES fire after delay
  // -------------------------------------------------------------------------
  describe("updates the debounced value after the full delay has elapsed", () => {
    it("resolves to the new value after exactly `delay` ms", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: "initial" } },
      );

      rerender({ value: "updated" });

      act(() => {
        jest.advanceTimersByTime(400);
      });

      expect(result.current).toBe("updated");
    });
  });

  // -------------------------------------------------------------------------
  // 4. Timer reset on rapid value changes
  // -------------------------------------------------------------------------
  describe("resets the timer when value changes before the delay fires", () => {
    it("only resolves to the last value when multiple changes occur within the delay window", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: "first" } },
      );

      // Rapid successive updates — each should reset the timer.
      rerender({ value: "second" });
      act(() => {
        jest.advanceTimersByTime(200);
      });

      rerender({ value: "third" });
      act(() => {
        jest.advanceTimersByTime(200);
      });

      // Still within the last timer window — should not have resolved yet.
      expect(result.current).toBe("first");

      // Now advance past the full delay since the last change.
      act(() => {
        jest.advanceTimersByTime(200);
      });

      expect(result.current).toBe("third");
    });

    it("skips intermediate values and only emits the final value", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 300),
        { initialProps: { value: "a" } },
      );

      rerender({ value: "b" });
      rerender({ value: "c" });
      rerender({ value: "d" });

      act(() => {
        jest.advanceTimersByTime(300);
      });

      expect(result.current).toBe("d");
    });
  });

  // -------------------------------------------------------------------------
  // 5. Delay prop changes
  // -------------------------------------------------------------------------
  describe("uses the updated delay when the delay prop changes", () => {
    it("applies the new delay when delay is reduced mid-flight", () => {
      const { result, rerender } = renderHook(
        ({ value, delay }) => useDebounce(value, delay),
        { initialProps: { value: "initial", delay: 600 } },
      );

      // Change both value and delay simultaneously.
      rerender({ value: "updated", delay: 200 });

      // Advance only 200ms (new shorter delay).
      act(() => {
        jest.advanceTimersByTime(200);
      });

      expect(result.current).toBe("updated");
    });

    it("applies the new delay when delay is increased mid-flight", () => {
      const { result, rerender } = renderHook(
        ({ value, delay }) => useDebounce(value, delay),
        { initialProps: { value: "initial", delay: 200 } },
      );

      rerender({ value: "updated", delay: 600 });

      // 200ms elapses — old delay would have fired but new delay hasn't yet.
      act(() => {
        jest.advanceTimersByTime(200);
      });

      expect(result.current).toBe("initial");

      // Now the full new delay elapses.
      act(() => {
        jest.advanceTimersByTime(400);
      });

      expect(result.current).toBe("updated");
    });
  });

  // -------------------------------------------------------------------------
  // 6. Unmount — no state update after removal, no memory leak
  // -------------------------------------------------------------------------
  describe("clears the timeout on unmount", () => {
    it("does not update state after the component unmounts", () => {
      const clearTimeoutSpy = jest.spyOn(global, "clearTimeout");

      const { rerender, unmount } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: "initial" } },
      );

      rerender({ value: "updated" });

      // Unmount before the timer fires.
      unmount();

      expect(clearTimeoutSpy).toHaveBeenCalled();

      // Advance past the delay — should not throw a React warning about
      // updating state on an unmounted component.
      act(() => {
        jest.advanceTimersByTime(400);
      });

      clearTimeoutSpy.mockRestore();
    });
  });

  // -------------------------------------------------------------------------
  // 7. delay = 0
  // -------------------------------------------------------------------------
  describe("handles delay = 0 correctly", () => {
    it("resolves on the next tick when delay is 0", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 0),
        { initialProps: { value: "initial" } },
      );

      rerender({ value: "immediate" });

      act(() => {
        jest.advanceTimersByTime(0);
      });

      expect(result.current).toBe("immediate");
    });
  });

  // -------------------------------------------------------------------------
  // 8. Non-string value types
  // -------------------------------------------------------------------------
  describe("works correctly with non-string value types", () => {
    it("debounces a number value", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: 0 } },
      );

      rerender({ value: 42 });

      act(() => {
        jest.advanceTimersByTime(400);
      });

      expect(result.current).toBe(42);
    });

    it("debounces a boolean value", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: false } },
      );

      rerender({ value: true });

      act(() => {
        jest.advanceTimersByTime(400);
      });

      expect(result.current).toBe(true);
    });

    it("debounces an object reference", () => {
      const objA = { threat: "low" };
      const objB = { threat: "critical" };

      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: objA } },
      );

      rerender({ value: objB });

      act(() => {
        jest.advanceTimersByTime(400);
      });

      expect(result.current).toBe(objB);
      expect(result.current.threat).toBe("critical");
    });

    it("debounces null correctly", () => {
      const { result, rerender } = renderHook(
        ({ value }) => useDebounce(value, 400),
        { initialProps: { value: "active" } },
      );

      rerender({ value: null });

      act(() => {
        jest.advanceTimersByTime(400);
      });

      expect(result.current).toBeNull();
    });
  });
});
