import { useEffect, useMemo, useRef, useState } from "react";

const easeOutQuad = (t) => t * (2 - t);

const clampMonotonicTarget = (current, nextTarget) => {
  if (!Number.isFinite(nextTarget)) {
    return current;
  }

  return Math.max(current, nextTarget);
};

/**
 * Animates only the visible number toward a live target.
 * This hook is display-only and never owns or resets canonical counter state.
 */
export function useCountUp(end, duration = 1400, deps = [], from = 0) {
  const target = Number.isFinite(Number(end)) ? Number(end) : 0;
  const start = Number.isFinite(Number(from)) ? Number(from) : 0;
  const dependencyKey = useMemo(() => {
    if (!Array.isArray(deps)) {
      return "";
    }

    return deps
      .map((dep) => {
        if (dep === null || dep === undefined) {
          return String(dep);
        }

        if (typeof dep === "object") {
          try {
            return JSON.stringify(dep);
          } catch {
            return Object.prototype.toString.call(dep);
          }
        }

        return String(dep);
      })
      .join("::");
  }, [deps]);

  const prefersReduced =
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const [value, setValue] = useState(prefersReduced ? target : start);
  const frame = useRef(null);
  const lastValueRef = useRef(prefersReduced ? target : start);
  const previousDepsRef = useRef(dependencyKey);

  useEffect(() => {
    const depKey = dependencyKey;
    const depsChanged = depKey !== previousDepsRef.current;

    const current = Number.isFinite(lastValueRef.current)
      ? lastValueRef.current
      : start;
    const nextTarget = Number.isFinite(target) ? target : start;
    const safeTarget = clampMonotonicTarget(current, nextTarget);

    if (depsChanged) {
      lastValueRef.current = current;
    }

    if (
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      setValue(safeTarget);
      lastValueRef.current = safeTarget;
      previousDepsRef.current = depKey;
      return undefined;
    }

    if (safeTarget <= current) {
      setValue(current);
      lastValueRef.current = current;
      previousDepsRef.current = depKey;
      return undefined;
    }

    if (frame.current != null) {
      cancelAnimationFrame(frame.current);
      frame.current = null;
    }

    let startTime;
    const animationStart = current;

    const step = (ts) => {
      if (startTime == null) {
        startTime = ts;
      }

      const progress = Math.min((ts - startTime) / duration, 1);
      const nextValue = Math.round(
        animationStart + (safeTarget - animationStart) * easeOutQuad(progress),
      );
      const clampedValue = Math.min(
        Math.max(nextValue, animationStart),
        safeTarget,
      );

      setValue(clampedValue);
      lastValueRef.current = clampedValue;

      if (progress < 1) {
        frame.current = requestAnimationFrame(step);
      } else {
        setValue(safeTarget);
        lastValueRef.current = safeTarget;
      }
    };

    frame.current = requestAnimationFrame(step);
    previousDepsRef.current = depKey;

    return () => {
      if (frame.current != null) {
        cancelAnimationFrame(frame.current);
        frame.current = null;
      }
    };
  }, [end, duration, from, target, start, dependencyKey, prefersReduced]);

  return value;
}
