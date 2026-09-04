import { useEffect, useRef, useState } from "react";

const easeOutQuad = (t) => t * (2 - t);

/**
 * Animates a numeric value from `from` to `end` over `duration` ms.
 * Respects prefers-reduced-motion: returns `end` immediately when motion is reduced.
 *
 * @param {number} end       - Target value
 * @param {number} duration  - Animation duration in ms (default 1400)
 * @param {Array}  deps      - Extra dependency array entries that retrigger the animation
 * @param {number} from      - Starting value (default 0)
 * @returns {number} Current animated value
 */
export function useCountUp(end, duration = 1400, deps = [], from = 0) {
  const target = Number(end) || 0;
  const start = Number(from) || 0;

  const prefersReduced =
    typeof window !== "undefined" &&
    window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  const [value, setValue] = useState(prefersReduced ? target : start);
  const frame = useRef();
  const lastValueRef = useRef(prefersReduced ? target : start);
  const previousDepsRef = useRef(deps);

  useEffect(() => {
    const depsChanged =
      deps.length !== previousDepsRef.current.length ||
      deps.some((dep, index) => dep !== previousDepsRef.current[index]);

    if (depsChanged) {
      lastValueRef.current = start;
    }

    const current = Number(lastValueRef.current) || 0;
    const boundedTarget = Number.isFinite(target) ? target : current;

    if (
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      setValue(boundedTarget);
      lastValueRef.current = boundedTarget;
      previousDepsRef.current = deps;
      return;
    }

    if (boundedTarget === current) {
      setValue(current);
      lastValueRef.current = current;
      previousDepsRef.current = deps;
      return;
    }

    let startTime;
    const animationStart = current;

    const step = (ts) => {
      if (!startTime) startTime = ts;
      const progress = Math.min((ts - startTime) / duration, 1);
      const nextValue = Math.round(
        animationStart +
          (boundedTarget - animationStart) * easeOutQuad(progress),
      );

      if (boundedTarget >= animationStart) {
        setValue(Math.min(nextValue, boundedTarget));
      } else {
        setValue(Math.max(nextValue, boundedTarget));
      }

      if (progress < 1) {
        frame.current = requestAnimationFrame(step);
      } else {
        setValue(boundedTarget);
        lastValueRef.current = boundedTarget;
      }
    };

    frame.current = requestAnimationFrame(step);
    previousDepsRef.current = deps;
    return () => cancelAnimationFrame(frame.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [end, duration, from, ...deps]);

  return value;
}
