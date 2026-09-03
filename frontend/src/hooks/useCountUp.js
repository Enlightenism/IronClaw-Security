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

  useEffect(() => {
    const current = Number(lastValueRef.current) || 0;
    const boundedTarget = Number.isFinite(target)
      ? Math.max(target, current)
      : current;

    if (
      typeof window !== "undefined" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches
    ) {
      setValue(boundedTarget);
      lastValueRef.current = boundedTarget;
      return;
    }

    if (boundedTarget === current) {
      setValue(current);
      lastValueRef.current = current;
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
      setValue(Math.min(nextValue, boundedTarget));
      if (progress < 1) {
        frame.current = requestAnimationFrame(step);
      } else {
        setValue(boundedTarget);
        lastValueRef.current = boundedTarget;
      }
    };

    frame.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [end, duration, from, ...deps]);

  return value;
}
