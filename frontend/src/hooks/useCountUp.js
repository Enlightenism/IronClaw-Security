import { useEffect, useRef, useState } from "react";

const easeOutQuad = (t) => t * (2 - t);

export function useCountUp(end, duration = 1400, deps = [], from = 0) {
  const [value, setValue] = useState(from);
  const frame = useRef();

  useEffect(() => {
    const target = Number(end) || 0;
    const start = Number(from) || 0;
    let startTime;

    const step = (ts) => {
      if (!startTime) startTime = ts;
      const progress = Math.min((ts - startTime) / duration, 1);
      setValue(Math.floor(start + (target - start) * easeOutQuad(progress)));
      if (progress < 1) {
        frame.current = requestAnimationFrame(step);
      } else {
        setValue(target);
      }
    };

    frame.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(frame.current);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [end, duration, from, ...deps]);

  return value;
}
