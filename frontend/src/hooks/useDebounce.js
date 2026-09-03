import { useEffect, useRef, useState } from "react";

/**
 * Returns a debounced copy of `value` that only updates after `delay` ms
 * of inactivity. Useful for delaying API calls triggered by user input
 * (e.g. email validation, search queries) without blocking the UI.
 *
 * - Clears the pending timer on every new value change.
 * - Clears the pending timer on unmount to prevent memory leaks and
 *   stale-closure state updates on unmounted components.
 * - Delay of 0 is valid and passes the value through on the next tick.
 *
 * @param {*}      value - The value to debounce (any type).
 * @param {number} delay - Debounce delay in milliseconds. Default is 0 so
 * input-driven behavior stays instant unless a caller explicitly requests a
 * delay.
 * @returns {*} The debounced value.
 */
export function useDebounce(value, delay = 0) {
  const [debouncedValue, setDebouncedValue] = useState(value);
  const timerRef = useRef(null);

  useEffect(() => {
    timerRef.current = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(timerRef.current);
    };
  }, [value, delay]);

  // Flush on unmount: ensure no pending timer fires after the component
  // is removed from the tree.
  useEffect(() => {
    return () => {
      clearTimeout(timerRef.current);
    };
  }, []);

  return debouncedValue;
}
