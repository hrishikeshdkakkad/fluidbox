"use client";

import { useEffect, useRef } from "react";

/**
 * Visibility-aware, non-overlapping polling.
 *
 * `setInterval` starts a second request even if the first is still in flight
 * and keeps doing work in background tabs. This loop schedules only after the
 * previous refresh settles, pauses while hidden, and refreshes immediately
 * when the user returns.
 */
export function useSmartPolling(
  refresh: () => void | Promise<void>,
  intervalMs: number,
  enabled = true
) {
  const refreshRef = useRef(refresh);

  useEffect(() => {
    refreshRef.current = refresh;
  }, [refresh]);

  useEffect(() => {
    if (!enabled) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let running = false;

    const schedule = (delay: number) => {
      if (timer) clearTimeout(timer);
      if (!stopped && document.visibilityState === "visible") {
        timer = setTimeout(run, delay);
      }
    };

    const run = async () => {
      if (stopped || running || document.visibilityState !== "visible") return;
      running = true;
      try {
        await refreshRef.current();
      } finally {
        running = false;
        schedule(intervalMs);
      }
    };

    const onVisibility = () => {
      if (document.visibilityState === "visible") schedule(0);
      else if (timer) clearTimeout(timer);
    };

    document.addEventListener("visibilitychange", onVisibility);
    schedule(0);
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      document.removeEventListener("visibilitychange", onVisibility);
    };
  }, [enabled, intervalMs]);
}
