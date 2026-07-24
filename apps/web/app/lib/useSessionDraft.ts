"use client";

import { useCallback, useEffect, useRef } from "react";

/**
 * Keeps a non-secret form draft for the lifetime of this browser tab.
 *
 * Restoration happens after hydration so server markup remains deterministic.
 * Writes are debounced and never leave sessionStorage; callers explicitly clear
 * only after the server accepts the completed form.
 */
export function useSessionDraft<T>({
  key,
  value,
  onRestore,
  shouldPersist,
  delayMs = 250,
}: {
  key: string;
  value: T;
  onRestore: (draft: T) => void;
  shouldPersist: boolean;
  delayMs?: number;
}) {
  const ready = useRef(false);
  const restoreRef = useRef(onRestore);

  useEffect(() => {
    restoreRef.current = onRestore;
  }, [onRestore]);

  useEffect(() => {
    ready.current = false;
    let readyTimer: ReturnType<typeof setTimeout> | null = null;
    try {
      const saved = sessionStorage.getItem(key);
      if (saved) restoreRef.current(JSON.parse(saved) as T);
    } catch {
      // Storage can be unavailable or a previous draft may be malformed.
      try {
        sessionStorage.removeItem(key);
      } catch {
        // Storage itself is unavailable; the in-memory form still works.
      }
    }
    // Let state restored above render before new values are eligible to save.
    readyTimer = setTimeout(() => {
      ready.current = true;
    }, 0);
    return () => {
      if (readyTimer) clearTimeout(readyTimer);
    };
  }, [key]);

  useEffect(() => {
    if (!ready.current) return;
    const timer = setTimeout(() => {
      try {
        if (shouldPersist) sessionStorage.setItem(key, JSON.stringify(value));
        else sessionStorage.removeItem(key);
      } catch {
        // The form remains fully usable when storage is disabled or full.
      }
    }, delayMs);
    return () => clearTimeout(timer);
  }, [delayMs, key, shouldPersist, value]);

  return useCallback(() => {
    try {
      sessionStorage.removeItem(key);
    } catch {
      // Nothing else is required; successful server state is authoritative.
    }
  }, [key]);
}
