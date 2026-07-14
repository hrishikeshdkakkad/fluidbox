"use client";

// The supported harness + model catalog, fetched from the control plane
// (GET /harnesses) — the SINGLE source of truth. The frontend no longer
// hardcodes model lists; a mismatched model is caught server-side with a
// clean 422 at agent-write time.

import { useCallback, useEffect, useState } from "react";
import { apiGet, HarnessInfo } from "./api";

export interface HarnessCatalog {
  harnesses: HarnessInfo[];
  loading: boolean;
  error: string;
  reload: () => void;
}

export function useHarnesses(): HarnessCatalog {
  const [harnesses, setHarnesses] = useState<HarnessInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [request, setRequest] = useState(0);

  const reload = useCallback(() => {
    setLoading(true);
    setError("");
    setRequest((current) => current + 1);
  }, []);

  useEffect(() => {
    let active = true;
    apiGet<{ harnesses: HarnessInfo[] }>("/harnesses")
      .then((response) => {
        if (active) setHarnesses(response.harnesses);
      })
      .catch((reason) => {
        if (active) {
          setHarnesses([]);
          setError(`Runtime catalog unavailable. ${String(reason)}`);
        }
      })
      .finally(() => {
        if (active) setLoading(false);
      });
    return () => {
      active = false;
    };
  }, [request]);

  return { harnesses, loading, error, reload };
}

/** The models offered for a harness id (empty if unknown/not loaded). */
export function modelsFor(harnesses: HarnessInfo[], id: string): HarnessInfo["models"] {
  return harnesses.find((h) => h.id === id)?.models ?? [];
}

/** The default model for a harness id (first model as a fallback). */
export function defaultModelFor(harnesses: HarnessInfo[], id: string): string {
  const h = harnesses.find((x) => x.id === id);
  return h?.default_model ?? h?.models[0]?.id ?? "";
}
