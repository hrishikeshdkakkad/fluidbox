"use client";

// The supported harness + model catalog, fetched from the control plane
// (GET /harnesses) — the SINGLE source of truth. The frontend no longer
// hardcodes model lists; a mismatched model is caught server-side with a
// clean 422 at agent-write time.

import { useCallback, useEffect, useState } from "react";
import { apiGetCached, DeploymentNetwork, HarnessInfo } from "./api";

export interface HarnessCatalog {
  harnesses: HarnessInfo[];
  /** The deployment's resolved network posture, or null when an older server
   *  omits the field (or the catalog failed to load). Callers treat null as
   *  "unknown" and must NOT gate on it — that keeps today's behaviour. */
  network: DeploymentNetwork | null;
  loading: boolean;
  error: string;
  reload: () => void;
}

export function useHarnesses(): HarnessCatalog {
  const [harnesses, setHarnesses] = useState<HarnessInfo[]>([]);
  const [network, setNetwork] = useState<DeploymentNetwork | null>(null);
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
    apiGetCached<{ harnesses: HarnessInfo[]; network?: DeploymentNetwork | null }>(
      "/harnesses",
      { maxAgeMs: 5 * 60_000, force: request > 0 }
    )
      .then((response) => {
        if (active) {
          setHarnesses(response.harnesses);
          // Absent on an older server → null, so the dashboard does not gate.
          setNetwork(response.network ?? null);
        }
      })
      .catch((reason) => {
        if (active) {
          setHarnesses([]);
          setNetwork(null);
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

  return { harnesses, network, loading, error, reload };
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
