"use client";

// The supported harness + model catalog, fetched from the control plane
// (GET /harnesses) — the SINGLE source of truth. The frontend no longer
// hardcodes model lists; a mismatched model is caught server-side with a
// clean 422 at agent-write time.

import { useEffect, useState } from "react";
import { apiGet, HarnessInfo } from "./api";

export function useHarnesses(): HarnessInfo[] {
  const [harnesses, setHarnesses] = useState<HarnessInfo[]>([]);
  useEffect(() => {
    apiGet<{ harnesses: HarnessInfo[] }>("/harnesses")
      .then((r) => setHarnesses(r.harnesses))
      .catch(() => {
        /* leave empty; the pickers render nothing until it loads */
      });
  }, []);
  return harnesses;
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
