"use client";

import { useEffect, useState } from "react";

// Remounts its children on a slow interval so their CSS entrance animations
// replay — the hero ledger reads as a living run, not a finished screenshot.
// The children are server-rendered and static; only the key changes here.
// Reduced-motion users get one static render (the rows' own animations are
// also disabled in CSS).
export function ReplayLoop({
  children,
  periodMs = 16000,
}: {
  children: React.ReactNode;
  periodMs?: number;
}) {
  const [cycle, setCycle] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const id = setInterval(() => setCycle((c) => c + 1), periodMs);
    return () => clearInterval(id);
  }, [periodMs]);
  return <div key={cycle}>{children}</div>;
}
