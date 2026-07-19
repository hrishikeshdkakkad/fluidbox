"use client";

import { useEffect, useState } from "react";
import { apiGet, AuthMe } from "./api";

/**
 * Fetch GET /auth/me once for ownership rendering (badges, owner pickers).
 * Presentation only — the server owner-filters and re-checks every write.
 *
 * Degrades gracefully in every mode: admin mode returns `{ operator: true }`
 * (no user_id/roles → org/personal without "yours", and the org owner option);
 * a missing/expired sso session 401s (api.ts routes to /login) and this stays
 * null; any other error also leaves it null. Callers must treat null as
 * "identity unknown", never as an authority signal.
 */
export function useAuthMe(): AuthMe | null {
  const [me, setMe] = useState<AuthMe | null>(null);
  useEffect(() => {
    let alive = true;
    apiGet<AuthMe>("/auth/me")
      .then((m) => {
        if (alive) setMe(m);
      })
      .catch(() => {
        // 401 already routed to /login (api.ts); other errors leave me null.
      });
    return () => {
      alive = false;
    };
  }, []);
  return me;
}
