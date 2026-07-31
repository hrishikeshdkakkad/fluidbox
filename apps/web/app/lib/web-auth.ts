// WorkOS web-tier authentication configuration (the decisions behind the
// FLUIDBOX_WEB_AUTH switch). Pure, side-effect-free, SDK-free — the same
// pattern as proxy-auth.ts / auth-gate.ts — so the fail-closed rules carry
// unit tests while proxy.ts / route handlers stay thin adapters.
//
// Two orthogonal switches govern the dashboard:
//
//   FLUIDBOX_WEB_MODE (proxy-auth.ts)  — which credential the server-side
//     proxy presents to the CONTROL PLANE: the operator token (admin) or the
//     fluidbox session cookie (sso).
//   FLUIDBOX_WEB_AUTH (this module)    — whether the WEB TIER itself requires
//     a WorkOS AuthKit session before /app/* and /api/fluidbox/* respond.
//
// `admin` + `workos` is the hosted single-tenant posture: WorkOS
// authenticates the human, the proxy still speaks operator token to the
// control plane. `sso` + `workos` is REFUSED: two session systems on one
// origin is a footgun — multi-user identity is fluidbox SSO, which can
// federate to WorkOS as a per-org OIDC IdP instead (see
// docs/plans/2026-07-30-public-site-and-auth-boundary-design.md §3).

import { isAppPath } from "./auth-gate";

export type WebAuthMode = "none" | "workos";

/** The web-tier auth mode, chosen ONLY by FLUIDBOX_WEB_AUTH.
 *
 *  ONLY an absent variable (undefined) stays "none" — the documented local
 *  default. "none" and "workos" select their modes. ANY OTHER value THROWS,
 *  INCLUDING a set-but-empty string: an explicitly blank env var is a
 *  misconfiguration, not the local default, so it fails loudly ("WORKOS",
 *  "work-os", "1") rather than silently serving an unprotected /app. */
export function webAuthMode(env: string | undefined): WebAuthMode {
  if (env === undefined) return "none";
  if (env === "none" || env === "workos") return env;
  throw new Error(
    `FLUIDBOX_WEB_AUTH must be "none" or "workos" (got ${JSON.stringify(env)})`
  );
}

/** sso + workos would run two independent session systems against one origin
 *  (fluidbox `__Host-fbx_web` and the AuthKit cookie), each with its own
 *  login, expiry, and logout. Refused at cold start — deliberately, per the
 *  design doc: WorkOS in a multi-user deployment belongs BEHIND fluidbox SSO
 *  as the per-org OIDC identity provider. */
export function assertAuthModeCompatible(
  webMode: "admin" | "sso",
  authMode: WebAuthMode
): void {
  if (webMode === "sso" && authMode === "workos") {
    throw new Error(
      "FLUIDBOX_WEB_MODE=sso and FLUIDBOX_WEB_AUTH=workos are mutually exclusive: " +
        "fluidbox SSO already authenticates the browser (configure WorkOS as the " +
        "organization's OIDC identity provider instead of a second web-tier gate)"
    );
  }
}

/** Everything AuthKit needs. All four must be present in workos mode. */
export const WORKOS_ENV_KEYS = [
  "WORKOS_API_KEY",
  "WORKOS_CLIENT_ID",
  "WORKOS_COOKIE_PASSWORD",
  "NEXT_PUBLIC_WORKOS_REDIRECT_URI",
] as const;

export interface WorkosPublicConfig {
  clientId: string;
  redirectUri: string;
}

/** Validate the WorkOS environment, failing CLOSED and LOUD: a workos
 *  deployment with incomplete configuration must take the app down at cold
 *  start, never silently serve an unprotected /app. Error messages name the
 *  missing VARIABLES, never their values. Returns only the non-secret subset
 *  callers may thread around. */
export function requireWorkosEnv(
  env: Record<string, string | undefined>
): WorkosPublicConfig {
  const missing = WORKOS_ENV_KEYS.filter((key) => !env[key]);
  if (missing.length > 0) {
    throw new Error(
      `FLUIDBOX_WEB_AUTH=workos requires ${missing.join(", ")} — ` +
        "refusing to start rather than serve an unprotected /app " +
        "(see apps/web/.env.example)"
    );
  }
  // iron-session's floor; a shorter password downgrades cookie sealing.
  if ((env.WORKOS_COOKIE_PASSWORD as string).length < 32) {
    throw new Error(
      "WORKOS_COOKIE_PASSWORD must be at least 32 characters (openssl rand -base64 24)"
    );
  }
  return {
    clientId: env.WORKOS_CLIENT_ID as string,
    redirectUri: env.NEXT_PUBLIC_WORKOS_REDIRECT_URI as string,
  };
}

export type WorkosGateDecision = "redirect-to-sign-in" | "pass";

/** The workos-mode navigation rule, applied AFTER the fluidbox gate: only
 *  /app/* demands a WorkOS user. Public routes pass untouched (the session
 *  still refreshes on them so a signed-in user stays signed in), and /api/*
 *  passes here because the API route answers 401 itself — a fetch must never
 *  be redirected to an IdP. */
export function workosGate(input: {
  pathname: string;
  hasUser: boolean;
}): WorkosGateDecision {
  if (input.pathname.startsWith("/api/")) return "pass";
  return isAppPath(input.pathname) && !input.hasUser ? "redirect-to-sign-in" : "pass";
}
