import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server bundle for the Docker image (deploy/web.Dockerfile).
  output: "standalone",
  // Product reviews happen against the local dev stack; keep the workspace
  // free of framework chrome while still surfacing compile/runtime errors.
  devIndicators: false,
  // Two generations of moves, kept working forever (bookmarks, muscle memory):
  //   2026-07    IA consolidation (approvals/policies/connections/triggers).
  //   2026-07-30 public-site split — the dashboard moved under /app/*, the
  //              docs moved from /developer to /docs, and the marketing site
  //              took over "/". Order matters: query-conditioned and literal
  //              rules must precede the wildcard that would otherwise
  //              swallow them.
  async redirects() {
    return [
      // -- pre-split IA moves, retargeted at their /app destinations --------
      { source: "/approvals", destination: "/app", permanent: true },
      { source: "/policies", destination: "/app/governance", permanent: true },
      { source: "/connections", destination: "/app/integrations", permanent: true },
      { source: "/triggers", destination: "/app/automations", permanent: true },
      // Briefly (2026-07-11) capabilities lived inside /integrations tabs.
      {
        source: "/integrations",
        has: [{ type: "query", key: "tab", value: "store" }],
        destination: "/app/capabilities",
        permanent: false,
      },
      {
        source: "/integrations",
        has: [{ type: "query", key: "tab", value: "bundles" }],
        destination: "/app/capabilities?tab=bundles",
        permanent: false,
      },
      // -- dashboard → /app (wildcards match the bare segment too) ----------
      { source: "/agents/:path*", destination: "/app/agents/:path*", permanent: true },
      { source: "/automations/:path*", destination: "/app/automations/:path*", permanent: true },
      { source: "/capabilities/:path*", destination: "/app/capabilities/:path*", permanent: true },
      { source: "/governance/:path*", destination: "/app/governance/:path*", permanent: true },
      { source: "/integrations/:path*", destination: "/app/integrations/:path*", permanent: true },
      { source: "/sessions/:path*", destination: "/app/sessions/:path*", permanent: true },
      { source: "/settings/:path*", destination: "/app/settings/:path*", permanent: true },
      // -- developer docs → /docs -------------------------------------------
      { source: "/developer/reference", destination: "/docs/api/reference", permanent: true },
      { source: "/developer/quickstart", destination: "/docs/getting-started", permanent: true },
      { source: "/developer/api.html", destination: "/docs/api.html", permanent: true },
      { source: "/developer/openapi.yaml", destination: "/docs/openapi.yaml", permanent: true },
      { source: "/developer/:path*", destination: "/docs/:path*", permanent: true },
      // The quickstart guide became getting-started in the /docs IA.
      { source: "/docs/quickstart", destination: "/docs/getting-started", permanent: true },
    ];
  },
  // SSO mode assumes the hosted topology, where the dashboard and the control
  // plane answer on ONE origin: the browser-facing `/v1/auth/*` routes (login
  // start, IdP callback) must set `__Host-` cookies on the same origin the
  // dashboard runs on, and cookie-authenticated writes are refused unless the
  // request `Origin` matches `FLUIDBOX_PUBLIC_URL` exactly (scheme+host+port).
  // Locally the two run on different ports, so serve `/v1/*` from the dashboard
  // origin as well and point `FLUIDBOX_PUBLIC_URL` at it. In admin mode nothing
  // navigates to `/v1` on this origin, so the rewrite is inert.
  async rewrites() {
    if (process.env.FLUIDBOX_WEB_MODE !== "sso") return [];
    const api = process.env.FLUIDBOX_API_URL || "http://127.0.0.1:8787";
    return [{ source: "/v1/:path*", destination: `${api}/v1/:path*` }];
  },
};

export default nextConfig;
