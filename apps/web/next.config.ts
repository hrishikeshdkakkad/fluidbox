import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Self-contained server bundle for the Docker image (deploy/web.Dockerfile).
  output: "standalone",
  // Product reviews happen against the local dev stack; keep the workspace
  // free of framework chrome while still surfacing compile/runtime errors.
  devIndicators: false,
  // The 2026-07 IA consolidation moved pages around; keep old URLs working
  // (bookmarks, muscle memory). Capabilities (agent tools) and Integrations
  // (platforms agents work on) are deliberately separate pages.
  async redirects() {
    return [
      { source: "/approvals", destination: "/", permanent: true },
      { source: "/policies", destination: "/agents?tab=policies", permanent: true },
      { source: "/connections", destination: "/integrations", permanent: true },
      { source: "/triggers", destination: "/automations", permanent: true },
      // Briefly (2026-07-11) capabilities lived inside /integrations tabs.
      {
        source: "/integrations",
        has: [{ type: "query", key: "tab", value: "store" }],
        destination: "/capabilities",
        permanent: false,
      },
      {
        source: "/integrations",
        has: [{ type: "query", key: "tab", value: "bundles" }],
        destination: "/capabilities?tab=bundles",
        permanent: false,
      },
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
