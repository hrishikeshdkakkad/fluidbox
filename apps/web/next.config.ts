import type { NextConfig } from "next";

const nextConfig: NextConfig = {
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
};

export default nextConfig;
