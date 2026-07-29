import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "MCP",
  description: "MCP tool connections and immutable server bundles for agents.",
};

export default function CapabilitiesLayout({ children }: LayoutProps<"/capabilities">) {
  return children;
}
