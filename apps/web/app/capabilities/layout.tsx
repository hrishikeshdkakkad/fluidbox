import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Capabilities",
  description: "Tool connections and immutable capability bundles for agents.",
};

export default function CapabilitiesLayout({ children }: LayoutProps<"/capabilities">) {
  return children;
}
