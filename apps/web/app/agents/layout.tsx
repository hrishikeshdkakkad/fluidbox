import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Agents",
  description: "Versioned agent definitions and the policies that govern them.",
};

export default function AgentsLayout({ children }: LayoutProps<"/agents">) {
  return children;
}
