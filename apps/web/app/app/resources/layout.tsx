import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Resources",
  description: "The agents, MCP servers, and integrations every run draws from.",
};

export default function ResourcesLayout({ children }: LayoutProps<"/app/resources">) {
  return children;
}
