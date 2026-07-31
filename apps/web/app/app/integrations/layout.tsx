import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Integrations",
  description: "Platform connections for workspaces, events, and result publishing.",
};

export default function IntegrationsLayout({ children }: LayoutProps<"/app/integrations">) {
  return children;
}
