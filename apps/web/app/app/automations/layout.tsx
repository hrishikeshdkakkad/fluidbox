import type { Metadata } from "next";

export const metadata: Metadata = {
  // This layout only ever renders the detail route — /app/automations itself
  // redirects — so the tab read "Runs · fluidbox" on an automation page.
  title: "Automation",
  description: "Governed runs launched manually or from API, schedule, and repository-event triggers.",
};

export default function AutomationsLayout({ children }: LayoutProps<"/app/automations">) {
  return children;
}
