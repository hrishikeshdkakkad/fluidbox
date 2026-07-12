import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Automations",
  description: "API, schedule, and repository-event triggers for governed runs.",
};

export default function AutomationsLayout({ children }: LayoutProps<"/automations">) {
  return children;
}
