import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Runs",
  description: "Governed runs launched manually or from API, schedule, and repository-event triggers.",
};

export default function AutomationsLayout({ children }: LayoutProps<"/automations">) {
  return children;
}
