import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Activity",
  description: "Manual and automated runs on one timeline, and the automations that start them.",
};

export default function ActivityLayout({ children }: LayoutProps<"/app/activity">) {
  return children;
}
