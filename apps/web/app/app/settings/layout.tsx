import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Settings",
  description: "Control-plane health and security posture.",
};

export default function SettingsLayout({ children }: LayoutProps<"/app/settings">) {
  return children;
}
