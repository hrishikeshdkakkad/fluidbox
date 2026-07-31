import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Run detail",
  description: "Live run timeline, frozen specification, approvals, artifacts, and usage.",
};

export default function SessionsLayout({ children }: LayoutProps<"/app/sessions">) {
  return children;
}
