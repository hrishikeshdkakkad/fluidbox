import type { Metadata } from "next";
import { Sidebar } from "../components/Sidebar";
import { webMode } from "../lib/proxy-auth";

// The authenticated application shell. Everything under /app/* renders inside
// this chrome; the masthead's background polls (/approvals, /auth/me) belong
// here and only here — public routes carry their own chrome and never call
// authenticated APIs.
//
// The operational surface is never indexed: robots metadata here plus the
// robots.txt disallow are the two halves of that statement.
export const metadata: Metadata = {
  title: {
    default: "Overview · fluidbox",
    template: "%s · fluidbox",
  },
  robots: { index: false, follow: false },
};

const WEB_MODE = webMode(process.env.FLUIDBOX_WEB_MODE);

export default function AppLayout({ children }: LayoutProps<"/app">) {
  return (
    <div className="shell">
      <Sidebar mode={WEB_MODE} />
      <main className="main">{children}</main>
    </div>
  );
}
