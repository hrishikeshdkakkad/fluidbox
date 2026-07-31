import type { Metadata } from "next";
import { DocsNav } from "./DocsNav";

export const metadata: Metadata = {
  title: "Developer",
  description:
    "Developer documentation for the fluidbox control plane: quickstart, authentication, governance, the runner contract, and the full API reference.",
};

// Public route (see lib/auth-gate.ts): the docs render without a session, so
// nothing under /developer may call authenticated APIs. The Sidebar suppresses
// its /approvals and /auth/me polling here for the same reason.
//
// The docs shell: persistent left rail, content column, and (per page) an
// "on this page" rail on the right.
export default function DeveloperLayout({ children }: LayoutProps<"/developer">) {
  return (
    <div className="docs-shell">
      <aside className="docs-rail">
        <DocsNav />
      </aside>
      <div className="docs-content">{children}</div>
    </div>
  );
}
