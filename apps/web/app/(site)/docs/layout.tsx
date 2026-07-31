import type { Metadata } from "next";
import { DocsNav } from "./DocsNav";

export const metadata: Metadata = {
  title: {
    default: "Documentation",
    template: "%s · fluidbox docs",
  },
  description:
    "Developer documentation for the fluidbox control plane: getting started, concepts, governance, deployment, the runner contract, and the full API reference.",
};

// Public by construction (see lib/auth-gate.ts): everything outside /app
// renders without a session, so nothing under /docs may call authenticated
// APIs. The docs shell: persistent left rail, content column, and (per page)
// an "on this page" rail on the right.
export default function DocsLayout({ children }: LayoutProps<"/docs">) {
  return (
    <div className="site-container docs-outer">
      <div className="docs-shell">
        <aside className="docs-rail">
          <DocsNav />
        </aside>
        <div className="docs-content">{children}</div>
      </div>
    </div>
  );
}
