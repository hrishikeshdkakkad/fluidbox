"use client";

import { usePathname } from "next/navigation";
import { Sidebar } from "./Sidebar";

/**
 * The app chrome. The masthead (Sidebar) — and the background polls it runs to
 * `/approvals` (every 4s) and `/auth/me` — belong only to authenticated
 * dashboard routes. `/login` is a pre-auth page, so mounting the Sidebar there
 * just 401-spams the control plane. This client component reads the current
 * route and renders `/login` bare (shared background only, no masthead, no
 * poll), and every other route with the full shell.
 *
 * This is the "make the root layout skip the Sidebar/masthead chrome for the
 * login route" fix: the single root layout keeps `<html>`/`<body>`/fonts/theme,
 * and the masthead is gated here. A route-group `(bare)/login` was NOT used: a
 * nested group layout still renders inside the root layout's shell, so dropping
 * the Sidebar that way needs it pushed into a sibling `(app)` group — i.e.
 * moving every route folder and rewriting its relative imports — churn this
 * change did not warrant.
 */
export function Shell({
  mode,
  children,
}: {
  mode: "admin" | "sso";
  children: React.ReactNode;
}) {
  const pathname = usePathname();
  if (pathname === "/login") {
    return <div className="shell">{children}</div>;
  }
  return (
    <div className="shell">
      <Sidebar mode={mode} />
      <main className="main">{children}</main>
    </div>
  );
}
