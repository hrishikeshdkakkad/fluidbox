"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { apiGet, apiGetCached, AuthMe, logout } from "../lib/api";
import { useSmartPolling } from "../lib/useSmartPolling";
import { ThemeToggle } from "./ThemeToggle";

/**
 * The component name remains Sidebar to keep the layout seam stable, but the
 * product navigation is now a compact masthead. The dashboard owns the
 * information architecture; this shell only provides global context.
 *
 * Since the 2026-07-30 public-site split this masthead renders ONLY under
 * /app/* (the dashboard layout mounts it), so every viewer is inside the
 * authenticated area: the /approvals poll and /auth/me lookup run
 * unconditionally, and the old public-route suppression is gone with the
 * public routes themselves (marketing + /docs carry their own chrome).
 *
 * `mode` is the static deployment configuration (see the proxy route). In
 * `admin` it renders exactly as before — no session UI at all. In `sso` it adds
 * the signed-in organization + email + a Log out control, fed by /auth/me.
 *
 * `workosSession` is the WorkOS web-tier badge (FLUIDBOX_WEB_AUTH=workos),
 * resolved SERVER-SIDE by the /app layout's withAuth() and passed down — the
 * client never derives auth state. Sign out is a POST server action (never a
 * GET route: prefetch-safe, CSRF-safe).
 */
export interface WorkosSessionBadge {
  label: string;
  email: string;
}

export function Sidebar({
  mode = "admin",
  workosSession = null,
  signOut,
}: {
  mode?: "admin" | "sso";
  workosSession?: WorkosSessionBadge | null;
  signOut?: () => Promise<void>;
}) {
  const pathname = usePathname();
  const [pending, setPending] = useState(0);
  const [online, setOnline] = useState(true);
  const [me, setMe] = useState<AuthMe | null>(null);
  const [mobileOpen, setMobileOpen] = useState(false);

  useEffect(() => {
    if (mode !== "sso") return;
    let alive = true;
    apiGetCached<AuthMe>("/auth/me", { maxAgeMs: 60_000 })
      .then((m) => {
        if (alive) setMe(m);
      })
      .catch(() => {
        // 401 already routed the browser to /login (api.ts); other errors just
        // leave the session block unrendered.
      });
    return () => {
      alive = false;
    };
  }, [mode]);

  const poll = useCallback(async () => {
    try {
      const response = await apiGet<{ approvals: unknown[] }>("/approvals");
      setPending(response.approvals.length);
      setOnline(true);
    } catch {
      setOnline(false);
    }
  }, []);
  useSmartPolling(poll, 8000, true);

  const closeMobileNav = () => setMobileOpen(false);

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link href="/app" className="brand masthead-brand" onNavigate={closeMobileNav}>
          <span className="wordmark">fluidbox</span>
          <span className="product-label">control plane</span>
        </Link>

        <nav
          className={`masthead-nav ${mobileOpen ? "open" : ""}`}
          id="primary-navigation"
          aria-label="Primary navigation"
        >
          <Link
            className={pathname === "/app" ? "active" : ""}
            href="/app"
            onNavigate={closeMobileNav}
          >
            Overview
          </Link>
          {/* Resources and Activity are jump-links to sections of the Overview
              page, not routes. They deliberately carry no `active` class: the
              you-are-here highlight is reserved for a page you are actually on,
              and lighting "Resources" while the URL reads /app/agents told the
              user something untrue. */}
          <Link href="/app#configuration" onNavigate={closeMobileNav}>
            Resources
          </Link>
          <Link href="/app#operations" onNavigate={closeMobileNav}>
            Activity
            {pending > 0 && <span className="masthead-count">{pending}</span>}
          </Link>
          <Link
            className={pathname.startsWith("/app/recipes") ? "active" : ""}
            href="/app/recipes"
            onNavigate={closeMobileNav}
          >
            Recipes
          </Link>
          <Link
            className={pathname.startsWith("/app/governance") ? "active" : ""}
            href="/app/governance"
            onNavigate={closeMobileNav}
          >
            Governance
          </Link>
          <Link href="/docs" onNavigate={closeMobileNav}>
            Docs
          </Link>
          <Link
            className={pathname === "/app/settings" ? "active" : ""}
            href="/app/settings"
            onNavigate={closeMobileNav}
          >
            Settings
          </Link>
          <Link
            className="mobile-primary-action"
            href="/app?action=new-run"
            onNavigate={closeMobileNav}
          >
            New Run
          </Link>
          {mode === "sso" && me?.user && (
            <div className="mobile-session">
              <span>
                <strong>{me.org?.display_name ?? me.org?.slug ?? "Signed in"}</strong>
                <small>{me.user.email}</small>
              </span>
              <button className="btn sm ghost" type="button" onClick={() => void logout()}>
                Log out
              </button>
            </div>
          )}
        </nav>

        <div className="masthead-actions">
          <div
            className="masthead-state"
            title={online ? "Control plane online" : "Control plane offline"}
          >
            <span className={`signal ${online ? "" : "down"}`} />
            <span>{online ? "Operational" : "Offline"}</span>
          </div>
          {/* No desktop "New Run" here. Every page that can start a run renders
              its own primary (e.g. app/app/page.tsx), so this was a second dark
              primary competing with it — and its 76px (90px with the gap) is
              exactly what the header needed to stop clipping the nav. The
              mobile dropdown keeps its own .mobile-primary-action above, where
              no page primary is in view. */}
          <ThemeToggle />
          {/* Classes, not inline style. An inline `display` cannot be
              overridden by a stylesheet, so the compact-desktop rule that hides
              the identity text below 1280px was silently a no-op while these
              were style={{…}} — the header kept overflowing by 20px. */}
          {workosSession && (
            <div className="masthead-session" data-testid="workos-session-shell">
              <span
                className="masthead-session-email"
                title={`${workosSession.label} · ${workosSession.email}`}
              >
                {workosSession.email}
              </span>
              {signOut && (
                <form action={signOut}>
                  <button className="btn sm ghost" type="submit">
                    Sign out
                  </button>
                </form>
              )}
            </div>
          )}
          {mode === "sso" && me?.user && (
            <div className="masthead-session" data-testid="session-shell">
              <span className="masthead-session-id">
                <strong>{me.org?.display_name ?? me.org?.slug ?? ""}</strong>
                <small>{me.user.email}</small>
              </span>
              <button className="btn sm ghost" onClick={() => void logout()}>
                Log out
              </button>
            </div>
          )}
          <button
            className="masthead-menu"
            type="button"
            aria-label={mobileOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={mobileOpen}
            aria-controls="primary-navigation"
            onClick={() => setMobileOpen((open) => !open)}
          >
            {mobileOpen ? <CloseIcon /> : <MenuIcon />}
          </button>
        </div>
      </div>
    </header>
  );
}

function MenuIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="M4 7h16M4 12h16M4 17h16" />
    </svg>
  );
}

function CloseIcon() {
  return (
    <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path d="m6 6 12 12M18 6 6 18" />
    </svg>
  );
}
