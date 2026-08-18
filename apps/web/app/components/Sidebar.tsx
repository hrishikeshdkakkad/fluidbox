"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useCallback, useEffect, useState } from "react";
import { apiGet, apiGetCached, AuthMe, logout } from "../lib/api";
import { NAV, sectionFor } from "../lib/nav";
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
  const activeSection = sectionFor(pathname);

  return (
    <>
      {/* Mobile only: a slim bar carrying the brand and the drawer toggle.
          Desktop hides it entirely — the rail below is the whole chrome. */}
      <header className="sidenav-mobilebar">
        <Link href="/app" className="brand masthead-brand" onNavigate={closeMobileNav}>
          <span className="wordmark">fluidbox</span>
          <span className="product-label">control plane</span>
        </Link>
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
      </header>

      {/* The navigation rail (Gemini drawer pattern): brand, a global New Run
          primary, the six sections as pill rows, and the ambient context —
          status, theme, account — at the foot where Google apps keep it. */}
      <aside className={`sidenav ${mobileOpen ? "open" : ""}`} aria-label="Primary">
        <Link href="/app" className="brand sidenav-brand" onNavigate={closeMobileNav}>
          <span className="wordmark">fluidbox</span>
          <span className="product-label">control plane</span>
        </Link>

        <Link
          className="btn primary sidenav-new"
          href="/app?action=new-run"
          onNavigate={closeMobileNav}
        >
          New Run
        </Link>

        <nav className="sidenav-nav" id="primary-navigation" aria-label="Primary navigation">
          {/* The six sections come from lib/nav's NAV table — the same table
              the breadcrumb walks — and you-are-here is sectionFor(pathname),
              so a route can never light two items, or none while the trail
              claims an ancestor. */}
          {NAV.map((item) => (
            <Link
              key={item.id}
              className={activeSection === item.id ? "active" : ""}
              href={item.href}
              onNavigate={closeMobileNav}
            >
              {item.label}
              {item.id === "activity" && pending > 0 && (
                <span className="masthead-count">{pending}</span>
              )}
            </Link>
          ))}
          {/* Docs deliberately sits outside NAV: it LEAVES the dashboard for
              the public surface, and the marker says so before the click. */}
          <Link href="/docs" onNavigate={closeMobileNav}>
            Docs
            <span className="masthead-ext" aria-hidden="true">
              ↗
            </span>
          </Link>
        </nav>

        <div className="sidenav-foot">
          <div className="sidenav-foot-row">
            <div
              className="masthead-state"
              title={online ? "Control plane online" : "Control plane offline"}
            >
              <span className={`signal ${online ? "" : "down"}`} />
              <span>{online ? "Operational" : "Offline"}</span>
            </div>
            <ThemeToggle />
          </div>
          {workosSession && (
            <div className="sidenav-session" data-testid="workos-session-shell">
              <div className="sidenav-account" title={`${workosSession.label} · ${workosSession.email}`}>
                <span className="sidenav-avatar" aria-hidden="true">
                  {initials(workosSession.label || workosSession.email)}
                </span>
                <span className="sidenav-identity">
                  <strong>{workosSession.label}</strong>
                  <small>{workosSession.email}</small>
                </span>
              </div>
              {signOut && (
                <form action={signOut}>
                  <button className="btn sm ghost sidenav-logout" type="submit">
                    Sign out
                  </button>
                </form>
              )}
            </div>
          )}
          {mode === "sso" && me?.user && (
            <div className="sidenav-session" data-testid="session-shell">
              <div
                className="sidenav-account"
                title={`${me.user.name || me.org?.display_name || ""} · ${me.user.email}`}
              >
                <span className="sidenav-avatar" aria-hidden="true">
                  {initials(me.user.name ?? me.user.email ?? "")}
                </span>
                <span className="sidenav-identity">
                  <strong>{me.org?.display_name ?? me.org?.slug ?? ""}</strong>
                  <small>{me.user.email}</small>
                </span>
              </div>
              <button
                className="btn sm ghost sidenav-logout"
                type="button"
                onClick={() => void logout()}
              >
                Log out
              </button>
            </div>
          )}
        </div>
      </aside>

      {/* Mobile drawer scrim: click-away closes; it never exists on desktop
          where the rail is static. */}
      {mobileOpen && (
        <button
          className="sidenav-scrim"
          type="button"
          aria-label="Close navigation"
          onClick={closeMobileNav}
        />
      )}
    </>
  );
}

/** Up to two typographic initials for the account avatar ("Hrishikesh
 *  Kakkad" → HK, "ops@corp.io" → O). Text, not iconography. */
function initials(source: string): string {
  const words = source
    .split(/[\s@._-]+/)
    .filter(Boolean)
    .slice(0, 2);
  const letters = words.map((word) => word[0]?.toUpperCase() ?? "");
  return letters.join("") || "?";
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
