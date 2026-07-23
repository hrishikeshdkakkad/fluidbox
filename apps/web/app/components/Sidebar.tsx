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
 * `mode` is the static deployment configuration (see the proxy route). In
 * `admin` it renders exactly as before — no session UI at all. In `sso` it adds
 * the signed-in organization + email + a Log out control, fed by /auth/me.
 */
export function Sidebar({ mode = "admin" }: { mode?: "admin" | "sso" }) {
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
  useSmartPolling(poll, 8000);

  const resourcesActive = ["/agents", "/capabilities", "/integrations"].some(
    (route) => pathname.startsWith(route)
  );
  const activityActive = ["/sessions", "/automations"].some(
    (route) => pathname.startsWith(route)
  );
  const closeMobileNav = () => setMobileOpen(false);

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link href="/" className="brand masthead-brand" onNavigate={closeMobileNav}>
          <span className="wordmark">fluidbox</span>
          <span className="product-label">control plane</span>
        </Link>

        <nav
          className={`masthead-nav ${mobileOpen ? "open" : ""}`}
          id="primary-navigation"
          aria-label="Primary navigation"
        >
          <Link className={pathname === "/" ? "active" : ""} href="/" onNavigate={closeMobileNav}>
            Overview
          </Link>
          <Link
            className={resourcesActive ? "active" : ""}
            href="/#configuration"
            onNavigate={closeMobileNav}
          >
            Resources
          </Link>
          <Link
            className={activityActive ? "active" : ""}
            href="/#operations"
            onNavigate={closeMobileNav}
          >
            Activity
            {pending > 0 && <span className="masthead-count">{pending}</span>}
          </Link>
          <Link
            className={pathname.startsWith("/governance") ? "active" : ""}
            href="/governance"
            onNavigate={closeMobileNav}
          >
            Governance
          </Link>
          <Link
            className={pathname === "/settings" ? "active" : ""}
            href="/settings"
            onNavigate={closeMobileNav}
          >
            Settings
          </Link>
          <Link
            className="mobile-primary-action"
            href="/?action=new-run"
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
          <div className="masthead-state" title={online ? "Control plane online" : "Control plane offline"}>
            <span className={`signal ${online ? "" : "down"}`} />
            <span>{online ? "Operational" : "Offline"}</span>
          </div>
          <Link className="topbar-action" href="/?action=new-run">
            New Run
          </Link>
          <ThemeToggle />
          {mode === "sso" && me?.user && (
            <div
              style={{ display: "flex", alignItems: "center", gap: 10 }}
              data-testid="session-shell"
            >
              <div
                style={{
                  display: "flex",
                  flexDirection: "column",
                  lineHeight: 1.15,
                  textAlign: "right",
                }}
              >
                <span style={{ fontSize: 12, color: "var(--ds-gray-1000)", fontWeight: 500 }}>
                  {me.org?.display_name ?? me.org?.slug ?? ""}
                </span>
                <span style={{ fontSize: 11, color: "var(--ds-gray-800)" }}>
                  {me.user.email}
                </span>
              </div>
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
