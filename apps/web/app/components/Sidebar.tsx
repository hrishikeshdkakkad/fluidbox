"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { apiGet, AuthMe, logout } from "../lib/api";

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

  useEffect(() => {
    if (mode !== "sso") return;
    let alive = true;
    apiGet<AuthMe>("/auth/me")
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

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const response = await apiGet<{ approvals: unknown[] }>("/approvals");
        if (alive) {
          setPending(response.approvals.length);
          setOnline(true);
        }
      } catch {
        if (alive) setOnline(false);
      }
    };
    void poll();
    const timer = setInterval(poll, 4000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, []);

  const resourcesActive = ["/agents", "/capabilities", "/integrations"].some(
    (route) => pathname.startsWith(route)
  );
  const activityActive = ["/sessions", "/automations"].some(
    (route) => pathname.startsWith(route)
  );

  return (
    <header className="topbar">
      <div className="topbar-inner">
        <Link href="/" className="brand masthead-brand">
          <span className="wordmark">fluidbox</span>
          <span className="product-label">control plane</span>
        </Link>

        <nav className="masthead-nav" aria-label="Primary navigation">
          <Link className={pathname === "/" ? "active" : ""} href="/">
            Overview
          </Link>
          <Link className={resourcesActive ? "active" : ""} href="/#configuration">
            Resources
          </Link>
          <Link className={activityActive ? "active" : ""} href="/#operations">
            Activity
            {pending > 0 && <span className="masthead-count">{pending}</span>}
          </Link>
          <Link className={pathname.startsWith("/governance") ? "active" : ""} href="/governance">
            Governance
          </Link>
          <Link className={pathname === "/settings" ? "active" : ""} href="/settings">
            Settings
          </Link>
        </nav>

        <div className="masthead-actions">
          <div className="masthead-state" title={online ? "Control plane online" : "Control plane offline"}>
            <span className={`signal ${online ? "" : "down"}`} />
            <span>{online ? "Operational" : "Offline"}</span>
          </div>
          <Link className="topbar-action" href="/?action=new-run">
            New Run
          </Link>
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
        </div>
      </div>
    </header>
  );
}
