"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ThemeToggle } from "../../components/ThemeToggle";

const REPO = "https://github.com/hrishikeshdkakkad/fluidbox";

const NAV = [
  { href: "/product", label: "Product" },
  { href: "/docs", label: "Docs" },
  { href: "/pricing", label: "Pricing" },
  { href: "/open-source", label: "Open Source" },
  { href: "/security", label: "Security" },
] as const;

function GitHubMark() {
  return (
    <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8Z" />
    </svg>
  );
}

// The public-site chrome: a lime announcement strip that scrolls away, then
// a pinned near-black masthead. Marketing chrome is dark-only by design —
// the theme toggle only appears on /docs, the one public surface that keeps
// dual themes.
export function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  return (
    <>
      <div className="site-announce">
        <div className="site-container site-announce-inner">
          <span>
            new: v0.3 — kubernetes-native sandboxes and the multi-user control
            plane. <Link href="/changelog">read the changelog ›</Link>
          </span>
          <nav className="site-announce-links" aria-label="Utility">
            <a href={REPO} target="_blank" rel="noreferrer">
              github
            </a>
            <a href={`${REPO}/blob/main/ROADMAP.md`} target="_blank" rel="noreferrer">
              roadmap
            </a>
            <a href={`${REPO}/discussions`} target="_blank" rel="noreferrer">
              talk to us
            </a>
          </nav>
        </div>
      </div>

      <header className="site-header">
        <div className="site-container">
          <div className="st-navpill">
          <Link href="/" className="st-brand" onNavigate={close}>
            <span className="st-mark" aria-hidden>
              <i />
              <i />
              <i />
              <i />
            </span>
            <span className="st-wordmark">fluidbox</span>
          </Link>

          <nav
            id="site-navigation"
            className={`site-nav ${open ? "open" : ""}`}
            aria-label="Site"
          >
            {NAV.map((item) => (
              <Link
                key={item.href}
                href={item.href}
                className={
                  pathname === item.href || pathname.startsWith(`${item.href}/`)
                    ? "active"
                    : ""
                }
                onNavigate={close}
              >
                {item.label}
              </Link>
            ))}
            <div className="site-nav-mobile-actions">
              <Link href="/sign-in" className="btn sm" onNavigate={close}>
                Log In
              </Link>
              <Link href="/docs/getting-started" className="btn sm primary" onNavigate={close}>
                Get Started
              </Link>
            </div>
          </nav>

          <div className="site-actions">
            {pathname.startsWith("/docs") && <ThemeToggle />}
            <a
              className="site-gh"
              href={REPO}
              target="_blank"
              rel="noreferrer"
              aria-label="fluidbox on GitHub"
            >
              <GitHubMark />
            </a>
            <Link href="/docs/getting-started" className="btn sm primary site-getstarted">
              Get Started
            </Link>
            <Link href="/sign-in" className="btn sm site-signin">
              Log In
            </Link>
            <button
              className="site-menu-btn"
              type="button"
              aria-label={open ? "Close navigation" : "Open navigation"}
              aria-expanded={open}
              aria-controls="site-navigation"
              onClick={() => setOpen((o) => !o)}
            >
              {open ? (
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="m6 6 12 12M18 6 6 18" />
                </svg>
              ) : (
                <svg viewBox="0 0 24 24" fill="none" aria-hidden="true">
                  <path d="M4 7h16M4 12h16M4 17h16" />
                </svg>
              )}
            </button>
          </div>
          </div>
        </div>
      </header>
    </>
  );
}
