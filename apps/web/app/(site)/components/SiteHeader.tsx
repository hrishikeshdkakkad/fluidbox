"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import { ThemeToggle } from "../../components/ThemeToggle";

const NAV = [
  { href: "/product", label: "Product" },
  { href: "/open-source", label: "Open Source" },
  { href: "/docs", label: "Docs" },
  { href: "/security", label: "Security" },
] as const;

// The public-site masthead. Same materials as the dashboard's topbar (chrome
// blur, hairline border, wordmark) so the product reads as one system, but
// its own information architecture: marketing pages, docs, GitHub, and the
// two ways in (sign in / get started).
export function SiteHeader() {
  const pathname = usePathname();
  const [open, setOpen] = useState(false);
  const close = () => setOpen(false);

  return (
    <header className="site-header">
      <div className="site-container site-header-inner">
        <Link href="/" className="brand masthead-brand" onNavigate={close}>
          <span className="wordmark">fluidbox</span>
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
          <a
            href="https://github.com/hrishikeshdkakkad/fluidbox"
            target="_blank"
            rel="noreferrer"
          >
            GitHub ↗
          </a>
          <div className="site-nav-mobile-actions">
            <Link href="/sign-in" className="btn sm" onNavigate={close}>
              Sign in
            </Link>
            <Link href="/docs/getting-started" className="btn sm primary" onNavigate={close}>
              Get started
            </Link>
          </div>
        </nav>

        <div className="site-actions">
          <ThemeToggle />
          <Link href="/sign-in" className="btn sm site-signin">
            Sign in
          </Link>
          <Link href="/docs/getting-started" className="btn sm primary site-getstarted">
            Get started
          </Link>
          <button
            className="masthead-menu site-menu-btn"
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
    </header>
  );
}
