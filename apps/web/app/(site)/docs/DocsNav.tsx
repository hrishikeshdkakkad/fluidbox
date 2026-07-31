"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { NAV_GROUPS } from "./nav";
import { DocsSearch } from "./Search";

// The persistent docs rail. Groups render in DOC_LINKS order; the active item
// carries the accent hairline. "Documentation" is the way back to the hub
// from anywhere in the section.
export function DocsNav() {
  const pathname = usePathname();

  return (
    <nav className="docs-nav" aria-label="Documentation">
      <Link
        href="/docs"
        className={`docs-nav-home ${pathname === "/docs" ? "active" : ""}`}
      >
        <span className="docs-nav-home-mark" aria-hidden>
          ⌘
        </span>
        Documentation
      </Link>

      <DocsSearch />

      {NAV_GROUPS.map((group) => (
        <div key={group.name} className="docs-nav-group">
          <div className="docs-nav-label">{group.name}</div>
          {group.links.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={`docs-nav-item ${pathname === link.href ? "active" : ""}`}
            >
              {link.title}
            </Link>
          ))}
        </div>
      ))}

      <div className="docs-nav-group">
        <div className="docs-nav-label">Spec</div>
        <a className="docs-nav-item" href="/docs/api.html">
          Schemas &amp; examples
        </a>
        <a className="docs-nav-item" href="/docs/openapi.yaml" download>
          openapi.yaml ↓
        </a>
      </div>
    </nav>
  );
}
