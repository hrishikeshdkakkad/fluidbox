"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { DOC_LINKS, type DocLink } from "./nav";

// The persistent docs rail. Groups render in DOC_LINKS order; the active item
// carries the accent hairline. "Docs home" is the way back to the hub from
// anywhere in the section.
export function DocsNav() {
  const pathname = usePathname();

  const groups: { name: string; links: DocLink[] }[] = [];
  for (const link of DOC_LINKS) {
    const last = groups[groups.length - 1];
    if (last && last.name === link.group) last.links.push(link);
    else groups.push({ name: link.group, links: [link] });
  }

  return (
    <nav className="docs-nav" aria-label="Documentation">
      <Link
        href="/developer"
        className={`docs-nav-home ${pathname === "/developer" ? "active" : ""}`}
      >
        <span className="docs-nav-home-mark" aria-hidden>
          ⌘
        </span>
        Developer docs
      </Link>

      {groups.map((group) => (
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
        <a className="docs-nav-item" href="/developer/api.html">
          Schemas &amp; examples
        </a>
        <a className="docs-nav-item" href="/developer/openapi.yaml" download>
          openapi.yaml ↓
        </a>
      </div>
    </nav>
  );
}
