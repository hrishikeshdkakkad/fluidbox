"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { crumbsFor } from "../lib/nav";

/**
 * The route-derived breadcrumb trail (2026-08-14 navigation-boundary design).
 * Reads lib/nav.ts — the same table that drives the masthead's active state —
 * so the trail and the you-are-here highlight cannot disagree, and no page
 * hand-maintains its own ancestry (the hand-written trails this replaced had
 * already drifted: one linked to pre-split /governance and bounced through a
 * 308). Renders nothing on section index pages — they ARE the top of their
 * trail — and off the dashboard entirely.
 *
 * `leaf` labels a dynamic last segment (a run id, an automation name) with the
 * human-readable form the page already shows in its heading.
 */
export function Breadcrumb({ leaf }: { leaf?: string }) {
  const pathname = usePathname();
  const crumbs = crumbsFor(pathname, { leaf });
  if (crumbs.length === 0) return null;

  return (
    <nav className="crumbs" aria-label="Breadcrumb">
      <ol>
        {crumbs.map((crumb, index) => (
          <li key={`${crumb.label}-${index}`}>
            {index > 0 && <span aria-hidden="true">/</span>}
            {crumb.href ? (
              <Link href={crumb.href}>{crumb.label}</Link>
            ) : (
              <span aria-current="page">{crumb.label}</span>
            )}
          </li>
        ))}
      </ol>
    </nav>
  );
}
