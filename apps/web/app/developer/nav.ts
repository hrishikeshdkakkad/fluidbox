import { GUIDES } from "./generated/content";

// The docs information architecture: grouped for the sidebar, flattened for
// prev/next pagination. Slugs reference generated/content.ts (docs-sync);
// a guide missing from these groups still renders — it just falls into the
// trailing "More" group rather than disappearing.
export type DocLink = { href: string; title: string; group: string };

const GROUPS: { name: string; slugs: string[] }[] = [
  { name: "Getting started", slugs: ["quickstart", "authentication"] },
  { name: "Governance", slugs: ["governance", "policies", "capabilities"] },
  { name: "Automation", slugs: ["triggers"] },
  { name: "Extending", slugs: ["runner-contract"] },
  { name: "Deployment", slugs: ["kubernetes"] },
];

const titleOf = new Map(GUIDES.map((g) => [g.slug, g.title]));

const grouped: DocLink[] = GROUPS.flatMap((group) =>
  group.slugs
    .filter((slug) => titleOf.has(slug))
    .map((slug) => ({
      href: `/developer/${slug}`,
      title: titleOf.get(slug)!,
      group: group.name,
    }))
);

const placed = new Set(grouped.map((l) => l.href));
const leftovers: DocLink[] = GUIDES.filter((g) => !placed.has(`/developer/${g.slug}`)).map(
  (g) => ({ href: `/developer/${g.slug}`, title: g.title, group: "More" })
);

export const REFERENCE_LINKS: DocLink[] = [
  { href: "/developer/reference", title: "API reference", group: "Reference" },
];

/** Sidebar + pagination order: guides, then the reference. */
export const DOC_LINKS: DocLink[] = [...grouped, ...leftovers, ...REFERENCE_LINKS];

export function prevNext(href: string): { prev: DocLink | null; next: DocLink | null } {
  const i = DOC_LINKS.findIndex((l) => l.href === href);
  if (i === -1) return { prev: null, next: null };
  return { prev: DOC_LINKS[i - 1] ?? null, next: DOC_LINKS[i + 1] ?? null };
}

export function docLink(href: string): DocLink | null {
  return DOC_LINKS.find((l) => l.href === href) ?? null;
}
