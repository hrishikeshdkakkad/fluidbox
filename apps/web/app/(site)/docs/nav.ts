import { GUIDES } from "./generated/content";

// The docs information architecture: grouped for the sidebar, flattened for
// prev/next pagination. Slugs reference generated/content.ts (docs-sync);
// a guide missing from these groups still renders — it just falls into the
// trailing "More" group rather than disappearing.
export type DocLink = { href: string; title: string; group: string };

/** Where a guide's page lives. Every slug maps to /docs/<slug>; `api` happens
 *  to be served by the literal /docs/api route (the API section landing)
 *  rather than the [slug] segment — same URL either way. */
export function hrefFor(slug: string): string {
  return `/docs/${slug}`;
}

/** "Edit this page on GitHub" — docs/ is the source of truth; the app renders
 *  a generated copy, so edits belong upstream. */
export const GITHUB_EDIT_BASE = "https://github.com/hrishikeshdkakkad/fluidbox/edit/main/";
export const GITHUB_REPO_URL = "https://github.com/hrishikeshdkakkad/fluidbox";

const GROUPS: { name: string; slugs: string[] }[] = [
  { name: "Start here", slugs: ["getting-started", "concepts"] },
  { name: "Running agents", slugs: ["agents", "runs", "triggers"] },
  { name: "Governance", slugs: ["governance", "policies", "approvals", "capabilities"] },
  { name: "Deployment", slugs: ["docker", "kubernetes", "security"] },
  { name: "Extending", slugs: ["runner-contract"] },
  { name: "Reference", slugs: ["api", "authentication"] },
];

const titleOf = new Map(GUIDES.map((g) => [g.slug, g.title]));

const grouped: DocLink[] = GROUPS.flatMap((group) =>
  group.slugs
    .filter((slug) => titleOf.has(slug))
    .map((slug) => ({
      href: hrefFor(slug),
      title: titleOf.get(slug)!,
      group: group.name,
    }))
);

const placed = new Set(grouped.map((l) => l.href));
const leftovers: DocLink[] = GUIDES.filter((g) => !placed.has(hrefFor(g.slug))).map(
  (g) => ({ href: hrefFor(g.slug), title: g.title, group: "More" })
);

export const REFERENCE_LINKS: DocLink[] = [
  { href: "/docs/api/reference", title: "API reference", group: "Reference" },
];

/** Sidebar + pagination order: guides, then the generated reference. */
export const DOC_LINKS: DocLink[] = [...grouped, ...leftovers, ...REFERENCE_LINKS];

/** The grouped view the sidebar and the hub render. */
export const NAV_GROUPS: { name: string; links: DocLink[] }[] = (() => {
  const out: { name: string; links: DocLink[] }[] = [];
  for (const link of DOC_LINKS) {
    const last = out[out.length - 1];
    if (last && last.name === link.group) last.links.push(link);
    else out.push({ name: link.group, links: [link] });
  }
  return out;
})();

export function prevNext(href: string): { prev: DocLink | null; next: DocLink | null } {
  const i = DOC_LINKS.findIndex((l) => l.href === href);
  if (i === -1) return { prev: null, next: null };
  return { prev: DOC_LINKS[i - 1] ?? null, next: DOC_LINKS[i + 1] ?? null };
}

export function docLink(href: string): DocLink | null {
  return DOC_LINKS.find((l) => l.href === href) ?? null;
}
