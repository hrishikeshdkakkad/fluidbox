// The dashboard's route model — ONE source of truth for "where am I".
//
// The masthead's you-are-here state and the breadcrumb trail both derive from
// this table, so they cannot disagree. Before this existed, Sidebar.tsx carried
// hand-maintained `pathname.startsWith(...)` checks and nothing else knew the
// hierarchy at all — which is why deep pages had no way back: there was no
// parent to return to, only browser history, and history is simply wrong for
// anyone who arrived from a deep link or a shared URL.
//
// Pure functions over a path string. No React, no I/O, so it is testable in
// this repo's node-only vitest setup (see nav.test.ts).

export type SectionId =
  | "overview"
  | "activity"
  | "resources"
  | "governance"
  | "recipes"
  | "settings";

export interface NavItem {
  readonly id: SectionId;
  readonly label: string;
  readonly href: string;
}

/** The masthead, in order. Six items, every one a real destination. */
export const NAV: readonly NavItem[] = [
  { id: "overview", label: "overview", href: "/app" },
  { id: "activity", label: "activity", href: "/app/activity" },
  { id: "resources", label: "resources", href: "/app/resources" },
  { id: "governance", label: "governance", href: "/app/governance" },
  { id: "recipes", label: "recipes", href: "/app/recipes" },
  { id: "settings", label: "settings", href: "/app/settings" },
];

export interface Crumb {
  readonly label: string;
  /** Absent on the LAST crumb: you are already there, so it is not a link. */
  readonly href?: string;
}

/**
 * A route and its ancestry. `prefix` matches the route itself and anything
 * beneath it, so the list is ordered most-specific-first and the first match
 * wins.
 */
interface RouteNode {
  readonly prefix: string;
  readonly section: SectionId;
  /** Ancestors, outermost first. Empty means a section index page. */
  readonly trail: readonly Crumb[];
  /** The page's own label, when the route is not dynamic. */
  readonly label?: string;
}

const ACTIVITY: Crumb = { label: "activity", href: "/app/activity" };
const RESOURCES: Crumb = { label: "resources", href: "/app/resources" };

const ROUTES: readonly RouteNode[] = [
  // ── activity ───────────────────────────────────────────────────────────
  { prefix: "/app/automations", section: "activity", trail: [ACTIVITY], label: "automations" },
  { prefix: "/app/sessions", section: "activity", trail: [ACTIVITY] },
  { prefix: "/app/activity", section: "activity", trail: [] },
  // ── resources ──────────────────────────────────────────────────────────
  {
    prefix: "/app/agents/new",
    section: "resources",
    trail: [RESOURCES, { label: "agents", href: "/app/agents" }],
    label: "new agent",
  },
  { prefix: "/app/agents", section: "resources", trail: [RESOURCES], label: "agents" },
  { prefix: "/app/capabilities", section: "resources", trail: [RESOURCES], label: "mcp" },
  { prefix: "/app/integrations", section: "resources", trail: [RESOURCES], label: "integrations" },
  { prefix: "/app/resources", section: "resources", trail: [] },
  // ── single-level sections ──────────────────────────────────────────────
  {
    prefix: "/app/governance",
    section: "governance",
    trail: [{ label: "governance", href: "/app/governance" }],
  },
  {
    prefix: "/app/recipes",
    section: "recipes",
    trail: [{ label: "recipes", href: "/app/recipes" }],
  },
  { prefix: "/app/settings", section: "settings", trail: [] },
];

function matches(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function nodeFor(pathname: string): RouteNode | null {
  return ROUTES.find((route) => matches(pathname, route.prefix)) ?? null;
}

/** Which nav section owns this route. `null` off the dashboard, so a public
 *  page lights nothing. */
export function sectionFor(pathname: string): SectionId | null {
  if (pathname === "/app") return "overview";
  if (!pathname.startsWith("/app/")) return null;
  return nodeFor(pathname)?.section ?? null;
}

/**
 * The breadcrumb trail. Empty for top-level pages (they ARE the top level);
 * otherwise the owning section first and the current page last, unlinked.
 *
 * `leaf` names a dynamic segment — a run id is not a label a person can read,
 * so the page passes the short form it already shows in its heading.
 */
export function crumbsFor(pathname: string, { leaf }: { leaf?: string } = {}): Crumb[] {
  if (pathname === "/app") return [];
  const node = nodeFor(pathname);
  if (!node) return [];

  // A section index page is the top of its own trail.
  if (pathname === node.prefix && node.trail.length === 0) return [];

  const own =
    pathname === node.prefix
      ? node.label
      : (leaf ?? pathname.slice(node.prefix.length + 1).split("/").pop());

  // Never link a crumb to the page you are already on.
  const trail = node.trail.filter((crumb) => crumb.href !== pathname);
  if (!own) return [...trail];
  return [...trail, { label: own }];
}
