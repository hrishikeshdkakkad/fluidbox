# Dashboard redesign — POC console → infra-grade control plane

**Date:** 2026-07-11 · **Scope:** `apps/web` only (presentation layer; zero Rust/API changes)
**Brief:** the POC UI proved the system; rebuild it as an infra-company dashboard
(Vercel/Modal reference), intuitive and plug-and-play, with a consolidated sidebar and a
capabilities surface that feels like an app store.

## 1. What changes and what doesn't

Changes: information architecture, visual system, copy register, component styling.
Doesn't change: every API call, flow, and invariant the UI already implements — the
same endpoints, the same payloads, the same behaviors (show-once tokens, OAuth watch
loops, popup-blocker-safe tab opening, approval decisions, SSE timeline). The dashboard
stays presentation-only per the hard constraint.

## 2. Information architecture — 8 nav items → 6

**Revised same-day (user correction):** the first cut folded capabilities and platform
connections into one "Integrations" page. That jumbled two different relationships with
the same service — GitHub-the-App is a *platform* fluidbox works ON (clone repo/branch
into the workspace, receive PR webhooks, publish reviews; credential used
control-plane-side), while GitHub-the-MCP-connector is a *capability* the agent calls
DURING a run through the permission gate. The §8.3 split is the security model; the UI
must encode it. They are now two pages with cross-links each way.

| New nav | Route | Absorbs | Rationale |
|---|---|---|---|
| **Runs** | `/` | `/approvals` | Approvals are run interruptions, not a place. Pending approvals render as an actionable attention strip at the top of Runs (and stay on session pages); the nav badge moves to Runs. |
| **Agents** | `/agents` | `/policies` (tab) | Policy is what governs an agent; both are the governance registry. Tabs: *Agents* · *Policies*. |
| **Capabilities** | `/capabilities` | — (rebuilt as the store) | Tools agents call during a run. Tabs: *Store* (MCP connector catalog as an app store) · *Bundles* (versioned registry + custom JSON registration) · *Connections* (mcp_http tool-server credentials). |
| **Integrations** | `/integrations` | `/connections` | Platforms agents work on. GitHub App setup/installs (manifest + install dances) and git connections — workspace checkouts, PR event ingress, result publishing. |
| **Automations** | `/automations` | `/triggers` | API / schedule / event subscriptions. "Trigger subscription" remains the term inside the page; the nav word describes what users are doing. |
| **Settings** | `/settings` | — | Health + security facts. |

Legacy routes redirect in `next.config.ts` (`/approvals→/`, `/policies→/agents?tab=policies`,
`/connections→/integrations`, `/triggers→/automations`, plus temporary query-matched rules
for the interim `/integrations?tab=store|bundles` shape).

## 3. Visual system

The current theme (teal glows, grid overlay, gradient panels, emoji icons) reads
"demo". The replacement is a quiet, near-black Geist-style system where the only
saturated things on screen are status and identity.

**Tokens** (single dark theme, CSS variables):
- Ground `#0a0a0a` · surface `#101011` · raised `#161618` · borders `#242427` / `#2e2e32`
- Ink `#ededed` · secondary `#a1a1a8` · tertiary `#71717a`
- Brand accent (kept from fluidbox, de-glowed): teal `#3ec8d2` — used for links,
  identifiers, and the running state only. Never as decoration.
- Status: running teal · needs-human amber `#e0a63f` · success green `#4cb782` ·
  failure red `#e5534b` · neutral gray.
- Primary action: **white button, black text** (the Vercel inversion) — the accent is
  deliberately not the primary button color.

**Type:** Geist Sans (UI) + Geist Mono (ids, digests, numbers, cron, code) via
`next/font/google`. 13px base, 20px/600 page titles, 11px uppercase tracked labels for
table headers and section markers, tabular numerals on all data.

**Icons:** `lucide-react` replaces unicode glyphs (nav, buttons, empty states, store
categories). New dependency; tree-shaken.

**Components:** bordered cards (no gradients, no shadows beyond a 1px border), tables
with real column headers, underline tabs, status dots (6px, no glow), badges, empty
states that invite the next action, modals with plain headers.

**Copy:** subtitles written from the user's side ("Give agents tools — every call
still passes the permission gate"), not design-doc prose. Invariant details move into
contextual helper lines where the decision is being made.

**Signature element:** the Integrations Store — icon tiles, tier badges
(verified/community/custom), category filter chips, search, and install-state on every
card ("Connect" → "Connected ✓"), with GitHub as the featured full-width card. This is
the page that must feel like an app store; everything else stays quiet around it.

## 3.5 Agent composer (added same day)

"New agent" moved from a cramped modal to a full-page composer at `/agents/new`:
sectioned panels (Identity · Model as option cards · Instructions · Default workspace ·
Capabilities as pin cards) with a sticky **Revision 1 preview** rail that live-renders
exactly what will freeze (name, model, policy, workspace, pins, inherits). The copy
teaches the two-prompts invariant in place: the system prompt is who the agent is; the
task is asked per run.

Workspace selection now lives ONLY on the agent (user decision): the agent's revision
carries `default_workspace`; New Run shows it read-only ("Set on the agent — change it
by appending a revision"). Per-run workspace overrides remain an API affordance. The
shared pickers were upgraded (workspace modes → segmented control; bundles → pin cards
with version selects, scrollable), which also improved the Add-revision modal.

## 4. Build plan

1. `globals.css` rewrite + fonts + `lucide-react`.
2. `Rail` → `Sidebar` (5 grouped items, Runs badge, live footer).
3. Pages in order: Runs home, Integrations, Agents(+Policies), Automations, session
   detail, Settings. Shared bits (`Pill`, `PageHead`, `DiffView`, pickers) restyled once.
4. Redirects; delete dead routes.
5. Verify: `npm run build`, live browser pass over every page against the running
   control plane, then `just check`.

## 5. Risks

- `useSearchParams` for tabs requires a `<Suspense>` boundary at build — wrap tabbed
  pages.
- The e2e's web expectations are API-level; nothing greps the dashboard markup, but
  `just check` includes the web build and must stay green.
- Route renames could break muscle memory/bookmarks — mitigated by permanent redirects.
