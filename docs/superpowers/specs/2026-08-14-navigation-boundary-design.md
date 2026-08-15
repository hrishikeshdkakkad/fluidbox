# Navigation boundary — public site and signed-in app

**Date:** 2026-08-14 · **Status:** approved, implementing

## Problem

The two surfaces bleed into each other and neither knows the other exists.

- The dashboard masthead's `docs` link **leaves the authenticated app** for the
  public site.
- The public header then offers a signed-in user **"Sign in"** and
  **"Get started"**, because it never checks for a session.
- The only route back to the dashboard is a footer link under *Product →
  Dashboard*.
- `resources` and `activity` in the masthead are not places. They are `#hash`
  jumps onto Overview, yet they rendered the you-are-here state on sub-pages.

One click on `docs` strands a signed-in user in a surface that treats them as a
stranger, with no visible way home. And because the dashboard has no hierarchy,
there is nothing for a deep page to breadcrumb back to.

## Decisions

| # | Decision | Rejected alternative |
|---|---|---|
| 1 | **One product; the chrome adapts to the session.** Same URLs, same pages, signed in or out. | A hard wall with docs duplicated at `/app/docs`; opening docs in a new tab. |
| 2 | **The two groups become real places** — `/app/resources`, `/app/activity`. | Flattening all 9 destinations into the nav (measured ~700px against a ~538px budget); collapsing to an Overview-only hub (2 clicks to anything). |
| 3 | **Scope is foundations.** Boundary, hierarchy, breadcrumbs, focus. | A ⌘K command palette; view transitions and prefetch. Both deferred — a palette over a broken hierarchy just reaches the mess faster. |
| 4 | **Session awareness via a pre-paint hint cookie.** | Making `(site)/layout.tsx` dynamic (loses static generation on the SEO surface); a client fetch of `/auth/me` (visible flash on every load). |

## The invariant

> From any page, the other surface is at most one click away, and that link is
> always visible and labelled.

```
SIGNED OUT · /docs   product docs pricing oss security   [GitHub] [Get started] [Sign in]
SIGNED IN  · /docs   product docs pricing oss security   [GitHub] [← Dashboard] [you@…]
SIGNED IN  · /app    overview activity resources governance recipes docs↗  [status] [you@…]
```

## Architecture

### Session hint (`app/lib/session-hint.ts`)

`proxy.ts` already runs on every navigation and already reads the session
cookie. It additionally writes a **non-httpOnly boolean** cookie, and an inline
script in the root layout stamps `data-session="in"|"out"` on `<html>` **before
first paint** — the same mechanism `THEME_INIT_SCRIPT` uses for the theme.

The header renders both variants; CSS shows the one that matches. Marketing
pages stay statically generated and there is no post-hydration swap.

**Security:** the hint cookie is a UI hint and never a credential. It carries no
identity, grants nothing, and is read by no authorization path. Every
authorization decision stays in the control plane behind the httpOnly
`__Host-fbx_web` session cookie. A forged hint changes only which button a
stranger sees; `/app` still redirects to `/login` and the API still answers 401.

### Route model (`app/lib/nav.ts`)

One pure module owns the route→section→ancestry mapping. Both the masthead's
active state and the breadcrumb derive from it, so they cannot disagree.

```
/app                        overview
/app/activity               activity      → runs · automations
/app/sessions/[id]          activity      ancestry: activity › runs
/app/automations[/id]       activity      ancestry: activity › automations
/app/resources              resources     → agents · mcp · integrations
/app/agents[/new]           resources     ancestry: resources › agents
/app/capabilities           resources     ancestry: resources › mcp
/app/integrations           resources     ancestry: resources › integrations
/app/governance[/name]      governance
/app/recipes[/...]          recipes
/app/settings               settings
```

Nav is six truthful items: `overview · activity · resources · governance ·
recipes · settings`. A section lights when the current route is anywhere
beneath it.

### Breadcrumbs

Derived from the route, never hand-written per page. One `<Breadcrumb />`
reading `nav.ts`. The last crumb is the current page and is not a link. This
gives an explicit parent link, so "back" does not depend on browser history —
which is wrong for anyone arriving via a deep link or a shared URL.

### Focus

A skip link targets the existing `<main id="content">`; focus moves to the page
`<h1>` after client navigation so keyboard and screen-reader users land on the
new page rather than the top of the nav.

## Out of scope

⌘K palette · view transitions · prefetch-on-intent · any change to existing
URLs · moving Recipes under Resources (a distinct concept, not a resource).

## Proofs

Each claim is measured, not asserted.

| Claim | Measurement |
|---|---|
| Boundary holds | Signed in, every public route shows exactly ONE visible link back to `/app`; signed out, zero |
| No flash | The signed-in header variant is present in first paint — no post-hydration swap |
| Static preserved | `next build` still marks marketing routes `○`/`●`, never `ƒ` |
| IA is truthful | Every `/app/*` route resolves to exactly ONE active nav item |
| Back always works | Every deep route renders a crumb trail whose first link is a real route |
| Focus lands right | After client navigation `document.activeElement` is the new `<h1>` |
| Nothing regressed | tsc · vitest · `lint:css` at its ceiling · `next build` · eslint unchanged |
