# Session handover — 2026-08-14 UI foundation + navigation boundary

**Branch:** `fix/web-ui-foundation-pass` · **PR:** [#141](https://github.com/hrishikeshdkakkad/fluidbox/pull/141), OPEN, 5 commits pushed
**Read first:** `docs/superpowers/specs/2026-08-14-navigation-boundary-design.md` — the approved design you are implementing.

---

## 1. State right now

**Committed and pushed (5 commits, all green):**

| commit | what |
|---|---|
| `f4dfd1d` | CSS gate + the four user-visible defects (diff contrast, masthead clipping, `ApiError` + 6 boundary files, docs copy button) |
| `e37bbf2` | Revoke confirmation, sign-in refusal redirect (incl. a Rust change in `login.rs`), Guardrails→Policy |
| `54452bd` | Tier 3 part 1 — radius/breakpoints/colour, gate 298 → 59 |
| `ffec520` | Tier 3 part 2 — 47 duplicate selectors folded via PostCSS, gate 59 → 10 |
| `3206890` | Two regressions I introduced, caught by a user screenshot (see §5) |

**Uncommitted — the navigation work, half done:**

```
 M apps/web/app/(site)/components/SiteHeader.tsx
 M apps/web/app/globals.css
 M apps/web/app/kernel.css          (comment correction only, see §5)
 M apps/web/app/layout.tsx
 M apps/web/proxy.ts
?? apps/web/app/lib/nav.ts + nav.test.ts
?? apps/web/app/lib/session-hint.ts + session-hint.test.ts
?? docs/superpowers/specs/2026-08-14-navigation-boundary-design.md
```

**Gates (verified moments ago):** `tsc` 0 · **241 tests / 16 files** · `lint:css`
10 problems at a ceiling of 10 · `next build` 0 · eslint unchanged at its
pre-existing 16-problem baseline (15 errors, 11 of them
`react-hooks/set-state-in-effect` — deliberately untouched).

---

## 2. What is DONE in the navigation work

The two pure modules — the hard part — are written and tested.

**`app/lib/nav.ts` (25 tests).** One route model for the whole dashboard.
`sectionFor(path)` → which of six nav sections owns a route (null off `/app`).
`crumbsFor(path, {leaf})` → the breadcrumb trail; empty for section-index pages,
otherwise section first and current page last with **no href**. Both the
masthead's active state and the breadcrumb derive from it, so they cannot
disagree. Replaces four inline `pathname` checks in `Sidebar.tsx`.

**`app/lib/session-hint.ts` (10 tests).** The pre-paint mechanism that lets
**statically generated** public pages know you are signed in. `proxy.ts` mirrors
the presence of the HttpOnly session cookie into a plain boolean `fbx_ui`
cookie; `SESSION_HINT_INIT_SCRIPT` stamps `data-session` on `<html>` in `<head>`
before first paint, exactly like `THEME_INIT_SCRIPT`.

> **Security note to preserve:** `fbx_ui` is a UI hint and **never a credential**.
> No authorization path reads it. Forging it changes only which button a
> stranger sees — `/app` still redirects to `/login`, the API still answers 401.
> It is deliberately **not** HttpOnly (the pre-paint script must read it), and a
> test asserts that, plus "it is not the session cookie".

**Wired:** `proxy.ts` stamps every response path (and *clears* the hint on the
`/login` bounce, so a lapsed session cannot leave the public header claiming you
are signed in); `layout.tsx` runs the script; `SiteHeader.tsx` renders both
variants (desktop + mobile); `globals.css` shows the matching one and **defaults
to signed-out**, so JS-disabled degrades toward the public state.

**The load-bearing risk is retired:** `next build` confirms **zero** marketing
routes went dynamic — `/docs`, `/pricing`, `/product`, `/open-source`,
`/changelog`, `/docs/api` all still `○`, `/docs/[slug]` still `●`. That was the
entire reason for choosing the hint cookie over reading cookies server-side.

---

## 3. What REMAINS — start here

Roughly half the plan. Everything below wires against the already-tested
contract in `lib/nav.ts`, so it is mechanical.

1. **`Sidebar.tsx`** — drive the masthead from `NAV`. Six items:
   `overview · activity · resources · governance · recipes · settings`.
   Delete the four inline `pathname === / startsWith` checks (~lines 93, 112,
   119, 129) and use `sectionFor(pathname) === item.id` for `.active`. The
   `docs` link stays but should carry an out-of-app marker (`↗`).
   *Measured budget: the nav has ~538px; six items fit with room.*
2. **`app/components/Breadcrumb.tsx`** — render `crumbsFor()` as
   `<nav aria-label="Breadcrumb">` with an ordered list; last crumb unlinked.
3. **`/app/resources/page.tsx`** — index over agents · mcp · integrations.
   **`/app/activity/page.tsx`** — index over runs · automations.
   Overview stays the summary; these are the workbenches.
4. **`<Breadcrumb />` on the deep pages** — `sessions/[id]` (pass the short id
   as `leaf`), `agents`, `agents/new`, `capabilities`, `integrations`,
   `governance/[name]`, `recipes/[slug]`, `recipes/instances/[id]`,
   `automations/[id]`.
5. **Skip link + focus** — `<main id="content">` already exists in
   `app/app/layout.tsx:54` but nothing targets it. Add a skip link, and move
   focus to the page `<h1>` after client navigation.

### The proofs still owed (from the design doc)

| Claim | How to measure |
|---|---|
| Boundary holds | Signed in, every public route shows exactly ONE visible link back to `/app`; signed out, zero |
| No flash | Signed-in header variant present in **first paint**, no post-hydration swap |
| Static preserved | ✅ already verified — keep it green |
| IA truthful | Every `/app/*` route resolves to exactly ONE active nav item |
| Back works | Every deep route renders a trail whose first link is a real route |
| Focus | `document.activeElement` is the new `<h1>` after client navigation |

---

## 4. Environment — how to actually see it

```
localhost:3000        next dev — SSO mode, /app 307s to /login
127.0.0.1:8787/8788   fluidbox-server, /v1/health 200
127.0.0.1:5433        postgres (deploy-postgres-1, healthy)
127.0.0.1:4000        litellm
```

- **Sign in:** `localhost:3000/login`, org slug **`local`** (Auth0). Use
  `localhost`, never `127.0.0.1` — Origin must equal `FLUIDBOX_PUBLIC_URL`.
- **To inspect `/app` without logging in:** restart with
  `FLUIDBOX_WEB_MODE=admin PORT=3000 ./node_modules/.bin/next dev`. Data reads
  will 403 (the admin token is confined to `/v1/admin/*` under
  `FLUIDBOX_REQUIRE_SSO=1`), so pages render their error states — fine for
  chrome/layout work, useless for data. **Put it back to sso mode afterwards.**
- Next 16 refuses two dev servers from one directory, so swap modes rather than
  running both.
- Run tools directly (`./node_modules/.bin/…`). `pnpm <script>` uses the PATH
  pnpm 11 against a pnpm-10 `node_modules` and demands a TTY purge. To add a
  dependency: `npx pnpm@10 add -D …`.
- **Never** run DB or e2e scripts unprompted — real infrastructure, real money.

---

## 5. Hard-won lessons — read before trusting any measurement

This session produced several wrong conclusions caught only by re-measuring. The
pattern is always the same: **verification only covers the question you thought
to ask.**

- **Three duplicate-selector merges were wrong** before the fourth. The third
  looked perfect — 26 blocks removed, semicolon count identical, brace count
  down exactly 26 — and the browser's CSS parser then found **60 declaration
  differences**: my hand-rolled parser disagreed with the browser about selector
  identity. **Use PostCSS** (`node_modules/.pnpm/postcss@8.5.16/…`), never
  regex, for structural CSS work.
- **A user screenshot caught two bugs my measurements could not.** (a) I removed
  the masthead "New Run" because the audit said the page renders its own
  primary — true in the JSX, false in the render, because `kernel.css` hid it
  with `.dashboard-header > .btn { display:none }`. Desktop had **no way to
  start a run**. (b) The signed-in email overlapped the theme toggle by 22px;
  my masthead check passed because it measured the **parent** box and only the
  **child** overflowed.
- **I reported a `color-scheme` dark-mode bug that does not exist.** My test set
  `data-theme` by hand while `THEME_INIT_SCRIPT`'s inline `color-scheme: light`
  was still on the element — the inline style won. The real toggle
  (`ThemeToggle.tsx:23-24`) sets both. The misleading comment in `kernel.css` is
  corrected in the uncommitted diff; **commit that correction.**
- **The audit's own contrast numbers were computed against the wrong
  background** (`--surface`, when `kernel.css` re-declares `.diff` to `--raised`
  and wins). Following its prescription literally would have pushed light
  `.diff .add` to 3.91:1.

**Rule established here:** measure the *rendered* result, name the element you
measured, and prefer an oracle you did not write (the browser's parser, a
mutation test) over one you did.

---

## 6. Known-open, not in this branch

- `.btn.danger:hover` at **3.00:1** — needs a design decision, not a token swap.
- 15 eslint errors (11 `set-state-in-effect` in `RunComposer` /
  `PolicyVersionHistory`) — own PR, own tests, runtime-behavioural.
- ~15 high-severity audit findings untouched, notably: the run timeline shows
  **no timestamps at all** on the product's core audit surface, and a dropped
  live stream is invisible once any event has arrived. This is the
  highest-value remaining UX work
  (`docs/reviews/2026-08-14-ui-audit/findings.json`).
- The 10 remaining `lint:css` warnings are judgement calls, enumerated in the
  `ffec520` commit message.
