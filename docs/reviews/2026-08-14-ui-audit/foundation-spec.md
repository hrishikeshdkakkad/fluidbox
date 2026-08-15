All load-bearing facts confirmed against the real files: import order (`globals.css` L3 → `kernel.css` L4, kernel wins ties); **five** `api.ts` throw sites (46, 115, 130, 147, 158) — P3's "two" is wrong; the three token divergences where kernel wins (`--surface-soft` .94 vs .9, `--surface-hover` `var(--ds-gray-100)` vs `#ece9dd`, `--accent-dim` `var(--ds-green-900)` vs `#486700`/`#81b300`); fonts/skeleton/canvas-glow exist only in globals (57/54/40), absent from kernel; masthead clip (globals 497-500 + `::-webkit-scrollbar`) never reset by kernel 250-256; `var(--muted)` undefined; zero boundary files; 9,708 CSS lines.

---

# fluidbox UI — Final Foundation Specification

## 1. Diagnosis

The dashboard ships two stylesheets that fight (`globals.css` 7,950 lines, then `kernel.css` 1,758 lines re-declaring ~76% of it and winning every tie by load order), three parallel token vocabularies (`--*`, `--ds-*`, `--st-*`) each hard-coding the same paper/ink/chartreuse palette in a different place, and no mechanical guard — CI runs `build`+`test` and never `lint`, so drift has zero cost. Because `kernel.css` already wins at runtime, the correct primitive layer is `--ds-*`; formalising that reality (not inventing a scheme) collapses the three vocabularies into one — but only as a **union**, because `kernel`'s `:root` lacks the fonts/skeleton/canvas-glow tokens that live only in globals, and its shared values *differ* from globals' in three places (a naive "delete globals `:root`" silently drops the fonts). Every felt symptom is downstream of these three facts: the masthead clips because a deliberate `overflow-x:auto; justify-content:center; scrollbar-width:none` is never reset; 404s and thrown errors fall to Next's black page because no App-Router boundary files exist; `api.ts` collapses every failure into one opaque string across five throw sites so no surface can tell "deleted" from "outage"; the diff goes dark-on-dark because `#1f6b49/#a33d36` never got a dark override. The fix is to consolidate the tokens, enforce exactly the three owner-locked scales (radius, colour, breakpoints) with a blocking CSS gate that is green on day one and decoupled from the pre-existing red eslint, land the visible chrome/state/live-run wins early, and split the monolith last behind a computed-style regression net.

---

## 2. Token contract

One file, `app/styles/tokens.css`, imported first and the **only** place a raw hex/rgb/hsl literal may appear. Two layers: primitives `--ds-*` (raw, theme-flipped) and semantics `--<role>` (aliases only). Light on bare `:root`; dark on `html[data-theme="dark"]` (this app never uses `prefers-color-scheme` — theme is stamped as `data-theme` before paint).

### 2.1 Colour — keep the existing scale, dedupe the roots

Canonical = **kernel's** `--ds-*` primitives + semantic aliases, kept **verbatim** (`kernel.css:16-84` light, `:116-151` dark). No colour value changes; keeping kernel's values = zero pixel change because kernel already wins today. The three shared tokens that *diverge* resolve to **kernel's** value (locking runtime truth):

| Token | globals (dead) | kernel (canonical — keep) |
|---|---|---|
| `--surface-soft` | `rgba(250,249,242,0.9)` | `rgba(250,249,242,0.94)` |
| `--surface-hover` | `#ece9dd` | `var(--ds-gray-100)` (`#eae7db`) |
| `--accent-dim` (light/dark) | `#486700` / `#81b300` | `var(--ds-green-900)` / `var(--ds-green-900)` |

Primitive anchors (verified): `--ds-background-100:#f2f0e7`, `--ds-background-200:#faf9f2`, `--ds-gray-100:#eae7db`, `--ds-green-700:#567a00`, `--ds-green-900:#b4e23e`, `--ds-red-700:#b3402e`, `--ds-gold-700:#8a6d1c`. Semantic layer (names components reference): `--bg --surface --surface-soft --surface-hover --raised --border --border-strong --ink --ink-2 --ink-3 --flood(#81b300) --flood-ink --accent --accent-dim --accent-tint --gold --green --green-tint --red --red-tint`.

**Union carry-forward (the keystone):** these live only in `globals.css` and MUST be merged into `tokens.css` or the app loses its fonts — `--font-sans/--font-mono/--font-display/--font-jp/--font-sc` (`globals.css:57-61`), `--skeleton-a/--skeleton-b` (`:54-55`), `--canvas-glow` (`:40`).

**`--st-*` retired as a palette:** its 23 members become aliases (`--st-bg:var(--bg)`, `--st-ink:var(--ink)`, `--st-flood:var(--flood)`, `--st-radius:var(--radius)`, …) so ~200 marketing call sites keep working; the triplicated hex (`globals.css:5819`, and the `.st`-scope re-pin at `:5907-5921`) dies. Marketing stays always-light by resetting semantics on the `.st` scope, not by re-hexing.

**`--term-*` (theme-exempt terminal-mockup swatches):** `--term-bg:#26282c --term-red:#ff5f57 --term-amber:#febc2e --term-green:#2ac840 --term-teal:#6ef0c0 --term-gold:#ffce6a --term-meta:#85869a`. The one sanctioned literal-colour ghetto (a simulated terminal has one look); stylelint whitelists only these names.

### 2.2 Radius — role-based, two tokens + three literals

| Property | Value |
|---|---|
| `--radius` | `4px` |
| `--radius-lg` | `8px` |
| *(sanctioned literals)* | `999px` (pills), `50%` (circles), `0` (square panels) |

**Assignment is by role, not blind nearest-value:** controls / chips / rows / inputs → `--radius`; cards / panels / modals / dropdowns / feature surfaces → `--radius-lg`. The gate only checks the value is one of the two tokens (or the three literals), never which — so role assignment is a design call, mechanically enforced.

### 2.3 Spacing — new, 4px grid (additive, WARN)

`--space-1:4px --space-2:8px --space-3:12px --space-4:16px --space-5:20px --space-6:24px --space-8:32px --space-10:40px --space-12:48px --space-14:56px --space-16:64px --space-24:96px`; plus `--control-touch:44px` (a WCAG hit-area, not spacing).

### 2.4 Type — new (additive, WARN); sub-pixel elimination is the real defect

Size: `--text-2xs:11px --text-xs:12px --text-sm:13px --text-base:14px --text-md:16px --text-lg:20px --text-xl:24px --text-title:33px --text-display:clamp(29px,3vw,38px)`. Weight: `--weight-light:300 --weight-normal:400 --weight-medium:500`. Leading: `--leading-tight:1.2 --leading-snug:1.35 --leading-normal:1.5`. Tracking: `--tracking-display:0.015em --tracking-label:0.02em --tracking-normal:0`. Sub-pixel sizes (`9.5/10.5/11.5/12.5/13.5/20.5px`) round to the nearest step. **Rule: `--font-mono` is reserved for machine data** (ids, paths, digests, timestamps, counts) — the `.chip` prose ("Personal", "via app") must leave mono.

### 2.5 Motion, elevation, z-index, border, shell (additive, WARN except where noted)

| Group | Tokens |
|---|---|
| Motion | `--dur-fast:120ms --dur-base:200ms --dur-entrance:400ms --dur-slow:600ms --dur-loop:1.4s`; `--ease-standard:cubic-bezier(0.2,0.7,0.2,1) --ease-out:ease-out --ease-linear:linear` |
| Elevation | `--elevation-flat:none` (every panel/card — the identity); `--shadow-overlay:0 24px 70px rgba(28,32,36,0.18)` (modals + the masthead dropdown ONLY); `--ring-flood:0 0 0 3px rgba(129,179,0,0.2)` (live-state glow) |
| Z-index | `--z-base:0 --z-sticky:30 --z-dropdown:40 --z-overlay:100 --z-modal:110 --z-skiplink:200 --z-toast:300` |
| Border | `--hairline:0.5px`; `--rule:var(--hairline) solid var(--border)`; `--rule-strong:var(--hairline) solid var(--border-strong)` |
| Shell | `--shell-max:1200px` |

### 2.6 Deletion map (old literal → new token)

| Old literal / site | → New token |
|---|---|
| `#f2f0e7` | `--bg` |
| `#faf9f2` / `#fffefa` / `#ffffff` (surfaces) | `--surface` / `--primary-ink` |
| `#eae7db` / `#ece9dd` | `--surface-hover` |
| `#1c2024` / `#11100d` | `--ink`; kernel:749 `#1c2024` → `--flood-ink` |
| `#4c5157` / `#60646c` | `--ink-2` / `--ink-3` |
| `var(--muted)` (`capabilities/page.tsx:343`, undefined) | `--ink-3` |
| `#81b300` | `--flood`; `#567a00`/`#486700` → `--accent`/`--accent-dim` |
| `.diff .add #1f6b49` (`globals.css:2220`) / `.diff .del #a33d36` (`:2224`), `#b3402e` | `--green` / `--red` (now flip in dark) |
| `rgba(250,249,242,0.94)` (`globals.css:255`) | `--surface-soft` |
| `rgba(33,34,37,…)` / `rgba(237,238,240,…)` | `--border` / `--border-strong` |
| panel `box-shadow 0 1px 2px rgba(42,38,32,.025)…` (`globals.css:617`) | `--elevation-flat` (delete — flat identity) |
| `#6ef0c0/#ffce6a/#ff5f57/#febc2e/#2ac840/#26282c/#85869a` | `--term-*` |
| `PixelIcon.tsx:139-140` `#81b300`→`#cab168` duotone | **delete the gradient**, single `currentColor`; `--gold` survives only for the GitHub-App badge + warn state |
| radius `5/6/7px` (controls), base `.btn 9px` (`globals.css:1953`) | `var(--radius)` |
| radius `9/10/11/12/14/15/16px` (panels/cards); `0 0 11px 11px` (`globals.css:3579`, dropdown) | `var(--radius-lg)`; `0 0 var(--radius-lg) var(--radius-lg)` |
| literal `4px`×16 / `8px`×11 | `var(--radius)` / `var(--radius-lg)` |
| `borderRadius:7` inline (`integrations/page.tsx:212`) | `var(--radius)` |
| `1px solid …` component dividers (GateStrip `globals.css:6958/6993/7803/7874`) | `var(--rule)` |
| `0.5px solid rgba(…)` (`.st-stage-card`, `globals.css:6484`) | `var(--rule-strong)` |
| `.topbar-inner max-width:1440px` (`globals.css:446`), `1240px` (`:2961`), `.main 1240px` (`:238`) | `var(--shell-max)` |
| 51 inline `fontSize:` + `fontSize:20` (`login-form.tsx:47`) | `--text-*` / a class |

---

## 3. Breakpoint contract

**Three widths, no others: 640 / 900 / 1280.** Today there are eleven media breakpoints (640, 720, 760, 860, 900, 960, 961, 980, 1000, 1060, 1120) plus three conflicting container maxes (1200/1240/1440). Declared once in `tokens.css`:

```css
@custom-media --bp-sm (max-width: 640px);
@custom-media --bp-md (max-width: 900px);
@custom-media --bp-lg (max-width: 1280px);
```

Authors write only `@media (--bp-md)`. This gate targets **media features only** — element-level `min-width`/`max-width` properties (the `170px` org-email ellipsis, grid floors) are untouched.

**Map (11 → 3):** `720→640`; `760→900`; `860→900` (5 shell/rail blocks); `960/961/980/1000→900`; `1060→1280`; `1120→1280`. `prefers-reduced-motion` and `pointer:coarse` are not width tiers, exempt.

**What reflows at each:** `--bp-lg` (≤1280) — marketing GateStrip and case-study grids reflow 6→3 columns (raising the reflow from `960` to `1280` fixes the confirmed `read-only` hyphen-break in the starved 961–1120 band). `--bp-md` (≤900) — masthead collapses to the vertical dropdown; app-shell rail collapses; dashboard grids and docs sidebar go single-column. `--bp-sm` (≤640) — everything single-column, 44px touch targets.

**Container/content width:** one token `--shell-max:1200px` referenced by `.topbar-inner` and `.main`; the 1440/1240 literals are deleted so header and content can no longer drift. **How a component declares responsive behaviour:** intrinsic-first — default to `flex-wrap` / `grid-template-columns: repeat(auto-fit, minmax(<floor>, 1fr))` / `clamp()`; a `@media` block is permitted only for a genuine column-count/axis reflow and only at the three custom-media tiers. Every marketing grid carries a `minmax()` floor so it can never collapse to one word per line.

---

## 4. Enforcement

Two gates, deliberately **decoupled**: a net-new **stylelint** CSS gate that is green day one and independent of the pre-existing red eslint, and an **eslint** inline-style rule that ships at `warn` so it never depends on the red baseline. Hard-gate exactly the three owner-locked scales (radius, colour, breakpoints); spacing/type/motion/z-index at `warning`.

New devDeps: `stylelint`, `stylelint-config-standard`, `stylelint-declaration-strict-value`, `postcss-custom-media`.

`stylelint.config.mjs`:
```js
export default {
  extends: ["stylelint-config-standard"],
  plugins: ["stylelint-declaration-strict-value"],
  rules: {
    // COLOUR (locked) — hex + the ~145 rgba/rgb/hsl literals color-no-hex can't see
    "color-no-hex": true,
    "scale-unlimited/declaration-strict-value": [
      ["/color$/", "background-color", "background", "border-color", "fill", "stroke", "box-shadow"],
      { ignoreValues: ["currentColor","transparent","inherit","none","0","initial","unset"], disableFix: true }
    ],
    // RADIUS (locked) — allow-list beats a disallow-lookahead; catches the 0 0 11px 11px shorthand
    "declaration-property-value-allowed-list": {
      "/^border(-[a-z]+)?-radius$/": ["/^var\\(--radius(-lg)?\\)$/", "999px", "50%", "0"]
    },
    // BREAKPOINTS (locked) — forces @media (--bp-*); a 4th width becomes un-typeable
    "media-feature-name-disallowed-list": ["min-width", "max-width"],
    // spacing/type (additive) — WARN only
    "declaration-property-value-disallowed-list": [
      { "/^(padding|margin|gap|font-size)$/": ["/\\b[0-9.]+px\\b/"] },
      { "severity": "warning" }
    ]
  },
  overrides: [
    { files: ["app/styles/tokens.css"],
      rules: { "color-no-hex": null, "scale-unlimited/declaration-strict-value": null,
               "media-feature-name-disallowed-list": null } }
  ]
};
```
`strict-value` on `background`/`box-shadow` closes the rgba-in-shorthand hole (`background: rgba(241,240,235,0.94)`, panel `box-shadow`); the flat identity makes box-shadow values `none` or `var(--shadow-overlay)`, both legal — the rare real gradient/image background takes a scoped disable comment.

`eslint.config.mjs` addition (WARN — no dependency on greening react-hooks):
```js
{ files: ["app/**/*.tsx"],
  rules: { "no-restricted-syntax": ["warn", {
    selector: "JSXAttribute[name.name='style'] Property[key.name=/^(color|backgroundColor|borderColor|fontSize|borderRadius|padding|margin|gap|boxShadow|zIndex)$/] > Literal",
    message: "Design values come from a token or class, not an inline literal."
  }]}}
```

`package.json`: `"lint:css": "stylelint 'app/**/*.css'"`. CI: a **new, separate** `web`-job step `- run: pnpm lint:css`, blocking, independent of the (still-red) `pnpm lint`. **Resolved disagreement — the breakpoint mechanism:** P3's `media-feature-name-value-allowed-list:{width:…}` is a no-op (zero `width`-feature queries exist) and P2's `grep -E` negative-lookahead fails on the dev's BSD grep; only P1's `media-feature-name-disallowed-list` + `@custom-media` is airtight, so that is what ships.

---

## 5. Masthead rebuild

**Confirmed mechanism:** `min-width:0` is already present (`globals.css:497`) — the owner's "missing min-width" hypothesis is refuted. The clip is a deliberate `overflow-x:auto; justify-content:center; scrollbar-width:none` (`:498-500`) + `::-webkit-scrollbar{display:none}` (`:507-509`), and `kernel.css:250-256` resets only `gap/padding/border/border-radius/background` — never those three — so a centre-justified hidden-scrollbar strip truncates both ends ("erview", "settin").

**Resolved disagreement — responsive technique:** reject P3's collapse-to-hamburger at ≤1280 (it hides primary nav on an ordinary 1024–1279 laptop). Adopt **Proposal 1's actions-yield grid** — the nav column takes its full intrinsic width and *cannot* clip; the actions cluster is the column that yields.

```css
.topbar-inner {
  max-width: var(--shell-max);           /* 1200 — collapses the three conflicting maxes */
  padding: 0 var(--space-6);
  display: grid;
  grid-template-columns: auto max-content 1fr;  /* brand | nav | actions */
  align-items: center; gap: var(--space-6);
}
.masthead-nav {                          /* single definition */
  display: flex; flex-wrap: nowrap; gap: var(--space-1);
  overflow: visible;                     /* the clip source — DELETED */
  justify-content: flex-start;           /* not center — center hides both ends */
}
.masthead-nav a { flex: 0 0 auto; min-height: 32px; padding: 0 var(--space-3); border-radius: var(--radius); }
.masthead-actions { justify-self: end; min-width: 0; }  /* the SHRINKING column; org/email already ellipsizes at 170px, then label→avatar */
```

Delete: `overflow-x/justify-content/scrollbar-width` + `::-webkit-scrollbar`; the off-scale `border:1px`/`border-radius:9px`/`background:rgba(255,254,250,0.64)` in the same block; the duplicate 760 block (`globals.css:4836`). Delete the **desktop `.topbar-action` New Run** (`Sidebar.tsx:172`) — it duplicates the page's own primary (`page.tsx:102`), reclaiming ~90px and enforcing one dark primary per view. Fix the **`.active` on cross-page hash anchors** (`Sidebar.tsx:105-118` — Resources/Activity link `/app#configuration` etc. yet carry the you-are-here class): demote to non-highlighting jump-links or promote to real routes.

**Plan:** `>900px` full inline nav (proof of fit at the tightest tier: brand ≈140 + nav max-content 7 items ≈450 + actions-min ≈90 + gaps ≈48 ⇒ ≈730 < 900, ~170px slack — structurally unclippable). `≤900px` the existing vertical dropdown (`kernel.css:1657-1743`, 44px targets, mobile New Run inside), its media query moved from `760` to `@media (--bp-md)`. A vertical stack cannot clip horizontally.

---

## 6. State system

**Resolved disagreement — the `ApiError` blast radius is FIVE throw sites, not two.** `api.ts:46,115,130,147,158` all throw bare `Error`; `apiPut/apiPatch/apiDelete` must be converted too or every `instanceof ApiError` branch silently falls through for writes. The `super()` message keeps the `${status}: …` shape so the existing `.message.startsWith("404")` consumer (`api.ts:504`) still works.

`app/lib/api.ts` — replace all five throw sites:
```ts
export class ApiError extends Error {
  constructor(readonly status: number, readonly detail: string) {
    super(`${status}: ${detail}`); this.name = "ApiError";
  }
  get kind(): "notFound" | "denied" | "unreachable" | "error" {
    if (this.status === 404) return "notFound";
    if (this.status === 401 || this.status === 403) return "denied";
    if (this.status === 0 || this.status >= 500) return "unreachable";
    return "error";
  }
}
```

**Four shared components** in `app/components/state.tsx` (kernel idiom — hairline card, `--elevation-flat`, lowercase title, `--font-mono` for codes):
- `<StateSkeleton rows>` — re-export the existing hairline shimmer `LoadingRows` (`bits.tsx:225`).
- `<StateEmpty title action>` — calm empty; lowercase title + one mono next-action. Copy example: title `"no runs yet"`, action `"create your first run →"`.
- `<StateError error onRetry>` — `role="alert"`, reads `error.kind`. Copy: `unreachable` → **"the control plane is unreachable. a failed read is not treated as empty."** + `Retry`; `denied` → **"your session expired."** + `sign in`; `notFound` delegates to `<StateNotFound>`; never renders `String(error)`.
- `<StateNotFound title href>` — charcoal `404` in `--font-mono`, lowercase title, one link home. No Retry.

**Rule everywhere:** guard first paint with `hasSnapshot`; skeleton while `!hasSnapshot`; `<StateError>` on a failed read (**never** the calm empty state); `<StateEmpty>` only after a fulfilled zero read. This fixes the one violator — `AutomationActivity` swallows its poll error (`AutomationPanel.tsx:273 } catch { /* keep last */ }`) then renders "No runs yet." (Note: the Overview em-dash at `page.tsx:85` is a defensible zero-state for an undefined completion rate — `hasSnapshot` already guards its loading path; leave it.)

**Four App-Router boundary files** (none exist today):

`app/app/loading.tsx`
```tsx
import { StateSkeleton } from "../components/state";
export default function Loading() { return <StateSkeleton rows={6} />; }
```
`app/not-found.tsx`
```tsx
import { StateNotFound } from "./components/state";
export default function NotFound() { return <StateNotFound title="page not found" href="/app" />; }
```
`app/(site)/not-found.tsx` (the copy the live `notFound()` in `docs/[slug]/page.tsx:40` + `docs/api/page.tsx:26` actually reaches)
```tsx
import { StateNotFound } from "../components/state";
export default function SiteNotFound() { return <StateNotFound title="page not found" href="/" />; }
```
`app/error.tsx` (Client)
```tsx
"use client";
import { StateError } from "./components/state";
export default function Error({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  return <StateError error={error} onRetry={reset} />;
}
```
Plus `app/global-error.tsx` (Client; replaces the root layout so it renders its own `<html>/<body>` and imports `tokens.css` directly, referencing only tokens — the one sanctioned inline-`style` file, and in stylelint `ignoreFiles`): lowercase "something broke" + a mono `500` + a reload button.

**Live-run fixes** (the product's centre screen, `sessions/[id]/page.tsx`, is silent to liveness/time/pauses): give `.timeline` (`:264`) `role="log" aria-live="polite" aria-relevant="additions"`; the pending-approval banner (`:229`) `role="alert"`; show the `streamReconnecting` chip regardless of `events.length` (today only inside the `=== 0` branch, `:261`); render a mono `timeAgo(occurred_at)` per row with absolute time in `title=` (`occurred_at` `api.ts:803` and `timeAgo` `bits.tsx:281` both already exist, unused). Add the dashboard skip link + `<main id="content">` (`app/app/layout.tsx:54`), mirroring the site layout.

---

## 7. CSS module split

Precondition: **collapse the override layers first, then split** — fold each `kernel.css` selector into its domain module (kernel's declaration is the winner kept), delete the internal "Nocturne" override zone (`globals.css:2952+`), the 72 dead classes, and the unused `@import "tailwindcss"` (no config, no `@apply`, no utilities consumed). Files live in `app/styles/`; a single `index.css` `@import`s them in the order below (tokens → base → dashboard → docs → marketing) so today's globals-then-kernel cascade is preserved. `layout.tsx` imports only `index.css`; `kernel.css` is deleted.

| # | File | Est. lines |
|---|---|---|
| 1 | `tokens.css` — merged `:root`/dark primitives + semantics + all new scales + `--st-*`/`--term-*` aliases + `@custom-media` | ~340 |
| 2 | `base.css` — reset, `html/body`, scrollbars, `::selection`, `*:focus-visible`, `.skip-link`, the single `prefers-reduced-motion` block | ~160 |
| 3 | `app-shell.css` — `.shell`, `.main`, `.topbar`, masthead (single defs), `.pagehead` | ~360 |
| 4 | `controls.css` — `.btn`, `.badge/.pill/.chip`, `.inp`, `.toggle`, tabs, `.modal`/`.overlay`, `.diff`, timeline, skeleton, state components | ~560 |
| 5 | `runs.css` — runs home, config overview, unified runs+automations, tables, row/list | ~700 |
| 6 | `composer.css` — agent/run composer, option cards, capability pins, pickers, schedule, automation contract | ~780 |
| 7 | `governance.css` — governance + connector catalog | ~480 |
| 8 | `integrations.css` — integrations store + connector modal | ~480 |
| 9 | `recipes.css` | ~250 |
| 10 | `docs.css` — `/docs` block | ~780 |
| 11 | `site-chrome.css` — marketing header/footer/announce, display type | ~500 |
| 12 | `site-home.css` — hero, ledger/terminal, GateStrip (with the new `minmax()` floor), logo wall | ~700 |
| 13 | `site-sections.css` — feature/use-case/case-study/quote/metric/OSS/architecture/CTA | ~700 |
| 14 | `site-pages.css` — pricing, changelog, security, responsive | ~480 |

Import order in `index.css`: `tokens → base → app-shell → controls → runs → composer → governance → integrations → recipes → docs → site-chrome → site-home → site-sections → site-pages`. Every file lands under the 800-line ceiling; each is single-domain; net LOC drops (dead code + tailwind removed).

---

## 8. Phase plan

Ordered so the machine gate exists before the bulk migration, the visible experience wins land early behind a provable no-op, and the risky refactor runs last against an already-cleaned, already-guarded surface. Each package has a **PROOF** measurement; if it fails, the package is not done. No phase depends on fixing the 15 red react-hooks errors.

**Phase 0 — Enforcement scaffold (decoupled).** stylelint + config in warn mode, `lint:css` script + separate blocking CI step, `postcss-custom-media`, inline-style eslint rule at `warn`. No CSS/TSX behaviour change. — **PROOF:** `git diff` touches only tooling; `pnpm lint:css` runs and prints baseline violation counts (radius N, colour M); rendered output byte-identical; react-hooks untouched.

**Phase 1 — Token union (provable no-op).** Build `tokens.css` as the *union* (kernel's winning values + the globals-only fonts/skeleton/canvas-glow); import first; delete the duplicate `:root`/dark blocks from globals and kernel. No component rule changed. — **PROOF:** dump `getComputedStyle` for every semantic token at `:root` and `[data-theme=dark]` before/after → **byte-identical**; 5-route × 2-theme screenshot diff = 0; a blank-font screenshot fails instantly (validates the union carried the fonts).

**Phase 2 — State system + live-run fixes (first experience win, CSS-independent).** `ApiError` at all five throw sites; the four boundary files; the four `<State*>` components; the `hasSnapshot` rule (fixes `AutomationActivity`); timeline `role="log"`/reconnect chip/`timeAgo`; approval `role="alert"`; skip link. — **PROOF:** `/app/sessions/deadbeef` → `<StateNotFound>` (not `Error: 404`); killed control plane → `<StateError role="alert">` (not "No runs yet."); a thrown render → styled `error.tsx`; `/docs/<garbage>` → styled `(site)` not-found; `find` shows ≥4 boundary files; `.timeline` reports `role="log"` and every row shows a `timeAgo` string.

**Phase 3 — Radius collapse.** Off-scale literals → `--radius`/`--radius-lg` by role; inline `borderRadius:7`; `--st-radius*`→alias. Flip the radius gate blocking. — **PROOF:** `stylelint` radius allow-list N→**0**; screenshot diff shows only intended ≤4px corner deltas, no layout shift.

**Phase 4 — Colour tokenization.** ~91 globals + 2 kernel component literals + all rgba → tokens; marketing swatches → `--term-*`; `var(--muted)`→`--ink-3`; delete the PixelIcon gold duotone; diff add/del → `--green`/`--red`. Flip the colour gate (`color-no-hex` + `strict-value`) blocking. — **PROOF:** both colour rules → **0** outside `tokens.css`; a computed-contrast check on `.diff .add`/`.del` in `[data-theme=dark]` ≥ 4.5:1 (today dark-on-dark).

**Phase 5 — Breakpoint contract + masthead rebuild.** `@custom-media`, 11→3, `--shell-max`, delete 1440/1240; rebuild the masthead per §5; GateStrip `minmax()` floor. Flip the breakpoint gate blocking. — **PROOF:** no non-{640,900,1280} media width committable (`media-feature-name-disallowed-list` green); at 640/900/1280/1440/1790 `.masthead-nav.scrollWidth <= clientWidth` AND computed `overflow-x !== auto` AND every nav label fully rendered (no "erview"); `querySelectorAll('.btn.primary').length <= 1` on `/app` and `/app/agents`; `.topbar-inner` computed `max-width === 1200`; no horizontal page scroll on any surface; GateStrip 3 columns with no `read-only` hyphen-break in 901–1280.

**Phase 6 — Override-collapse + module split.** Fold kernel in; delete Nocturne zone + 72 dead classes + tailwind import; split into the 14 files; `index.css`; delete `kernel.css`. — **PROOF:** a per-route `getComputedStyle` snapshot diff over a fixed selector set on every route = empty except intended token deltas; `wc -l app/styles/*.css` every file ≤ 800; top-level-selector `sort | uniq -d` = 0; `pnpm build` green; CSS bundle smaller.

**Phase 7 — Inline-style migration + additive scales + motion/a11y.** Replace the 51 inline `fontSize`/`color`/`borderRadius` with tokens/classes; spacing/type/motion/z-index migrated opportunistically (warn); one consolidated `prefers-reduced-motion` block covering `enter`+`fadein`; `SectionReveal` hides below-fold only and force-reveals on disconnect; `.sectitle` divs → real headings. — **PROOF:** `grep -rE 'style=\{\{[^}]*(fontSize|color|borderRadius):' app` = 0; under `prefers-reduced-motion` emulation `.home-hero` computes `animation-duration ≤ 1ms` and no section is stuck at `opacity:0` after a `#hash` jump; `grep -c '<div className="sectitle"'` = 0.

**Phase 8 — Enforcement lock.** Wire `pnpm lint:css` as a required blocking CI check. — **PROOF:** a demo PR that reintroduces a raw hex, an off-scale radius, a 4th media breakpoint, or an inline `fontSize` **fails CI**. The foundation is "done" only when regression has a cost.

---

## 9. Trades

- **Only the three owner-locked scales are hard-gated** (radius, colour, breakpoints). Spacing, type, motion, z-index and elevation ship as additive scales at `warning` and migrate opportunistically per touched file — they may converge slowly and a sub-pixel blur can linger. This is scope discipline matching the brief, not an oversight.
- **The 15 red react-hooks eslint errors are NOT fixed as a prerequisite.** They are runtime-behavioural changes in the run composer and policy editor — out of scope for a visual foundation and exactly the mid-flight exposure to avoid. The CSS gate is fully decoupled (own script, own CI job, green day one) and the inline-style rule ships at `warn`, so nothing in the foundation depends on greening eslint. Turning the inline rule to `error` is a separate, later track once someone greens react-hooks on its own merits.
- **No `bits.tsx` primitives library with type-level `style` prohibition.** Proposal 1's ~2,000-site primitive migration is dropped; the WARN eslint rule plus opportunistic class extraction achieves the same drift resistance at a fraction of the blast radius.
- **The masthead collapses inline nav only below 900px** (not 1280). A 1024–1279 laptop keeps the full inline nav; the cost is the actions cluster degrading its label to an avatar under width pressure (the org/email already ellipsizes). Rejected P3's collapse-at-1280, which hid primary nav on a common laptop width.
- **The token merge keeps kernel's values verbatim even where they differ from globals** (`--surface-soft` 0.94, `--surface-hover` `#eae7db`, dark `--accent-dim` `#b4e23e`) — it formalises runtime truth for zero pixel change, not a re-tuning of those three colours.
- **Snapping ~44 spacing and 32 type literals to grids loses hand-tuned pixels** — a coarser but enforceable rhythm; sub-pixel sizes (10.5/11.5/13.5) round, which is a genuine defect fix.
- **Marketing loses two intermediate breakpoints** (960/1060) and the 900–1280 band is slightly less optimal, but the tier set is closed and the GateStrip starvation is fixed.
- **Three CSS files sit near 800** (composer, docs, site-home) — deliberate; splitting a single coherent surface across files costs more in cross-file hunts than it saves.