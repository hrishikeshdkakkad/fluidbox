I have enough evidence. Compiling the report now.

## Dark-Mode Parity Audit — `apps/web`

Static analysis only. Every ratio in §3 was computed by hand from the sRGB→linear→WCAG formula given; none are guessed. A key structural fact governs the whole report: **`kernel.css` loads after `globals.css` (`app/layout.tsx:3-4`) and re-declares most dashboard component colours using tokens** (it is almost literal-free — only two hardcoded colours survive in its component rules, `kernel.css:749` and `:780`). So a large share of the ~91 raw literals in the pre-`5818` dashboard block are *cascade-dead* — overridden by a token-based rule in `kernel.css`. I flag which are live and which are not, because it changes the priority order completely.

---

## 1. Token diff

Four declaration sites define tokens:

| Site | File:line | Has a dark variant? |
|---|---|---|
| App tokens `:root` | `globals.css:11` | yes — `html[data-theme="dark"]` `globals.css:69` |
| App tokens (override) `:root` | `kernel.css:14` | yes — `html[data-theme="dark"]` `kernel.css:86` |
| Marketing `--st-*` `:root` | `globals.css:5818` | **NO dark block anywhere** |
| Marketing scope re-pin `.st { … }` | `globals.css:5894-5919` | n/a — deliberately re-pins the *app* tokens back to light |

### globals.css `:root` (11) vs dark (69) — colour parity

Every colour-bearing token in `:root` **is** redefined in the dark block. I checked each: `--bg`, `--surface`, `--raised`, `--surface-soft/-hover`, `--border(-strong)`, `--ink/-2/-3`, `--accent(-dim/-tint)`, `--amber(-tint)`, `--green(-tint)`, `--red(-tint)`, `--chrome-bg`, `--interactive-subtle/-hover`, `--control-bg`, `--primary-bg/-hover/-ink`, `--overlay-bg`, `--selection-bg`, `--scrollbar(-hover)`, `--modal-shadow`, `--skeleton-a/b` — all present in both.

**Defined in `:root` but NOT redefined in dark — and correctly so (they must not flip):**
- `--font-sans/-mono/-display/-jp/-sc` (`globals.css:57-61`) — non-colour.
- `--radius: 4px`, `--radius-lg: 8px`, `--hairline: 0.5px` (`globals.css:64-66`) — geometry, correct to inherit.

**Redefined in dark but to an identical value (intentional theme-independence):**
- `--flood: #81b300` (`:27` / `:83`), `--flood-ink: #1c2024` (`:28` / `:84`), `--gold: #cab168` (`:34` / `:90`). The chartreuse brand flood and its charcoal ink are the same in both themes by design (the flood is the resource-identity colour; §3 shows charcoal-on-chartreuse clears AA both ways at 6.54).

**Exists only in dark:** none. The dark block is a strict subset-with-overrides — nothing new is introduced.

Verdict: the app-token pair is clean. No colour token is stranded un-flipped.

### kernel.css `:root` (14) vs dark (86)

Same story, expressed through a `--ds-*` primitive layer that both blocks fully mirror (`kernel.css:16-44` vs `:88-114`), then mapped to identical semantic names. Cross-checking the semantic outputs against globals' dark:

| token | globals dark | kernel dark | agree? |
|---|---|---|---|
| `--ink` | `#edeef0` (`:79`) | `var(--ds-gray-1000)`=`#edeef0` (`:99,123`) | ✅ |
| `--ink-2` | `#b3b7bc` (`:80`) | `#b3b7bc` (`:98,124`) | ✅ |
| `--ink-3` | `#83888f` (`:81`) | `#83888f` (`:96,125`) | ✅ |
| `--accent` | `#9ccf1f` (`:85`) | `#9ccf1f` (`:107,128`) | ✅ |
| `--red` | `#e0705c` (`:93`) | `#e0705c` (`:113,136`) | ✅ |

**kernel.css omits some globals tokens** — `--skeleton-a/b`, `--canvas-glow`, and the `--font-*` family are not declared in `kernel.css`. They resolve from the globals `:root`/dark blocks (still theme-correct), so this is harmless but is real drift between the two "same" systems.

### The `--st-*` system (5818) — the real disagreement

`--st-*` has **no dark counterpart and never flips**. `--st-ink: #1c2024` (`globals.css:5822`), `--st-body: #3d4147` (`:5823`), `--st-bg: #f2f0e7` (`:5819`) stay near-black-on-beige in dark mode. This is intentional — the marketing surface re-pins the app tokens back to light inside `.st { … --bg:#f2f0e7; --ink:#1c2024; … }` (`globals.css:5907-5918`) so the marketing pages are light-only. The three systems therefore **do not agree in dark mode by design**: two flip, one is frozen light. The risk is purely leakage — any `--st-*` value that reaches a themed surface (dashboard/docs) would render near-black text on a dark canvas. I found no such leak (docs uses the app tokens, not `--st-*`), but the fragility is structural.

---

## 2. Colour that cannot flip (literals in component rules)

Skipping the two known `.diff` lines. I split by whether the rule is actually reachable.

### A. Live and theme-independent (correct — dark text on a light-in-both-themes chip)
| # | Where | file:line | verbatim | surface | dark-legible? |
|---|---|---|---|---|---|
| 1 | `.masthead-count` on `var(--gold)` | `globals.css:545` | `color: #1c2024;` | masthead chrome (live) | ✅ gold `#cab168` in both themes; charcoal-on-gold reads |
| 2 | `.btn.human` on `var(--gold)` | `kernel.css:749` | `color: #1c2024;` | dashboard buttons (live) | ✅ same |
| 3 | `PixelIcon` logo gradient | `app/(site)/components/PixelIcon.tsx:139-140` | `stopColor="#81b300"` … `"#cab168"` | brand mark, both surfaces | ✅ brand identity, theme-independent |

### B. Live and genuinely at risk in dark
| # | Where | file:line | verbatim | surface | dark-legible? |
|---|---|---|---|---|---|
| 4 | `.btn.danger:hover` | `kernel.css:780` | `color: #faf9f2;` | dashboard danger button hover | ⚠️ near-white on `--red` which in dark is the *light* coral `#e0705c` → **3.00:1**, fails AA body (see §3). The one real cross-theme literal bug. |

### C. Marketing surface — always light by design, so literals are correct there
These sit inside the `.st`-scoped, forced-light marketing pages, or are deliberately-dark "screenshot" islands on that light page. Not dark-mode bugs, but they are the bulk of the post-`5818` literals:
- Deliberately-dark demo cards: `.st-stage-card { background:#26282c }` `globals.css:6483`, `.st-stage-tool { color:#ecedf3 }` `:6524`, `.st-stage-policy pre { color:#b0b1c0 }` `:6560`, `.st-chipbtn { color:#edeef0 }` `:6547`. (Note `.st-stage-head .ttl` uses `--st-faint #82868e` on `#26282c` ≈ low contrast even on the light page.)
- Dark bands: `.st-day { background: var(--st-charcoal) }` `:7157` with `.st-day .site-kicker { color:#83888f }` `:7162`, `.st-day .tt { color:#9ccf1f }` `:7168`.
- Film poster: `.st-film-body { background:#191a1c }` `:6597`, `.st-film-cover { background:#212225 }` `:6614`.
- Architecture SVG assumes light paper: `.arch-box { fill:#faf9f2 }` `:7420`, `.arch-inner { fill:#f2f0e7 }` `:7431` (see §5 — `ArchitectureDiagram.tsx` has no import site I could find; if it were ever mounted in themed docs it would be light-boxes-on-dark).

### D. Cascade-dead or orphaned (present in source, not reachable on the live UI)
- `.btn.primary { color:#fffefa }` `globals.css:1977` and `.btn.primary:hover { background:#11100e }` `:1981` — overridden by a later same-selector rule `.btn.primary { background:var(--primary-bg); color:var(--primary-ink) }` `globals.css:3320-3322` and again in `kernel.css:735+`.
- `.workspace-context { background: rgba(255,254,250,0.72) }` `globals.css:328`, `.workspace-avatar { background:#dedbd2 }` `:335`, `.navlink:hover { background: rgba(38,35,31,0.045) }` `:384`, `.navlink.active { background: rgba(38,35,31,0.07) }` `:388` — near-white panel / dark-ink overlays that would be illegible in dark (white panel with `var(--ink)`=near-white text; hover tints invisible on a dark canvas). **But the live shell is a top masthead**: `Sidebar.tsx` renders only `product-label` and `masthead-nav` (`Sidebar.tsx:90,94`); `workspace-context`/`navlink` have no `.tsx` consumer I could find. Latent, not currently rendered — worth deleting, low user-facing priority.
- `.masthead-nav { background: rgba(255,254,250,0.64) }` `globals.css:505` — overridden by `kernel.css:255` `background: transparent`.

**Headline for §2:** because `kernel.css` re-tokenises the dashboard, the scary-sounding 91 literals are mostly dead or marketing-only. The single live cross-theme defect is `kernel.css:780`.

---

## 3. Contrast arithmetic (WCAG, computed)

Method per pair: `s=v/255`; `lin = s/12.92 if s≤0.03928 else ((s+0.055)/1.055)^2.4`; `L = 0.2126R+0.7152G+0.0722B`; `ratio=(L1+0.05)/(L2+0.05)`. Thresholds: **4.5** body, **3.0** large-text / UI.

Computed luminances (L):

| token | light L | dark L |
|---|---|---|
| `--bg` | 0.8697 | 0.01029 |
| `--surface` | 0.9449 | 0.01601 |
| `--ink` | 0.01407 | 0.8545 |
| `--ink-2` | 0.08109 | 0.4708 |
| `--ink-3` | 0.12686 | 0.2442 |
| `--accent`/`--green` | 0.15895 | 0.5179 |
| `--flood` | 0.36907 | 0.36907 |
| `--flood-ink` | 0.01407 | 0.01407 |
| `--red` | 0.13450 | 0.2821 |
| `--amber` | 0.16423 | 0.4500 |
| `--primary-bg` | 0.01601 | 0.8545 |
| `--primary-ink` | 0.8697 | 0.01407 |
| green-tint (composited on bg) | 0.7771 | 0.02870 |
| red-tint (on bg) | 0.7501 | 0.02056 |
| amber-tint (on bg) | 0.7709 | 0.02860 |

### Ratios

| pair | LIGHT | DARK | verdict |
|---|---|---|---|
| `--ink` on `--bg` | **14.35** | **15.00** | pass both |
| `--ink-2` on `--bg` | **7.02** | **8.64** | pass both |
| `--ink-3` on `--bg` | **5.20** | **4.88** | pass both (body) |
| `--ink-3` on `--surface` | **5.63** | **4.46** | ⚠️ **DARK fails AA body** (4.46<4.5), passes large/UI. Light OK |
| `--accent` on `--bg` | **4.40** | **9.42** | ⚠️ **LIGHT fails AA body**, passes large/UI. Dark fine |
| `--accent` on `--surface` | **4.76** | **8.60** | pass both |
| `--flood-ink` on `--flood` | **6.54** | **6.54** | pass both |
| `--primary-ink` on `--primary-bg` | **13.93** | **14.12** | pass both |
| `--green` on `--bg` | **4.40** | **9.42** | ⚠️ **LIGHT fails AA body** |
| `--green` on green-tint | **3.96** | **7.22** | ⚠️ **LIGHT fails AA body** (status-pill text), passes large. Dark fine |
| `--red` on `--bg` | **4.99** | **5.51** | pass both |
| `--red` on red-tint | **4.34** | **4.71** | ⚠️ **LIGHT fails AA body** (4.34<4.5). Dark passes |
| `--amber` on `--bg` | **4.29** | **8.29** | ⚠️ **LIGHT fails AA body** |
| `--amber` on amber-tint | **3.83** | **6.36** | ⚠️ **LIGHT fails AA body** (status text), passes large. Dark fine |
| `.product-label` (`--ds-gray-700`) on chrome-bg | **5.20** | **4.88** | pass both (11px mono → body threshold) |
| `.masthead-nav a` (`--ds-gray-900`) on chrome-bg | **8.18** | **8.64** | pass both |
| **`.btn.danger:hover` `#faf9f2` on `--red`** | **5.39** | **3.00** | ⚠️ **DARK fails AA body** (exactly 3.00; button label), passes large/UI only |

### The pattern that matters
Contrary to the usual "dark mode is the neglected one" expectation, **the light theme carries most of the small-text failures** — `--accent`/`--green`/`--amber` status and link text on `--bg` and on their own tints all land in the 3.8–4.4 band (pass 3:1, fail 4.5:1). The dark theme flips brighter accents in and clears those, but introduces its own two: **`--ink-3` on `--surface` at 4.46** (secondary/muted text on cards) and **`.btn.danger:hover` at 3.00**. All failures are ≥3:1, so nothing fails the large-text / UI-component bar — but any of these used at ≤~16px regular weight is a genuine AA body failure.

---

## 4. Theme application

Reading `app/lib/theme.ts`, `ThemeToggle.tsx`, `layout.tsx`:

- **Before first paint?** Yes. `THEME_INIT_SCRIPT` (`theme.ts:15-17`) is injected synchronously into `<head>` via `dangerouslySetInnerHTML` (`layout.tsx:84`), so `document.documentElement.dataset.theme` and `.style.colorScheme` are set while the document is still parsing. **No FOUC** for the theme itself.
- **One caveat — a wrong-theme static shell exists.** `<html … data-theme="light">` is hardcoded in the server render (`layout.tsx:79`), and `ThemeToggle` seeds `useState<Theme>("dark")` (`ThemeToggle.tsx:33`). The inline script corrects `data-theme` before paint, and `suppressHydrationWarning` (`layout.tsx:81`) hides the mismatch. So the *attribute* is right pre-paint, but the initial React state (`"dark"`) and the SSR attribute (`"light"`) disagree with each other and with reality until `useEffect`→`sync()` runs (`ThemeToggle.tsx:52`). The toggle's own label can therefore render momentarily wrong, though the page colours do not flash.
- **Persistence?** Yes — `localStorage["fluidbox-color-theme"]` (`theme.ts:3`), written on click (`ThemeToggle.tsx:25`), read by the init script and by `resolveTheme` (`theme.ts:6-9`). Cross-tab sync via a `storage` listener (`ThemeToggle.tsx:47-50`).
- **`prefers-color-scheme` for a first-time visitor?** Respected. With no stored value, `resolveTheme` and the init script both fall back to `matchMedia("(prefers-color-scheme: dark)")` (`theme.ts:8,17`). Light is **not** forced (the `data-theme="light"` in `layout.tsx:79` is overwritten by the script before paint). Live OS changes are followed only while unset (`followSystem`, `ThemeToggle.tsx:42-45`).
- **`color-scheme` set?** Yes, twice: the init script sets `d.style.colorScheme=t` (`theme.ts:17`) and `applyTheme` sets `root.style.colorScheme` (`ThemeToggle.tsx:24`); CSS also pins `color-scheme: light` / `dark` (`globals.css:125,130`; `kernel.css:154,159`). Native controls, form widgets and scrollbars follow the theme.
- **`themeColor` dark counterpart?** **No — this is a gap.** `viewport.themeColor` is a single value `"#f2f0e7"` (`layout.tsx:60`), the *light* beige, with no `media`-keyed dark entry. `ThemeToggle.syncBrowserChrome` patches the live `<meta name="theme-color">` to `#191a1c` in dark (`ThemeToggle.tsx:15-19`) — but that runs only after hydration and only in the dashboard where `ThemeToggle` mounts. On first paint, on any route that doesn't mount the toggle, and before JS, the mobile browser chrome / PWA status bar stays **light beige even in dark mode**. The fix is a `themeColor: [{media:"(prefers-color-scheme:dark)",color:"#191a1c"}, {media:"(prefers-color-scheme:light)",color:"#f2f0e7"}]` array so the browser picks correctly with zero JS.

---

## 5. Assets and the surface boundary

- **Marketing (`(site)`) surface is light-only, by construction.** Every marketing page wraps content in `.st`, which re-pins the app tokens back to beige (`globals.css:5894-5919`: `--bg:#f2f0e7; --ink:#1c2024; …`). `page.tsx`, `product/page.tsx`, `pricing/page.tsx`, `open-source`, `security`, `changelog`, plus `SiteHeader`/`SiteFooter` all use `.st` (confirmed by grep). So a dark-mode dashboard user who clicks from `/app` to `/`, `/product`, or `/pricing` **lands on a bright beige page** regardless of their saved dark preference — a hard light/dark seam at the dashboard↔marketing boundary. The shared header/footer pin their own colours, so even the chrome doesn't carry the dark theme across.
- **Docs (`(site)/docs`) DO theme.** `docs/layout.tsx` uses `.site-container.docs-outer` / `.docs-shell` (`docs/layout.tsx:19-24`) — no `.st` wrapper — so docs render on the theme-switched app tokens. **Therefore the specific path in the brief, `/app → /docs`, is consistent** (both dark). The jarring jump is `/app → /` (marketing), not `/app → /docs`.
- **Mermaid diagrams assume-and-freeze a theme.** `MermaidBlock.tsx:15` reads `dataset.theme` once at mount and initialises mermaid `theme: dark ? "dark" : "neutral"` (`:21`). The effect deps are `[text, reactId]` (`:34`) — **not** the theme — so if a user toggles theme while a docs page with a diagram is open, the SVG keeps its old palette (light "neutral" boxes on the now-dark page, or vice-versa) until a reload. First render is correct because the init script set `data-theme` pre-paint; the bug is only on live toggle.
- **Architecture SVG hardcodes light fills.** `.arch-box{fill:#faf9f2}` (`globals.css:7420`), `.arch-inner{fill:#f2f0e7}` (`:7431`), `.arch-db{fill:#faf9f2}` (`:7436`). `ArchitectureDiagram.tsx` lives in `(site)/components` but I found no import of it — if it is marketing-only it is fine (always-light surface); if it is ever mounted in themed docs it becomes light boxes on a dark canvas. Flagging as latent.
- **Raster assets are theme-blind.** `og.png` (`layout.tsx:50`) and the hero `<video>` poster / `<img>` on `product/page.tsx:110` / `HeroFilm.tsx:30` are single fixed images; the film chrome is a designed dark cover (`.st-film-body #191a1c`, `:6597`) which is fine, but OG/hero imagery is authored for the light brand and does not adapt.

---

## Top five to fix first

1. **`kernel.css:780** — `.btn.danger:hover { color:#faf9f2 }` gives 3.00:1 on the dark-theme coral `--red`; replace the literal with a token (e.g. `var(--primary-ink)` / a dedicated on-red token) so the danger button label clears AA body in dark.
2. **`app/layout.tsx:60** — `themeColor: "#f2f0e7"` has no dark counterpart; make it a `media`-keyed array (`#191a1c` for dark) so browser/PWA chrome is correct on first paint without JS.
3. **`globals.css:5829 / :35 / :32** — the light-theme accent/green `#567a00` fails AA body on `--bg` (4.40) and on its tint (3.96); darken the light `--accent`/`--green` (and `--amber #8a6d1c`, 4.29) or reserve them for large/UI text only. This is a *light*-mode fix surfaced by the parity audit.
4. **`globals.css:81** — dark `--ink-3: #83888f` is 4.46:1 on `--surface`; nudge it lighter (toward `#8b9097`) so muted/secondary text on dark cards clears 4.5.
5. **`MermaidBlock.tsx:34** — add the resolved theme to the effect deps (and re-render on the `fluidbox:theme-change` event) so docs diagrams re-theme on toggle instead of freezing at mount; while there, tokenise `ArchitectureDiagram`'s `fill:#faf9f2/#f2f0e7` (`globals.css:7420,7431`) if it is ever shown in docs.

Bonus cleanup (not top-five): delete the orphaned light-only `.workspace-context`/`.navlink`/`.workspace-avatar` rules (`globals.css:320-412`) — unreachable from the current `Sidebar.tsx` masthead, and a latent dark-mode landmine if reintroduced.