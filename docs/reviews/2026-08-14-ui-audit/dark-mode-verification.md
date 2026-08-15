All claims verified. My recomputed contrast values match the auditor's within rounding; the non-contrast claims hold. Below is the verification report.

---

## Contrast recheck

Formula applied exactly as specified (sRGB→linear, `L=0.2126R+0.7152G+0.0722B`, `(L₁+0.05)/(L₂+0.05)`). Tints composited over their stated background in sRGB space before conversion. Thresholds: 4.5 body / 3.0 large-UI.

| pair | theme | claimed | recomputed | verdict |
|---|---|---|---|---|
| `--ink` on `--bg` | light / dark | 14.35 / 15.00 | 14.35 / 15.00 | ✅ match, pass both |
| `--ink-2` on `--bg` | light | 7.02 | 7.02 (globals `#4c5157`) / **8.19 (live kernel `#43474d`)** | ✅ number matches globals; see refutation #2 for the live value |
| `--ink-2` on `--bg` | dark | 8.64 | 8.64 | ✅ match |
| `--ink-3` on `--bg` | light / dark | 5.20 / 4.88 | 5.20 / 4.88 | ✅ match, pass both |
| `--ink-3` on `--surface` | light / dark | 5.63 / 4.46 | 5.63 / 4.46 | ✅ match; **dark 4.46 < 4.5 fails AA body** — confirmed |
| `--accent` on `--bg` | light / dark | 4.40 / 9.42 | 4.40 / 9.42 | ✅ match; light fails AA body — confirmed |
| `--accent` on `--surface` | light / dark | 4.76 / 8.60 | 4.76 / 8.60 | ✅ match, pass both |
| `--flood-ink` on `--flood` | both | 6.54 | 6.54 | ✅ match, pass both |
| `--primary-ink` on `--primary-bg` | light / dark | 13.93 / 14.12 | 13.93 / 14.12 | ✅ match, pass both |
| `--green` on `--bg` | light / dark | 4.40 / 9.42 | 4.40 / 9.42 | ✅ match; light fails AA body |
| `--green` on green-tint | light / dark | 3.96 / 7.22 | 3.95 / 7.24 | ✅ ±0.02 rounding, verdict unchanged (light fails) |
| `--red` on `--bg` | light / dark | 4.99 / 5.51 | 4.99 / 5.51 | ✅ match, pass both |
| `--red` on red-tint | light / dark | 4.34 / 4.71 | 4.33 / 4.72 | ✅ ±0.01 rounding, verdict unchanged (light fails) |
| `--amber` on `--bg` | light / dark | 4.29 / 8.29 | 4.29 / 8.29 | ✅ match; light fails AA body |
| `--amber` on amber-tint | light / dark | 3.83 / 6.36 | 3.82 / 6.36 | ✅ ±0.01, verdict unchanged (light fails) |
| `.product-label` `#60646c`/`#83888f` on chrome-bg | light / dark | 5.20 / 4.88 | 5.20 / 4.88 | ✅ match, pass both |
| `.masthead-nav` `#43474d`/`#b3b7bc` on chrome-bg | light / dark | 8.18 / 8.64 | 8.19 / 8.64 | ✅ ±0.01, pass both |
| **`.btn.danger:hover` `#faf9f2` on `--red`** | light / dark | 5.39 / 3.00 | 5.39 / 3.00 | ✅ match; **dark = 3.00, fails AA body** — confirmed |

**Every ratio in §3 is arithmetically sound.** No verdict flips. The largest deviation is 0.02 (compositing rounding). This audit's contrast math is trustworthy — a rare thing.

---

## Claims refuted

**1. "The single live cross-theme defect is `kernel.css:780`" / "The one real cross-theme literal bug" (§2 item 4, §2 headline).** REFUTED as an overstatement. The audit *chose to skip* `.diff .add {color:#1f6b49}` (globals.css:2220) and `.diff .del {color:#a33d36}` (globals.css:2224) because the brief pre-confirmed them — but those literals are in the **same theme-switched dashboard surface** (line 2220 < 5818), never flip, and I compute them on their own translucent backgrounds over dark `--surface`:
- `.diff .add #1f6b49` in dark → **2.14:1** (light: 5.67:1)
- `.diff .del #a33d36` in dark → **2.26:1** (light: 5.45:1)

Both are **worse than danger:hover's 3.00 and fail even the 3:1 large/UI floor.** So `kernel.css:780` is neither the single nor the worst live cross-theme literal defect. The audit was entitled to defer the `.diff` lines, but the sweeping "single defect / one real bug" phrasing is factually false given its own §3 method.

**2. §3 luminance-table row `--ink-2 (light) L=0.08109 → 7.02:1`.** Sourcing error (no verdict impact). `#4c5157` is the globals `:root` value, but `kernel.css` loads last and overrides `--ink-2` to `--ds-gray-900 = #43474d` (kernel.css:26,54), so the **dashboard** light value is `#43474d` → **8.19:1**, not 7.02:1. `#4c5157` is live only inside the forced-light marketing `.st` scope (globals.css:5917). Both pass AA, so the "pass both" verdict stands — but the stated number is the marketing value, not the dashboard-effective one. (The audit itself uses `#43474d` correctly one row down for `.masthead-nav`, so this is an internal inconsistency.)

Minor rounding notes (NOT refutations, no verdict change): green-on-tint dark 7.22→7.24; red-on-tint 4.34/4.71→4.33/4.72; amber-on-tint light 3.83→3.82; green-on-tint light 3.96→3.95; masthead light 8.18→8.19.

---

## Claims confirmed (brief)

All verified against source, verbatim:
- **Load order:** `globals.css` then `kernel.css` (layout.tsx:3-4). ✅
- **Literals:** `kernel.css:749` `color: #1c2024;` (`.btn.human` on `--gold`), `kernel.css:780` `color: #faf9f2;` (`.btn.danger:hover`). ✅
- **`.btn.primary` cascade-dead:** globals.css:1977 `color:#fffefa` + :1981 `background:#11100e` are overridden by globals.css:3319-3323 (`var(--primary-ink)`) and kernel.css:733. ✅
- **`--st-*` has no dark block:** declared at second `:root` globals.css:5818; `.st` re-pins app tokens to light at globals.css:5896-5919 (`--ink:#1c2024; --ink-2:#4c5157; …`). ✅
- **Token parity (§1):** every colour token in globals `:root` is redefined in `html[data-theme="dark"]`; `--flood`/`--flood-ink`/`--gold` intentionally identical across themes; geometry/fonts correctly not flipped. ✅
- **`themeColor`:** single value `"#f2f0e7"` (layout.tsx:60), no `media` array; `syncBrowserChrome` patches `<meta theme-color>` post-hydration only (ThemeToggle.tsx:15-19). ✅
- **Pre-paint theme:** `THEME_INIT_SCRIPT` sets `dataset.theme` + `colorScheme` synchronously (theme.ts:15-17, injected layout.tsx:84); SSR `data-theme="light"` (layout.tsx:79) vs `useState("dark")` (ThemeToggle.tsx:33) mismatch, hidden by `suppressHydrationWarning`. ✅
- **Mermaid freeze:** reads `dataset.theme` once (MermaidBlock.tsx:15), `theme: dark?"dark":"neutral"` (:21), effect deps `[text, reactId]` — no theme (:34). ✅
- **Orphans:** `Sidebar.tsx` renders only `product-label`/`masthead-nav`; `workspace-context`/`navlink`/`workspace-avatar` have **zero** `.tsx` consumers (grep empty). ✅
- **`ArchitectureDiagram`:** no import site anywhere in `app/` (grep empty) — latent. ✅
- **Docs theme:** `docs/layout.tsx` uses `.site-container.docs-outer`/`.docs-shell`, no `.st` wrapper — so `/app → /docs` is theme-consistent; the seam is `/app → /` (marketing). ✅
- **PixelIcon:** gradient `stopColor="#81b300" … "#cab168"` — brand mark, theme-independent. ✅

Adjacent note: the brief's "toggle says 'Dark'/'Night'" is stale — the button labels the **next** theme: `{theme==="dark" ? "Light" : "Dark"}` (ThemeToggle.tsx:73), so "Light" in dark mode. Not an audit claim, so not scored.

---

## Net corrected finding list (priority order)

1. **`.diff .add` / `.diff .del` dark-mode illegibility — globals.css:2220, 2224.** `color:#1f6b49` / `#a33d36` never flip; on their tinted backgrounds over dark `--surface` they compute to **2.14:1 / 2.26:1**, failing even the 3:1 bar. This is the **most severe live cross-theme literal** in the dashboard surface — the audit demoted it to a skipped footnote. Tokenise both (e.g. a themed `--diff-add-ink`/`--diff-del-ink`).
2. **`.btn.danger:hover` — kernel.css:780.** `#faf9f2` on dark `--red #e0705c` = **3.00:1**, fails AA body. Replace the literal with an on-red token. (Confirmed as stated, just not "the single" defect.)
3. **Dark `--ink-3 #83888f` on `--surface` — globals.css:81.** **4.46:1**, fails AA body for muted/secondary text on dark cards. Nudge lighter.
4. **Light-theme accent family — globals.css:29/32/35 (`--accent`/`--amber`/`--green`).** `#567a00` = 4.40 on bg / 3.95 on tint; `#8a6d1c` = 4.29 on bg / 3.82 on tint — all fail AA body. Light-mode issues surfaced by the parity pass; darken or reserve for large/UI text.
5. **`layout.tsx:60` — `themeColor:"#f2f0e7"` has no dark counterpart.** Browser/PWA chrome stays light beige on first paint / no-JS / non-toggle routes. Make it a `media`-keyed array.
6. **`MermaidBlock.tsx:34` — theme absent from effect deps.** Docs diagrams freeze their palette on live toggle. Add resolved theme + re-render on `fluidbox:theme-change`.
7. **`--st-*` system has no dark block — globals.css:5818.** Structural fragility (no leak found today); any `--st-*` value reaching a themed surface renders near-black on charcoal.

Bonus (as the audit noted): orphaned light-only `.workspace-context`/`.navlink`/`.workspace-avatar` (globals.css:320-412) are unreachable from the current `Sidebar.tsx` masthead — dead code, latent dark landmine.