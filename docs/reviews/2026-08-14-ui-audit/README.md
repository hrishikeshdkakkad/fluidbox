# fluidbox web UI audit — 2026-08-14

Evidence for a foundation pass on `apps/web`. Produced by a 34-agent audit in which every
finding was sent to an adversarial verifier that reopened the cited file and tried to refute
it. Read `CORRECTIONS` below before using any of it.

| file | what it is |
|---|---|
| `foundation-spec.md` | The synthesised foundation specification — token contract, breakpoint contract, enforcement config, masthead rebuild, state system, module split, 9 phases each with a proof measurement, and the trades it knowingly makes. |
| `findings.json` | 85 findings that survived verification, plus the 6 refuted with reasons. Fields: title, dimension, severity, file, line, evidence (verbatim), user_impact, fix, effort, correction. |
| `dark-mode-audit.md` | Dark-mode parity: token diff, non-flipping colour inventory, contrast arithmetic, theme-application review. |
| `dark-mode-verification.md` | Independent recomputation of every contrast ratio in the above. All agreed to within 0.02. |
| `judge-completability.md` | Scored three competing foundation proposals on "can this be finished without breaking the product mid-flight". |
| `judge-experience.md` | Scored the same three on "does this serve the developer using fluidbox". |

## CORRECTIONS — these claims are wrong, do not act on them

1. **The theme toggle is NOT broken.** An earlier note claimed it says "Dark" in light mode and
   "Night" in dark mode. False. `ThemeToggle.tsx:73` is
   `{theme === "dark" ? "Light" : "Dark"}` with an `aria-label` of "Use <next> theme" — it
   correctly labels the theme being switched *to*. The claim came from misreading a
   low-resolution screenshot and was then supplied to all 34 agents as an established premise.

2. **"91 literal colours never flip in dark mode" is much narrower than stated.** `kernel.css`
   loads after `globals.css` and re-declares most dashboard colours *through tokens*, so a
   large share of those 91 are cascade-dead. The live cross-theme failures number about four.

3. **`min-width: 0` is present on the masthead nav** (`globals.css:497`). The clipping is not a
   missing `min-width`; it is a deliberate `overflow-x: auto` + `justify-content: center` +
   `scrollbar-width: none` that `kernel.css:250-256` never resets.

4. **`--ink-2` light contrast is 8.19, not 7.02.** `kernel.css:54` overrides the globals value
   to `#43474d`. Passes AA either way.

## Measured facts worth keeping

Masthead, measured live across 13 viewport widths: nav truncation shrinks as the screen widens
but **plateaus at 28px** — identical at 1280, 1400 and 1790, because `.topbar-inner` is capped
at `max-width: 1240px`. The desktop masthead has never fit at any width. Horizontal page scroll
of 12–18px exists below 1280. Mobile (390/640) is the healthiest tier; **860–1280 is a dead
zone** where the desktop masthead is active but does not fit.

Contrast failures, computed three times independently and agreeing:

| pair | light | dark | note |
|---|---|---|---|
| `.diff .add` `#1f6b49` on its tint | 5.68 | **2.13** | worst in the product; fails even the 3:1 non-text floor |
| `.diff .del` `#a33d36` on its tint | 5.45 | **2.26** | same |
| `.btn.danger:hover` `#faf9f2` on `--red` | 5.39 | **3.00** | fails AA body |
| `--ink-3` on `--raised` | 4.79 | **3.97** | muted text on dark cards |
| `--ink-3` on `--surface` | 5.63 | **4.46** | marginal |
| `--accent` on `--bg` (39 text uses) | **4.40** | 9.42 | light only |
| `--amber` on `--bg` (8+ text uses) | **4.29** | 8.29 | light only |

Suggested values that clear AA while preserving hue and saturation: `--accent` `#557800`,
`--amber` `#866a1b`, dark `--ink-3` `#8d9298`. The `.diff` colours should become
`var(--green)` / `var(--red)`, which already flip.

## Caveats on the finding count

Roughly 40% of the 85 are `low` severity and a meaningful share are taste that survived because
the verifier's bar was "is this real", not "does this matter". A realistic estimate is **~20
findings genuinely worth fixing, of which about 4 are user-visible**: the diff colours in dark
mode, the nav eating its own labels, a deleted run rendering as an outage, and the docs copy
button being invisible on touch devices. Treat 85 as an inventory, not a mandate.

The two runs of the same audit produced 85 and 84 confirmed findings — the verification stage
is not perfectly deterministic. Counts are ±1.
