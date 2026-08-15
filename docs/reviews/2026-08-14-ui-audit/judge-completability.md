I have what I need. The masthead grid, the documented anti-bleed history, the eslint red-state, the duplicate-selector counts, and the absence of any Playwright harness are all confirmed against the tree. Verdict below.

---

# Axis: completability without visible mid-flight breakage — which proposal survives the trapeze, and each one's riskiest step

## Scores

| Proposal | Score /10 |
|---|---|
| **P1 (strict)** | **5** |
| **P2 (safe)** | **9** |
| **P3 (dx)** | **6** |

The axis rewards: a regression net that exists *before* the risky edit, keeping battle-tested structure, sequencing the biggest mechanical edit last under that net, and never shipping a known-broken intermediate. It punishes: max blast radius, proofs that are green-but-blind, and re-litigating a fix the codebase already earned.

---

## P1 (strict) — 5/10

**Strongest idea:** the closed set lives in exactly one file and *the wrong value no longer compiles* — `stylelint declaration-strict-value` for CSS **plus `tsc --noEmit` on closed `variant`/`size` unions with no `className`/`style` escape on `Button`/`Card`**. That compile-time component-API guarantee (c.3) is the single most durable anti-drift mechanism in any of the three; neither other proposal fully matches it.

**Worst idea:** the stated thesis — *"maximum up-front churn… touches nearly every `.tsx` and every CSS rule."* That is the antithesis of this axis, and it comes with **no automated visual net**. Package 1's proof is a manual "screenshot 8 routes, pixel-diff ≈ 0"; the mass Package 3 migration's *only* proof is "stylelint 0 errors." Stylelint proves no literal survives — it does **not** prove the token you mapped to is the visually correct one. A mis-map (`#ffffff`→`--surface` where the role was `--primary-ink`) passes the green gate and ships a regression.

**Single riskiest step: Package 3 — rewriting all ~91 colours + 44 spacings + 32 font-sizes + radii/borders/motion/z in one package, gated only by a linter.** A wrong token map is invisible to stylelint, and because it's one giant commit it's hard to bisect. Secondary: the **collapse-at-900 masthead is arithmetically holed.** P1's fit proof (§d) sums `brand 150 + nav 448 + actions 230 = 828 < 852` — but it omits the grid's two `gap: 20px`/`24px` inter-track gaps, and uses 448px for the nav when the *confirmed* finding #1 measures the 7-item nav at **510px**. Real total ≈ `150 + 510 + 230 + 48 = 938` vs 852 available. P1 keeps the inline nav down to 900px, so it would re-clip/bleed across the 900–1050px band — the exact confirmed-defect zone. P1 is the only proposal whose masthead fix can visibly break in normal laptop widths.

---

## P2 (safe) — 9/10

**Strongest idea:** *"build the net before the trapeze."* Phase 0 stands up visual goldens (route × {light,dark} × {640,900,1280}) **and** report-only violation counters *before any risky edit*, and every guard flips report-only→failing only *after* its migration lands (so a gate never blocks its own cleanup). Phase 2 even predicts the exact diff — *"light snapshots identical; dark diff **exactly** on `.diff .add/.del` + the 2 kernel strays; all else identical"* — which is the correct use of a golden net: separating the intended fix from a regression. This is the plan literally engineered for this axis.

It also makes the two safest structural calls: it **keeps the battle-tested `auto minmax(0,1fr) auto` masthead grid** (confirmed at `globals.css:466` / `kernel.css:220`, whose comment documents that this shape was the deliberate fix for actions bleeding over the nav), and it **collapses the whole nav to the hamburger at 1280** so the nav physically cannot clip in the sub-1280 band. The split (Phase 7) — the single biggest mechanical edit, and the real de-dup problem is real (`.resource-card` is defined **9×** in globals + **3×** in kernel; `.btn.primary` 8+2) — runs **last, under the fully-armed net**, proven byte-comparable to Phase-0 goldens. That is the safest possible placement.

**Worst idea:** staking the plan's entire safety on **"byte-identical" golden snapshots** is oversold. The chrome uses `backdrop-filter: saturate(140%) blur(14px)` (`kernel.css:207`) and `next/font`; subpixel AA + blur make true byte-identity unreliable, so the no-op proofs (Phases 1, 7) need a masked/threshold diff, not equality. Minor second: the masthead's `overflow: clip` backstop could silently re-truncate if a future locale ever overflows the 74px slack — the 1280 collapse alone is the real guarantee; the clip is a footgun.

**Single riskiest step: Phase 0's golden fidelity — the one link everything else hangs from.** The riskiest *edit* (Phase 7 split) is the best-protected; the riskiest *dependency* is that the goldens are trustworthy. If snapshot noise (blur/AA/font hinting) isn't masked, the "prove it's a no-op" bracket around consolidation and the split can't cleanly distinguish a real regression from render noise, quietly eroding the net every later phase leans on. This is a calibration fix (threshold + mask the blurred bar), not a structural flaw.

---

## P3 (dx) — 6/10

**Strongest idea:** the state system. `ApiError` with a typed `kind` getter (`notFound`/`forbidden`/`unreachable`/`server`) is the most complete error model of the three, `error.tsx` correctly branches on `error.name === "ApiError"`, and it explicitly **declines Next 16's experimental `global-not-found.tsx` flag** in a migration-safety pass — the right call. `--muted` (referenced once at `capabilities/page.tsx:343`, confirmed defined nowhere) is caught and aliased.

**Worst idea (and single riskiest step): WP0 — fixing the 15 `react-hooks/set-state-in-effect` errors as the *opening move*, before any visual net exists.** I confirmed the red state: `16 problems (15 errors, 1 warning)`, and the errors are render-logic (`RunComposer.tsx:557` `if (autonomyForbidden && autonomous) setAutonomous(false)`; `PolicyVersionHistory.tsx:108` reset-on-prop-change). These are **behavior-changing edits to components unrelated to the CSS foundation**, done first, with no snapshot net armed. A regression in *when* the autonomy toggle resets or the timeline clears ships silently and is not a CSS problem any CSS proof would catch. P3 flags it as a trade but under-weights that it is both off-topic and the least-protected edit in the plan.

Runner-up risk: the masthead changes the grid track to **`minmax(max-content, 1fr)`** and calls clipping *"mathematically impossible."* That is true for the nav's own text — but it **reintroduces the exact configuration the `globals.css:451–465` comment says was the original bug**: nav takes full intrinsic width, never yields, actions cluster (~450px) *"bled LEFTWARDS across the nav."* P3 is the only masthead proposal that fights the codebase's own documented fix **without citing it**. It mitigates with a bounded/ellipsized identity cluster + 1280 collapse, so it likely holds — but if the actions cluster isn't perfectly capped, the overlap bug returns. P3's masthead is also the most-changed (removes bar New Run, swaps org/email for an avatar menu, demotes Resources/Activity from routes to jump-links) — bundling IA/nav-model decisions into the foundation is mild scope-widening layered onto the riskiest chrome edit. Its token-consolidation proof (WP1) is a `getComputedStyle` check on **3 selectors** — far blinder than P2's full goldens, so a dropped survivor token (e.g. a `--font-*` fallback) would slip through.

---

## Which one I'd build on: **P2 (safe).**

For this axis it isn't close. P2 is the only plan whose regression net exists *before* the mass edits, keeps the masthead grid the codebase already fought for, collapses early enough that the nav cannot clip, and puts the module split last under an armed net with report-only→failing guard flips so no gate blocks its own cleanup. Its weaknesses are proof-calibration ("byte-identical" → masked threshold; drop the `overflow: clip` backstop and lean on the 1280 collapse), not structural.

I'd graft two things onto it before building: **(1) P1's `tsc` closed-union component API** — the only *compile-time* guarantee a caller can't pass a raw value, strictly stronger than P2's lint-only inline guard; and **(2) P3's `ApiError.kind` typed getter** for the state layer. And I'd move P3's WP0 react-hooks fixes *out* of the foundation entirely — they're real bugs, but they are their own PR with their own behavioral test, never the opening move of a CSS pass.