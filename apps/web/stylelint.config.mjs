// The CSS gate.
//
// Deliberately DECOUPLED from eslint: its own config, its own script, its own
// CI step. eslint has a pre-existing red baseline (15 errors, 11 of them
// react-hooks/set-state-in-effect) that is a runtime-behaviour problem in the
// run composer and policy editor, and nothing about enforcing the design
// scales should wait on greening it.
//
// Every rule here reports at `warning`, and `pnpm lint:css` runs with a
// --max-warnings ceiling set to the current count. That is the ratchet: the
// existing violations do not block anyone, but ONE new raw hex, off-scale
// radius, fourth breakpoint or duplicate selector pushes the count over the
// ceiling and fails CI. As each migration lands, lower the ceiling in
// package.json — the number going down is the visible progress bar.
//
// stylelint-config-standard is deliberately NOT extended. It is a general CSS
// style guide; enabling it against a 9,700-line legacy stylesheet buries the
// four things the owner actually locked under hundreds of formatting
// warnings. The scales are the contract; formatting is not.

/** The only radius values in the system: two tokens plus three literals that
 *  are shapes rather than scale steps (pill, circle, square panel).
 *
 *  Expressed as one regex over 1-4 space-separated parts, because a per-corner
 *  shorthand is legal CSS made of legal parts — `0 var(--radius) var(--radius)
 *  0` (a tab joined to its neighbour) is correct, and an anchored single-value
 *  pattern reported it as a violation. A rule that cries wolf on correct code
 *  is how a gate gets switched off. */
const RADIUS_PART = String.raw`(?:var\(--radius(?:-lg)?\)|999px|50%|0)`;
const RADIUS = [`/^${RADIUS_PART}(?: +${RADIUS_PART}){0,3}$/`];

/** Three breakpoints, no others. Keyed on the real feature names — keying on
 *  `width` would be a silent no-op, because no query in this codebase uses the
 *  range syntax. */
const BREAKPOINTS = [
  "640px",
  "900px",
  "1280px",
  // The min-width COMPLEMENTS of the same three tiers. `min-width: 901px` is
  // not a fourth breakpoint — it is "above the 900 tier", and spelling it any
  // other way (`not all and (max-width: 900px)`) is less readable for no gain.
  "641px",
  "901px",
  "1281px",
];

const config = {
  ignoreFiles: ["**/node_modules/**", ".next/**"],
  plugins: ["stylelint-declaration-strict-value"],
  rules: {
    // COLOUR — every colour comes from a custom property. The token blocks
    // themselves are the one sanctioned home for a literal and carry an
    // explicit `stylelint-disable` comment, so the boundary is visible in the
    // source rather than implied.
    "color-no-hex": [true, { severity: "warning" }],
    "scale-unlimited/declaration-strict-value": [
      ["/color$/", "background-color", "background", "border-color", "fill", "stroke"],
      {
        ignoreValues: [
          "currentColor",
          "transparent",
          "inherit",
          "initial",
          "unset",
          "none",
          "0",
        ],
        disableFix: true,
        severity: "warning",
      },
    ],

    // RADIUS — an allow-list rather than a disallow-lookahead, so the
    // `0 0 11px 11px` shorthand is caught too.
    "declaration-property-value-allowed-list": [
      { "/^border(-[a-z]+)?-radius$/": RADIUS },
      { severity: "warning" },
    ],

    // BREAKPOINTS — a fourth width becomes un-typeable.
    "media-feature-name-value-allowed-list": [
      { "/^(min|max)-width$/": BREAKPOINTS },
      { severity: "warning" },
    ],

    // DUPLICATE SELECTORS — the reason `.topbar-inner` is declared seven times
    // in one file and the last one silently wins. This is the cheap guard that
    // makes splitting the monolith unnecessary; note it only sees duplicates
    // WITHIN a file, so the globals-vs-kernel overlap is still on us.
    "no-duplicate-selectors": [true, { severity: "warning" }],
  },
};

export default config;
