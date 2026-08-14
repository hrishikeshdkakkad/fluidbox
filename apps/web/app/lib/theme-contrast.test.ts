import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { AA_BODY, compositeOver, contrastRatio, parseColor, type Rgb } from "./contrast";

// The mechanical guard behind the 2026-08-14 contrast fixes.
//
// It reads the REAL stylesheets and resolves the real token graph, so a future
// edit to `--ds-green-700` (or to the `.diff` tints, or to any alias in
// between) fails here instead of shipping. Hard-coding the resolved hex would
// defeat the entire point.
//
// Cascade note: globals.css loads first (layout.tsx:3), kernel.css second
// (layout.tsx:4), so kernel wins ties at equal specificity. Both roots are read
// in that order.

const globals = readFileSync(new URL("../globals.css", import.meta.url), "utf8");
const kernel = readFileSync(new URL("../kernel.css", import.meta.url), "utf8");

/** Every `--name: value` declared inside the given selector's blocks, in
 *  source order across the supplied sheets (later wins). */
function customProperties(sheets: readonly string[], selector: string): Map<string, string> {
  const out = new Map<string, string>();
  for (const sheet of sheets) {
    // Multiline-anchored: both roots start their own line, and `}`-anchoring
    // would miss kernel.css, whose `:root` follows the file's banner comment.
    const blocks = new RegExp(`^\\s*${selector}\\s*\\{([^}]*)\\}`, "gm");
    for (const block of sheet.matchAll(blocks)) {
      for (const decl of block[1].matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
        out.set(decl[1], decl[2].trim());
      }
    }
  }
  return out;
}

/** Follow `var(--a)` chains to a literal. Throws on an unknown or cyclic token
 *  rather than returning something plausible. */
function resolve(value: string, tokens: Map<string, string>, seen = new Set<string>()): string {
  const ref = /^var\(\s*(--[\w-]+)\s*\)$/.exec(value.trim());
  if (!ref) return value.trim();
  const name = ref[1];
  if (seen.has(name)) throw new Error(`cyclic token reference: ${name}`);
  const next = tokens.get(name);
  if (next === undefined) throw new Error(`undefined token: ${name}`);
  return resolve(next, tokens, new Set(seen).add(name));
}

const LIGHT = customProperties([globals, kernel], ":root");
const DARK = new Map([
  ...customProperties([globals, kernel], ":root"),
  ...customProperties([globals, kernel], 'html\\[data-theme="dark"\\]'),
]);
const THEMES = { light: LIGHT, dark: DARK } as const;

function opaque(token: string, tokens: Map<string, string>): Rgb {
  return parseColor(resolve(tokens.get(token) ?? token, tokens)).rgb;
}

/** The declarations of a component rule, verbatim from source. */
function ruleDeclarations(sheet: string, selector: string): Record<string, string> {
  const head = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const block = new RegExp(`^\\s*${head}\\s*\\{([^}]*)\\}`, "m").exec(sheet);
  if (!block) throw new Error(`rule not found: ${selector}`);
  return Object.fromEntries(
    [...block[1].matchAll(/([\w-]+)\s*:\s*([^;]+);/g)].map((d) => [d[1], d[2].trim()])
  );
}

describe("token graph", () => {
  it("resolves every semantic alias this suite depends on", () => {
    for (const [theme, tokens] of Object.entries(THEMES)) {
      for (const name of ["--bg", "--surface", "--raised", "--ink", "--ink-2", "--ink-3"]) {
        expect(() => opaque(name, tokens), `${theme} ${name}`).not.toThrow();
      }
    }
  });
});

describe("body and muted text clear WCAG AA in both themes", () => {
  for (const [theme, tokens] of Object.entries(THEMES)) {
    for (const ink of ["--ink", "--ink-2", "--ink-3"] as const) {
      for (const surface of ["--bg", "--surface", "--raised"] as const) {
        it(`${theme}: ${ink} on ${surface}`, () => {
          const ratio = contrastRatio(opaque(ink, tokens), opaque(surface, tokens));
          expect(ratio, `${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(AA_BODY);
        });
      }
    }
  }
});

describe("accent and amber clear WCAG AA as text on the light canvas", () => {
  // Light-only: both tokens are far lighter in dark mode and pass comfortably.
  //
  // --raised is included deliberately. It is the DARKEST light surface, and
  // accent text does land on it (globals.css `.tl-body code` and `.recipe-mark`
  // pair them in a single rule, and more reach it through ancestry inside
  // cards). Asserting only --bg and --surface is how a token gets tuned for
  // the canvas and then quietly fails on every card — which is exactly what
  // this suite missed on its first pass.
  for (const token of ["--accent", "--amber"] as const) {
    for (const surface of ["--bg", "--surface", "--raised"] as const) {
      it(`light: ${token} on ${surface}`, () => {
        const ratio = contrastRatio(opaque(token, LIGHT), opaque(surface, LIGHT));
        expect(ratio, `${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(AA_BODY);
      });
    }
  }
});

describe("the diff viewer is legible in both themes", () => {
  // kernel.css re-declares `.diff` AFTER globals.css and therefore sets the
  // real panel background. Assert the winner is still what we think it is — if
  // this declaration moves, every ratio below is measured against the wrong
  // base and must be recomputed.
  it("still takes its panel background from --raised via kernel.css", () => {
    expect(kernel).toMatch(/\.diff,\s*\n?\s*\.codebox\s*\{[^}]*background:\s*var\(--ds-gray-100\)/);
  });

  for (const [theme, tokens] of Object.entries(THEMES)) {
    for (const kind of ["add", "del"] as const) {
      it(`${theme}: .diff .${kind} ink on its tinted row`, () => {
        const rule = ruleDeclarations(globals, `.diff .${kind}`);
        const row = compositeOver(parseColor(rule.background), opaque("--raised", tokens));
        const ink = parseColor(resolve(rule.color, tokens)).rgb;
        const ratio = contrastRatio(ink, row);
        expect(
          ratio,
          `${ratio.toFixed(2)}:1 on rgb(${row.map(Math.round).join(",")})`
        ).toBeGreaterThanOrEqual(AA_BODY);
      });
    }

    for (const part of ["hdr", "at"] as const) {
      it(`${theme}: .diff .${part} ink on the panel`, () => {
        const rule = ruleDeclarations(globals, `.diff .${part}`);
        const ink = parseColor(resolve(rule.color, tokens)).rgb;
        const ratio = contrastRatio(ink, opaque("--raised", tokens));
        expect(ratio, `${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(AA_BODY);
      });
    }
  }
});
