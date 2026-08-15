// WCAG 2.x colour arithmetic.
//
// This exists so contrast claims about the design tokens are MEASURED rather
// than asserted: theme-contrast.test.ts reads the real stylesheets, resolves
// the token graph, and fails the build if a pair drops below its floor. The
// 2026-08-14 audit found `.diff .add` at 1.97:1 in dark mode — on the screen
// where a person reviews what an agent changed — precisely because nothing
// mechanical was checking.
//
// Pure functions, no I/O, no DOM.

/** An opaque sRGB triple. Channels are 0-255 but need not be integers: the
 *  result of compositing a translucent layer is a fractional colour, and
 *  rounding it to 8-bit before measuring would introduce error the browser
 *  does not make. */
export type Rgb = readonly [number, number, number];

export interface Rgba {
  readonly rgb: Rgb;
  readonly alpha: number;
}

/** WCAG AA floors. Large text is >=18.66px bold or >=24px. */
export const AA_BODY = 4.5;
export const AA_LARGE = 3;
/** The floor below which even a non-text UI boundary is not distinguishable. */
export const NON_TEXT = 3;

function channel(token: string): number {
  const value = token.endsWith("%")
    ? (Number.parseFloat(token) * 255) / 100
    : Number.parseFloat(token);
  if (!Number.isFinite(value)) throw new Error(`unsupported colour channel: ${token}`);
  return value;
}

function alphaChannel(token: string): number {
  const value = token.endsWith("%") ? Number.parseFloat(token) / 100 : Number.parseFloat(token);
  if (!Number.isFinite(value)) throw new Error(`unsupported colour alpha: ${token}`);
  return value;
}

function parseHex(hex: string): Rgba {
  const body = hex.length <= 4 ? hex.replace(/./g, (c) => c + c) : hex;
  if (!/^[0-9a-f]{6}([0-9a-f]{2})?$/i.test(body)) {
    throw new Error(`unsupported colour: #${hex}`);
  }
  const byte = (i: number) => Number.parseInt(body.slice(i, i + 2), 16);
  return {
    rgb: [byte(0), byte(2), byte(4)],
    alpha: body.length === 8 ? byte(6) / 255 : 1,
  };
}

function parseFunctional(inner: string): Rgba {
  // Both `rgb(r, g, b, a)` and the modern `rgb(r g b / a)` reach here.
  const [head, slashAlpha] = inner.split("/");
  const parts = head.trim().split(/[\s,]+/).filter(Boolean);
  if (parts.length < 3) throw new Error(`unsupported colour: rgb(${inner})`);
  const rawAlpha = slashAlpha !== undefined ? slashAlpha.trim() : parts[3];
  return {
    rgb: [channel(parts[0]), channel(parts[1]), channel(parts[2])],
    alpha: rawAlpha === undefined ? 1 : alphaChannel(rawAlpha),
  };
}

/**
 * Read a CSS colour literal. Deliberately supports ONLY the notations the
 * stylesheets actually use (hex 3/4/6/8, rgb(), rgba()) and throws on anything
 * else — a named colour or an unresolved `var()` silently defaulting to black
 * would turn a contrast test into a source of false confidence.
 */
export function parseColor(value: string): Rgba {
  const text = value.trim();
  if (text.startsWith("#")) return parseHex(text.slice(1));
  const functional = /^rgba?\(([^)]*)\)$/i.exec(text);
  if (functional) return parseFunctional(functional[1]);
  throw new Error(`unsupported colour: ${value}`);
}

/** Flatten a translucent layer onto an opaque one (source-over). */
export function compositeOver(top: Rgba, base: Rgb): Rgb {
  const mix = (t: number, b: number) => t * top.alpha + b * (1 - top.alpha);
  return [mix(top.rgb[0], base[0]), mix(top.rgb[1], base[1]), mix(top.rgb[2], base[2])];
}

/** sRGB 0-255 -> linear-light 0-1. */
function linearize(value: number): number {
  const c = value / 255;
  return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
}

/** L = 0.2126R + 0.7152G + 0.0722B over linear-light channels. */
export function relativeLuminance(rgb: Rgb): number {
  const [r, g, b] = [linearize(rgb[0]), linearize(rgb[1]), linearize(rgb[2])];
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

/** (Llighter + 0.05) / (Ldarker + 0.05). Symmetric; 1..21. */
export function contrastRatio(a: Rgb, b: Rgb): number {
  const [la, lb] = [relativeLuminance(a), relativeLuminance(b)];
  return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
}
