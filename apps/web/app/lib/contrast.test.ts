import { describe, expect, it } from "vitest";
import { compositeOver, contrastRatio, parseColor, relativeLuminance } from "./contrast";

describe("parseColor", () => {
  it("reads the three hex forms", () => {
    expect(parseColor("#fff")).toEqual({ rgb: [255, 255, 255], alpha: 1 });
    expect(parseColor("#1c2024")).toEqual({ rgb: [28, 32, 36], alpha: 1 });
    expect(parseColor("#21222526").alpha).toBeCloseTo(0x26 / 255, 5);
  });

  it("reads rgb() and rgba(), space- or comma-separated", () => {
    expect(parseColor("rgb(76, 183, 130)")).toEqual({ rgb: [76, 183, 130], alpha: 1 });
    expect(parseColor("rgba(129, 179, 0, 0.14)")).toEqual({ rgb: [129, 179, 0], alpha: 0.14 });
    expect(parseColor("rgb(28 32 36 / 40%)").alpha).toBeCloseTo(0.4, 5);
  });

  it("rejects anything it cannot read rather than guessing a colour", () => {
    expect(() => parseColor("var(--bg)")).toThrow(/unsupported colour/i);
    expect(() => parseColor("chartreuse")).toThrow(/unsupported colour/i);
  });
});

describe("relativeLuminance", () => {
  // WCAG 2.x anchors: pure white is exactly 1, pure black exactly 0.
  it("anchors black at 0 and white at 1", () => {
    expect(relativeLuminance([0, 0, 0])).toBeCloseTo(0, 10);
    expect(relativeLuminance([255, 255, 255])).toBeCloseTo(1, 10);
  });

  // Below 0.04045 the linearisation is the c/12.92 branch, not the power one.
  it("uses the linear branch for very dark channels", () => {
    expect(relativeLuminance([10, 10, 10])).toBeCloseTo(10 / 255 / 12.92, 10);
  });
});

describe("contrastRatio", () => {
  it("is 21:1 for black on white and 1:1 for a colour on itself", () => {
    expect(contrastRatio([0, 0, 0], [255, 255, 255])).toBeCloseTo(21, 10);
    expect(contrastRatio([129, 179, 0], [129, 179, 0])).toBeCloseTo(1, 10);
  });

  it("is symmetric in its arguments", () => {
    const a: [number, number, number] = [86, 122, 0];
    const b: [number, number, number] = [242, 240, 231];
    expect(contrastRatio(a, b)).toBeCloseTo(contrastRatio(b, a), 12);
  });

  // #767676 on white is the canonical smallest grey that clears AA body text.
  it("matches the published WCAG reference greys", () => {
    expect(contrastRatio([0x76, 0x76, 0x76], [255, 255, 255])).toBeCloseTo(4.54, 2);
    expect(contrastRatio([0x77, 0x77, 0x77], [255, 255, 255])).toBeCloseTo(4.48, 2);
  });
});

describe("compositeOver", () => {
  it("returns the base untouched at zero alpha and the top at full alpha", () => {
    expect(compositeOver({ rgb: [255, 0, 0], alpha: 0 }, [10, 20, 30])).toEqual([10, 20, 30]);
    expect(compositeOver({ rgb: [255, 0, 0], alpha: 1 }, [10, 20, 30])).toEqual([255, 0, 0]);
  });

  it("mixes linearly in between", () => {
    expect(compositeOver({ rgb: [0, 0, 0], alpha: 0.5 }, [255, 255, 255])).toEqual([
      127.5, 127.5, 127.5,
    ]);
  });
});
