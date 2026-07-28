import { describe, expect, it } from "vitest";
import { coerceCap, coerceTtlSecs } from "./policy-caps";

// The one property that matters: NOTHING a person can type mid-edit may turn a
// ceiling into "no ceiling". `clear` is reachable only from a genuinely empty
// field — which is why the form holds raw text instead of reading
// `<input type="number">`, whose `value` is "" for `-`, `1e` and `1.` too.
describe("coerceCap", () => {
  it("clears only on a genuinely empty field", () => {
    expect(coerceCap("", true)).toEqual({ kind: "clear" });
    expect(coerceCap("   ", true)).toEqual({ kind: "clear" });
  });

  it("never widens on an unfinished or unparseable entry", () => {
    // Every one of these is what `type="number"` reported as "" — i.e. every
    // one of these used to clear the cap.
    for (const raw of ["-", "1e", "1e+", ".", "-.", "abc", "1/2", "NaN", "1e999"]) {
      expect(coerceCap(raw, true), raw).toEqual({ kind: "keep" });
      expect(coerceCap(raw, false), raw).toEqual({ kind: "keep" });
    }
  });

  it("commits ordinary values", () => {
    expect(coerceCap("1800", true)).toEqual({ kind: "set", value: 1800 });
    expect(coerceCap("2.5", false)).toEqual({ kind: "set", value: 2.5 });
    expect(coerceCap(" 100 ", true)).toEqual({ kind: "set", value: 100 });
    expect(coerceCap("0", true)).toEqual({ kind: "set", value: 0 });
  });

  it("moves an unrepresentable value DOWN, never up", () => {
    // Negative → 0 (the tightest cap), not `null`.
    expect(coerceCap("-1", true)).toEqual({ kind: "set", value: 0 });
    expect(coerceCap("-0.5", false)).toEqual({ kind: "set", value: 0 });
    // Fractional integer caps FLOOR. Rounding 1.5 → 2 would grant a tool call
    // nobody asked for.
    expect(coerceCap("1.5", true)).toEqual({ kind: "set", value: 1 });
    expect(coerceCap("0.9", true)).toEqual({ kind: "set", value: 0 });
    // Past MAX_SAFE_INTEGER a JS number is no longer the integer typed, and
    // `1e20` would reach the u64 parser as a serde error.
    expect(coerceCap("1e20", true)).toEqual({
      kind: "set",
      value: Number.MAX_SAFE_INTEGER,
    });
    expect(coerceCap("9007199254740995", true)).toEqual({
      kind: "set",
      value: Number.MAX_SAFE_INTEGER,
    });
  });

  it("emits only values the Rust side can parse", () => {
    for (const raw of ["-1", "1.5", "1e20", "9007199254740995", "0", "1800", "2.5"]) {
      for (const integer of [true, false]) {
        const out = coerceCap(raw, integer);
        if (out.kind !== "set") continue;
        expect(Number.isFinite(out.value), `${raw} finite`).toBe(true);
        expect(out.value >= 0, `${raw} non-negative`).toBe(true);
        expect(out.value <= Number.MAX_SAFE_INTEGER, `${raw} in range`).toBe(true);
        if (integer) expect(Number.isSafeInteger(out.value), `${raw} integral`).toBe(true);
      }
    }
  });
});

describe("coerceTtlSecs", () => {
  it("keeps the last good value rather than guessing", () => {
    // An empty TTL has nothing to send: the previous window stands. It must NOT
    // collapse to 1 second, which is what `Number("") || 1` used to do.
    for (const raw of ["", "   ", "-", "0", "-5", "0.4", "abc"]) {
      expect(coerceTtlSecs(raw), raw).toEqual({ kind: "keep" });
    }
  });

  it("commits whole seconds", () => {
    expect(coerceTtlSecs("600")).toEqual({ kind: "set", value: 600 });
    expect(coerceTtlSecs("1.9")).toEqual({ kind: "set", value: 1 });
    expect(coerceTtlSecs("1e20")).toEqual({ kind: "set", value: Number.MAX_SAFE_INTEGER });
  });
});
