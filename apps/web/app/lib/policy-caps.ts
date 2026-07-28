// How a typed string becomes a policy CAP.
//
// This lives apart from the form because it is the rule that decides whether a
// keystroke can loosen a ceiling, and that rule deserves tests rather than a
// component. The governing constraint: **an edit must never widen a cap by
// accident.** `null` means "no ceiling of this kind", so anything that turns
// an unfinished or unparseable entry into `null` hands the policy an unbounded
// budget the person never asked for.
//
// The reason a raw STRING arrives here at all is that `<input type="number">`
// cannot express the difference: it reports `value === ""` for a cleared field
// AND for every intermediate state it cannot parse — `-`, `1e`, `1.`. The form
// therefore holds the text itself and asks this function what it means.

/** What the form should do with what was typed. */
export type CapEdit =
  /** Commit this value. */
  | { kind: "set"; value: number }
  /** The field is empty: no ceiling of this kind. */
  | { kind: "clear" }
  /** Not a usable number yet — hold the last good value, do not widen. */
  | { kind: "keep" };

/**
 * @param raw     exactly what is in the field
 * @param integer the cap is a `u64` server-side (seconds, tokens, tool calls)
 *                rather than the `f64` cost
 *
 * Values that ARE usable are only ever moved DOWN to something the server can
 * represent: negatives to `0`, fractional integer caps floored (never rounded
 * — rounding `1.5` up to `2` is a widening), and anything past
 * `Number.MAX_SAFE_INTEGER` clamped to it, because past that a JS number is no
 * longer the integer that was typed and `1e20` would otherwise reach the `u64`
 * parser as a serde error against a field still being edited.
 */
export function coerceCap(raw: string, integer: boolean): CapEdit {
  const t = raw.trim();
  if (t === "") return { kind: "clear" };
  const n = Number(t);
  if (!Number.isFinite(n)) return { kind: "keep" };
  const clamped = Math.min(Math.max(0, n), Number.MAX_SAFE_INTEGER);
  return { kind: "set", value: integer ? Math.floor(clamped) : clamped };
}

/**
 * The approval TTL is NOT nullable — every approval has an expiry — so an empty
 * or sub-1 entry has nothing to send and the last good value stands. Shortening
 * an approval window by accident is a real change to how long a human has to
 * answer, so this errs the same way: keep, never guess.
 */
export function coerceTtlSecs(raw: string): CapEdit {
  const n = Number(raw.trim());
  if (!Number.isFinite(n) || n < 1) return { kind: "keep" };
  return { kind: "set", value: Math.floor(Math.min(n, Number.MAX_SAFE_INTEGER)) };
}
