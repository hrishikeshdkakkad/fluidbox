// The permission gate's decision sequence — a real, fixed order in the
// product (internal.rs::decide_tool_call), which is why this strip is
// allowed to be ordered. Every tool call, both harnesses, both tool classes,
// every autonomy mode: this exact sequence.

const STAGES: { name: string; note: string }[] = [
  { name: "budget", note: "cost, tokens, wall-clock, tool calls" },
  { name: "frozen surface", note: "only tools the RunSpec froze exist" },
  { name: "schema", note: "arguments validated server-side" },
  { name: "trust tier", note: "fork PRs are read-only, always" },
  { name: "policy", note: "allow · deny · ask a human" },
  { name: "approval", note: "expiry denies; decisions idempotent" },
];

export function GateStrip() {
  return (
    <div className="gate" role="list" aria-label="The permission gate's decision order">
      {STAGES.map((stage, i) => (
        <div className="gate-step" role="listitem" key={stage.name}>
          <span className="gate-index" aria-hidden>
            {i + 1}
          </span>
          <span className="gate-name">{stage.name}</span>
          <span className="gate-note">{stage.note}</span>
        </div>
      ))}
    </div>
  );
}
