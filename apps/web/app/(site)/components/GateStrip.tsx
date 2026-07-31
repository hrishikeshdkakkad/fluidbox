// The permission gate's decision sequence — a real, fixed order in the
// product (internal.rs::decide_tool_call), which is why this strip is
// allowed to be ordered. Every tool call, both harnesses, both tool classes,
// every autonomy mode: this exact sequence.

const STAGES: { name: string; note: string }[] = [
  { name: "budget", note: "spending and time limits, checked first" },
  { name: "frozen surface", note: "only the tools you attached exist" },
  { name: "schema", note: "arguments checked before anything runs" },
  { name: "trust tier", note: "fork PRs stay read-only, always" },
  { name: "policy", note: "allow · deny · ask a human" },
  { name: "approval", note: "no answer means no" },
];

export function GateStrip({ vertical = false }: { vertical?: boolean }) {
  return (
    <div
      className={`gate ${vertical ? "gate-vertical" : ""}`}
      role="list"
      aria-label="The permission gate's decision order"
    >
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
