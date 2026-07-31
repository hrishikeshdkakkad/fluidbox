import { ReplayLoop } from "./ReplayLoop";

// The signature panel: a governed run exactly as the ledger records it —
// seq-numbered events, verdicts with their deciding stage, an approval pause,
// a brokered call with a digest instead of a payload, metered spend, and the
// redaction line. The three verdicts on show are the pitch: routine work is
// allowed, a credential grab is denied, an external action waits for a
// human. Every event name and field is the product's real vocabulary
// (event.rs / the permission gate); the run itself is illustrative. Rows
// stage in on load and replay on a slow loop (reduced motion shows the
// finished state once).

type Row =
  | { kind: "event"; seq: number; type: string; chip?: Chip; detail: string }
  | { kind: "pause"; label: string }
  | { kind: "note"; label: string };

type Chip = { text: string; tone: "allow" | "approve" | "deny" | "ok" };

const ROWS: Row[] = [
  {
    kind: "event",
    seq: 14,
    type: "tool.requested",
    detail: "Edit crates/core/src/policy.rs",
  },
  {
    kind: "event",
    seq: 15,
    type: "tool.decision",
    chip: { text: "allow", tone: "allow" },
    detail: "policy · paths /workspace/**",
  },
  {
    kind: "event",
    seq: 16,
    type: "tool.requested",
    detail: "Read ~/.ssh/id_ed25519",
  },
  {
    kind: "event",
    seq: 17,
    type: "tool.decision",
    chip: { text: "deny", tone: "deny" },
    detail: "policy · outside /workspace/** — run continues",
  },
  {
    kind: "event",
    seq: 18,
    type: "tool.requested",
    detail: "mcp__linear__create_issue (brokered)",
  },
  {
    kind: "event",
    seq: 19,
    type: "tool.decision",
    chip: { text: "approve", tone: "approve" },
    detail: "policy · pausing for a human · ttl 600s",
  },
  { kind: "pause", label: "awaiting_approval · 38s · approved_once by an owner" },
  {
    kind: "event",
    seq: 22,
    type: "tool.brokered",
    chip: { text: "ok", tone: "ok" },
    detail: "control-plane call · 212ms · result sha256:9f2c…",
  },
  {
    kind: "event",
    seq: 23,
    type: "usage",
    detail: "2,148 tokens · $0.011 of $2.50 budget · wall 4m12s",
  },
  {
    kind: "note",
    label: "prompts ▮▮▮▮▮▮▮▮▮▮ redacted at ingest — only digests reach the ledger",
  },
];

// Cumulative reveal delays, derived once from the static row list (the pause
// row earns a longer beat). Precomputed so render never mutates.
const DELAYS: string[] = ROWS.reduce<number[]>((acc, row, i) => {
  const prev = i === 0 ? 0 : acc[i - 1];
  acc.push(prev + (row.kind === "pause" ? 0.32 : 0.14));
  return acc;
}, []).map((d) => `${d.toFixed(2)}s`);

const TAIL_DELAY = `${(
  ROWS.reduce((acc, row) => acc + (row.kind === "pause" ? 0.32 : 0.14), 0) + 0.2
).toFixed(2)}s`;

export function RunLedger() {
  return (
    <figure className="ledger st-window" aria-label="A governed run as the event ledger records it">
      <figcaption className="st-window-head">
        <span className="st-dots" aria-hidden>
          <i />
          <i />
          <i />
        </span>
        <span className="ledger-head">
          <span className="ledger-dot" aria-hidden />
          <span className="ledger-title">run 0198f2c4</span>
          <span className="ledger-meta">agent fixer · policy default v7 · RunSpec frozen</span>
        </span>
      </figcaption>
      <div className="ledger-body">
        <ReplayLoop>
          {ROWS.map((row, i) => {
            const style = { "--d": DELAYS[i] } as React.CSSProperties;
            if (row.kind === "pause") {
              return (
                <div key={i} className="lr lr-pause" style={style}>
                  <span>── {row.label} ──</span>
                </div>
              );
            }
            if (row.kind === "note") {
              return (
                <div key={i} className="lr lr-note" style={style}>
                  {row.label}
                </div>
              );
            }
            return (
              <div key={i} className="lr" style={style}>
                <span className="lr-seq">{row.seq}</span>
                <span className="lr-type">{row.type}</span>
                {row.chip ? (
                  <span className={`lr-chip ${row.chip.tone}`}>{row.chip.text}</span>
                ) : (
                  <span className="lr-chip-space" aria-hidden />
                )}
                <span className="lr-detail">{row.detail}</span>
              </div>
            );
          })}
          <div
            className="lr lr-tail"
            style={{ "--d": TAIL_DELAY } as React.CSSProperties}
            aria-hidden
          >
            <span className="lr-cursor" />
          </div>
        </ReplayLoop>
      </div>
    </figure>
  );
}
