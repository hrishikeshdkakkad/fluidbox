"use client";

// The buttons a human is offered for a parked approval.
//
// One home for the tool -> buttons rule. Overview and the session timeline both
// render pending approvals, and both had grown their own copy of "which tools
// relabel Approve and drop Whole session" — with different structure, so the
// same approval could read differently depending on where you found it.

export type ApprovalDecision = "approved_once" | "approved_session" | "denied";

/** Tools whose authority is inherently PER-RUN. "Whole session" is meaningless
 *  for these (the grant expires with the run), and the affirmative verb is
 *  "Authorize" rather than "Approve". Presentation only — the decision value
 *  stays `approved_once`, which is what the server records. */
const PER_RUN_TOOLS = new Set(["network.grant"]);

export function ApprovalActions({
  tool,
  busy = false,
  onDecide,
}: {
  tool: string;
  busy?: boolean;
  onDecide: (decision: ApprovalDecision) => void;
}) {
  const perRun = PER_RUN_TOOLS.has(tool);
  return (
    <div className="acts">
      <button
        className="btn human sm"
        type="button"
        disabled={busy}
        onClick={() => onDecide("approved_once")}
      >
        {perRun ? "Authorize" : "Approve once"}
      </button>
      {!perRun && (
        <button
          className="btn sm"
          type="button"
          disabled={busy}
          onClick={() => onDecide("approved_session")}
        >
          Whole session
        </button>
      )}
      <button
        className="btn sm ghost danger"
        type="button"
        disabled={busy}
        onClick={() => onDecide("denied")}
      >
        Deny
      </button>
    </div>
  );
}
