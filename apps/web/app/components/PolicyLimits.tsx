"use client";

// Budgets · Approvals · Egress — read-only. The permissions matrix answers what
// an agent may do; this answers what a run may SPEND doing it, how long a human
// has to answer, and whether the sandbox may reach the network.
//
// Presentation only, like everything else on this page: every value here was
// resolved by the control plane and sent over the wire. This file chooses words
// and units for a number, never the number.

import { ApprovalScope, ApprovalSettings, Budgets, Egress, EgressMode } from "../lib/api";
import { VERB } from "./PermissionMatrix";

/** A cap the policy did not set. `spec::Budgets` is four `Option`s, so an unset
 *  cap arrives as `null` — no ceiling of that kind, which is not zero. */
const NO_CAP = "No limit";

const SCOPE: Record<ApprovalScope, string> = {
  once: "Once",
  session: "Session",
};

const EGRESS: Record<EgressMode, string> = {
  none: "None",
  "proxy-only": "Proxy only",
  allowlist: "Allowlist",
};

function num(n: number): string {
  return n.toLocaleString("en-US");
}

/** 1800 → "30 min". Units only; the seconds are the server's. */
function duration(secs: number): string {
  if (secs < 60) return `${num(secs)} sec`;
  const scaled = secs < 3600 ? secs / 60 : secs / 3600;
  return `${num(Math.round(scaled * 10) / 10)} ${secs < 3600 ? "min" : "hr"}`;
}

/** 2.5 → "$2.50". A sub-cent ceiling keeps its digits rather than rounding up
 *  to a limit the policy does not actually grant. */
function usd(n: number): string {
  return n.toLocaleString("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: n > 0 && n < 0.01 ? 4 : 2,
  });
}

/** Applies a formatter only to a cap that exists. */
function cap(value: number | null, format: (n: number) => string): string {
  return value == null ? NO_CAP : format(value);
}

function Fact({ k, v }: { k: string; v: string }) {
  return (
    <div className="spec-row">
      <span className="k">{k}</span>
      <span className="v">{v}</span>
    </div>
  );
}

export function PolicyLimits({
  budgets,
  approvals,
  egress,
}: {
  budgets: Budgets;
  approvals: ApprovalSettings;
  egress: Egress;
}) {
  return (
    <>
      <div className="sectitle" style={{ marginTop: 0 }}>
        What a run may spend
      </div>
      <p className="helper" style={{ marginBottom: 4 }}>
        A ceiling, not an allowance: an agent and each run may tighten these, never widen them.
      </p>
      <div>
        <Fact k="Wall clock" v={cap(budgets.max_wall_clock_secs, duration)} />
        <Fact k="Tokens" v={cap(budgets.max_tokens, num)} />
        <Fact k="Cost" v={cap(budgets.max_cost_usd, usd)} />
        <Fact k="Tool calls" v={cap(budgets.max_tool_calls, num)} />
      </div>

      <div className="sectitle">Approvals</div>
      <div>
        <Fact k="Request expires after" v={duration(approvals.default_ttl_secs)} />
        <Fact k="Scope" v={SCOPE[approvals.scope]} />
        <Fact k="If nobody answers" v={VERB[approvals.timeout_action]} />
      </div>

      <div className="sectitle">Network</div>
      <div>
        <Fact k="Egress" v={EGRESS[egress.mode]} />
      </div>
    </>
  );
}
