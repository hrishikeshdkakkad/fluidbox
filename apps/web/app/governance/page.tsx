"use client";

// Governance = the policies behind every run: what agents may do, and what
// happens when they ask. The control plane resolves every verdict; this page
// only renders what it sends.

import { useEffect, useState } from "react";
import Link from "next/link";
import { ChevronRight } from "lucide-react";
import { apiGet, PolicySummary } from "../lib/api";
import { LoadingRows, PageHead } from "../components/bits";

export default function GovernancePage() {
  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet<{ policies: PolicySummary[] }>("/policies")
      .then((r) => setPolicies(r.policies))
      .catch((reason) => setErr(`Policies could not be loaded. ${String(reason)}`))
      .finally(() => setLoading(false));
  }, []);

  return (
    <>
      <PageHead
        title="Governance"
        sub="What your agents are allowed to do, and what happens when they ask."
      />

      {err && <div className="err">{err}</div>}

      <div className="panel">
        {loading ? (
          <LoadingRows />
        ) : policies.length === 0 ? (
          <div className="empty">
            <div>No policies yet.</div>
            <div className="helper">
              Policies are defined in <span className="mono">policies/*.yaml</span> and pushed with{" "}
              <span className="mono">just policy-sync</span>.
            </div>
          </div>
        ) : (
          <div className="policy-rows">
            {policies.map((p) => (
              <Link key={p.id} href={`/governance/${p.name}`} className="policy-row">
                <div className="policy-row-main">
                  <div className="policy-row-title">
                    <strong>{p.name}</strong>
                    <span className="chip">v{p.version}</span>
                  </div>
                  <div className="policy-row-sub">{autonomyLine(p.autonomy_summary)}</div>
                </div>
                <span className="policy-row-agents faint">
                  {p.agents_using} {p.agents_using === 1 ? "agent" : "agents"}
                </span>
                <ChevronRight className="run-arrow" aria-hidden />
              </Link>
            ))}
          </div>
        )}
      </div>
    </>
  );
}

/** One line of plain English for the autonomy summary the server computed. */
function autonomyLine(a: PolicySummary["autonomy_summary"]): string {
  if (!a.permitted) return "Unattended runs not permitted";
  const fallback =
    a.default_fallback === "deny"
      ? "risky actions denied by default"
      : "risky actions allowed by default";
  const contrary =
    a.default_fallback === "deny" ? a.allow_overrides : a.deny_overrides;
  const verb = a.default_fallback === "deny" ? "allow" : "deny";
  const tail =
    contrary > 0 ? ` · ${contrary} rule${contrary === 1 ? "" : "s"} ${verb} instead` : "";
  return `Unattended runs allowed · ${fallback}${tail}`;
}
