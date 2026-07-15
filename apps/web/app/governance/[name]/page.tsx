"use client";

// One policy, fully resolved. A change here applies immediately and to every
// future run of every agent on this policy, so the blast radius leads the page.

import { use, useCallback, useEffect, useState } from "react";
import { apiDelete, apiGet, apiPut, PolicyAction, PolicyDetail } from "../../lib/api";
import { PageHead } from "../../components/bits";
import { PermissionMatrix } from "../../components/PermissionMatrix";
import { PolicyLimits } from "../../components/PolicyLimits";

export default function PolicyDetailPage({ params }: { params: Promise<{ name: string }> }) {
  const { name } = use(params);
  const [detail, setDetail] = useState<PolicyDetail | null>(null);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setDetail(await apiGet<PolicyDetail>(`/policies/${name}`));
    } catch (reason) {
      setErr(`This policy could not be loaded. ${String(reason)}`);
    }
  }, [name]);

  useEffect(() => {
    void load();
  }, [load]);

  // The server is the single writer: apply, then re-read the resolved policy
  // rather than guessing what the new matrix looks like.
  const mutate = async (tool: string, apply: () => Promise<unknown>) => {
    setBusy(tool);
    setErr("");
    try {
      await apply();
      await load();
    } catch (reason) {
      setErr(`${tool}: ${String(reason)}`);
    } finally {
      setBusy(null);
    }
  };

  const onSet = (tool: string, action: PolicyAction) =>
    mutate(tool, () => apiPut(`/policies/${name}/overrides/${tool}`, { action }));
  const onClear = (tool: string) =>
    mutate(tool, () => apiDelete(`/policies/${name}/overrides/${tool}`));

  if (!detail) {
    return (
      <>
        <PageHead title={name} crumbs={[{ href: "/governance", label: "Governance" }]} />
        {err ? <div className="err">{err}</div> : null}
      </>
    );
  }

  const a = detail.autonomy_summary;
  const contrary = a.default_fallback === "deny" ? a.allow_overrides : a.deny_overrides;
  const contraryVerb = a.default_fallback === "deny" ? "allow" : "deny";

  return (
    <>
      <PageHead
        title={detail.policy.name}
        sub={`Version ${detail.policy.version}`}
        crumbs={[{ href: "/governance", label: "Governance" }]}
      />

      {/* A click applies immediately and globally. This is not decoration. */}
      <div className="blast-radius">
        Changes affect future runs of all {detail.agents_using}{" "}
        {detail.agents_using === 1 ? "agent" : "agents"} on this policy. Runs already in flight
        keep the policy they started with.
      </div>

      {err && <div className="err">{err}</div>}

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          Unattended runs
        </div>
        {a.permitted ? (
          <p className="note">
            Allowed. When an action needs approval, it is{" "}
            <strong>{a.default_fallback === "deny" ? "denied" : "allowed"}</strong> automatically.
            {contrary > 0 &&
              ` ${contrary} rule${contrary === 1 ? "" : "s"} ${contraryVerb} instead.`}
          </p>
        ) : (
          <p className="note">Not permitted by this policy.</p>
        )}
      </div>

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          What agents may do
        </div>
        <p className="helper" style={{ marginBottom: 4 }}>
          Rules whose verdict depends on the path touched or the command run are shown as written —
          they cannot be reduced to a single choice.
        </p>
        <PermissionMatrix rows={detail.matrix} busy={busy} onSet={onSet} onClear={onClear} />
      </div>

      {/* The third question a policy answers, after "can it run unattended" and
          "what may it do": what can it spend. */}
      <div className="panel pad">
        <PolicyLimits
          budgets={detail.budgets}
          approvals={detail.approvals}
          egress={detail.egress}
        />
      </div>
    </>
  );
}
