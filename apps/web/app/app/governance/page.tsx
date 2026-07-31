"use client";

// Governance = the policies behind every run: what agents may do, and what
// happens when they ask. The control plane resolves every verdict; this page
// only renders what it sends. Policies are CREATED here too (design §4.4):
// clone an existing one or start blank — either way the server mints the
// identity and version 1 together.

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ChevronRight } from "lucide-react";
import { apiGetCached, apiPost, PolicySummary } from "../../lib/api";
import { LoadingRows, ModalShell, PageHead } from "../../components/bits";

export default function GovernancePage() {
  const router = useRouter();
  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  const [hasSnapshot, setHasSnapshot] = useState(false);
  const [creating, setCreating] = useState(false);

  const load = useCallback(() => {
    setErr("");
    apiGetCached<{ policies: PolicySummary[] }>("/policies", { maxAgeMs: 30_000 })
      .then((r) => {
        setPolicies(r.policies);
        setHasSnapshot(true);
      })
      .catch((reason) => setErr(`Policies could not be loaded. ${String(reason)}`))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    const timer = window.setTimeout(load, 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  return (
    <>
      <PageHead
        title="Governance"
        sub="What your agents are allowed to do, and what happens when they ask."
        right={
          <button className="btn primary" type="button" onClick={() => setCreating(true)}>
            New policy
          </button>
        }
      />

      {err && <div className="err">{err}</div>}

      <div className="panel">
        {loading ? (
          <LoadingRows />
        ) : err && !hasSnapshot ? (
          <div className="launch-empty">
            <div>
              <h3>Governance is unavailable.</h3>
              <p>A failed read is not treated as an empty policy set.</p>
            </div>
            <div className="empty-actions">
              <button
                className="btn"
                type="button"
                onClick={() => {
                  setLoading(true);
                  load();
                }}
              >
                Retry now
              </button>
            </div>
          </div>
        ) : policies.length === 0 ? (
          <div className="empty">
            <div>No policies yet.</div>
            <div className="helper">
              A fresh control plane seeds <span className="mono">default</span> at boot; create
              more here — every edit becomes an immutable, revertible version.
            </div>
            <div className="act">
              <button className="btn" type="button" onClick={() => setCreating(true)}>
                Create a policy
              </button>
            </div>
          </div>
        ) : (
          <div className="policy-rows">
            {policies.map((p) => (
              <Link
                key={p.id}
                href={`/governance/${encodeURIComponent(p.name)}`}
                className="policy-row"
              >
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

      {creating && (
        <NewPolicyDialog
          policies={policies}
          onClose={() => setCreating(false)}
          onCreated={(name) => {
            setCreating(false);
            router.push(`/app/governance/${encodeURIComponent(name)}`);
          }}
        />
      )}
    </>
  );
}

function NewPolicyDialog({
  policies,
  onClose,
  onCreated,
}: {
  policies: PolicySummary[];
  onClose: () => void;
  onCreated: (name: string) => void;
}) {
  const [name, setName] = useState("");
  const [from, setFrom] = useState(policies[0]?.name ?? "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const create = async () => {
    setErr("");
    setBusy(true);
    try {
      // Pin the exact version the dialog DISPLAYED — a publish landing while
      // this dialog is open must not silently change what gets cloned.
      const fromVersion = policies.find((p) => p.name === from)?.version;
      await apiPost("/policies/clone", {
        name: name.trim(),
        ...(from ? { from, from_version: fromVersion } : {}),
      });
      onCreated(name.trim());
    } catch (reason) {
      setErr(String(reason).replace(/^Error:\s*/, ""));
      setBusy(false);
    }
  };

  return (
    <ModalShell
      title="New policy"
      sub="Clone a policy's rules as version 1, or start blank — everything unknown asks a human until you say otherwise."
      onClose={onClose}
      dirty={name.trim().length > 0}
    >
      <label className="field">
        <span className="lab">Name</span>
        <input
          className="inp mono"
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder="staging"
          maxLength={64}
        />
        <span className="field-hint">1–64 characters: letters, digits, . _ -</span>
      </label>
      <label className="field">
        <span className="lab">Start from</span>
        <select className="inp" value={from} onChange={(event) => setFrom(event.target.value)}>
          <option value="">Blank — fail-safe defaults, no rules</option>
          {policies.map((p) => (
            <option key={p.id} value={p.name}>
              Clone {p.name} · v{p.version}
            </option>
          ))}
        </select>
      </label>
      {err && <div className="err">{err}</div>}
      <div className="spread" style={{ marginTop: 14 }}>
        <span className="helper">Creates the policy and its version 1 together.</span>
        <button
          className="btn primary"
          type="button"
          disabled={busy || !name.trim()}
          onClick={() => void create()}
        >
          {busy ? "Creating…" : "Create policy"}
        </button>
      </div>
    </ModalShell>
  );
}

/** One line of plain English for the autonomy summary the server computed. */
function autonomyLine(a: PolicySummary["autonomy_summary"]): string {
  if (!a) return "No versions yet — runs of this policy fail closed";
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
