"use client";

import { Suspense, useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ChevronDown, ChevronRight, Search as SearchIcon } from "lucide-react";
import {
  apiGetCached,
  apiPost,
  Agent,
  BundleRef,
  ConnectionRequirement,
  NetworkGrantMode,
  NetworkRequest,
  PolicyContent,
  PolicySummary,
  Revision,
  workspaceLabel,
  bundleRefsLabel,
} from "../../lib/api";
import { BundlePicker } from "../../components/BundlePicker";
import { RequirementsEditor } from "../../components/RequirementsEditor";
import { HarnessPicker } from "../../components/HarnessPicker";
import { useHarnesses, modelsFor, defaultModelFor } from "../../lib/harnesses";
import { LoadingRows, ModalShell, PageHead, short } from "../../components/bits";
import {
  WorkspacePicker,
  WorkspaceDraft,
  specToDraft,
  draftToInput,
} from "../../components/WorkspacePicker";
import { NetworkRequestEditor } from "../../components/NetworkRequestEditor";
import {
  MODE_LABEL,
  networkOf,
  requestForWire,
  requestOf,
  summarizeRequest,
} from "../../lib/network";

export default function AgentsPage() {
  return (
    <Suspense fallback={null}>
      <Agents />
    </Suspense>
  );
}

function Agents() {
  const router = useRouter();
  const params = useSearchParams();
  // The YAML policies tab retired with DB-native policies (§17 #11):
  // Governance is the authoring surface. Old bookmarks land there.
  const legacyPoliciesTab = params.get("tab") === "policies";
  useEffect(() => {
    if (legacyPoliciesTab) router.replace("/app/governance");
  }, [legacyPoliciesTab, router]);

  const [agents, setAgents] = useState<Agent[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [revs, setRevs] = useState<Record<string, Revision[]>>({});
  const [addRev, setAddRev] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await apiGetCached<{ agents: Agent[] }>("/agents", { maxAgeMs: 15_000 });
      setAgents(r.agents);
      setLoadError("");
    } catch (error) {
      setLoadError(`Agents could not be loaded. ${String(error)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRevs = useCallback(async (id: string) => {
    const r = await apiGetCached<{ revisions: Revision[] }>(`/agents/${id}`, { maxAgeMs: 30_000 });
    setRevs((prev) => ({ ...prev, [id]: r.revisions }));
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    return () => clearTimeout(first);
  }, [load]);

  // Warm the revisions for every agent so the collapsed row can state what the
  // agent DECLARES. `GET /agents` carries only id/name/description, so without
  // this the declaration is invisible until you expand — which is how an agent
  // silently sat offline. O(agents) cached GETs on mount; a failure is
  // deliberately silent because the row renders nothing rather than guessing.
  useEffect(() => {
    let live = true;
    for (const a of agents) {
      if (revs[a.id]) continue;
      void loadRevs(a.id).catch(() => {
        if (!live) return;
      });
    }
    return () => {
      live = false;
    };
    // `revs` is intentionally absent: including it would re-run on every load
    // and re-request agents already in flight.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents, loadRevs]);

  const toggle = async (id: string) => {
    if (open === id) {
      setOpen(null);
      return;
    }
    setOpen(id);
    if (!revs[id]) {
      try {
        await loadRevs(id);
      } catch (error) {
        setLoadError(`Agent revisions could not be loaded. ${String(error)}`);
      }
    }
  };

  return (
    <>
      <PageHead
        title="Agents"
        sub="Versioned recipes. Editing appends an immutable revision — running sessions keep their frozen spec. Policies are authored in Governance."
        right={
          <Link className="btn primary" href="/app?action=new-agent#configuration">
            New agent
          </Link>
        }
      />

      {agentsList()}

      {addRev && (
        <AddRevision
          agentId={addRev}
          current={(revs[addRev] || [])[0]}
          onClose={() => setAddRev(null)}
          onAdded={() => {
            loadRevs(addRev);
            setAddRev(null);
          }}
        />
      )}
    </>
  );

  function agentsList() {
    const shown = q.trim()
      ? agents.filter((a) =>
          `${a.name} ${a.description || ""}`.toLowerCase().includes(q.trim().toLowerCase())
        )
      : agents;
    return (
      <>
        {loadError && <div className="err" style={{ marginBottom: 10 }}>{loadError}</div>}
        {agents.length > 8 && (
          <div className="search" style={{ marginBottom: 12 }}>
            <SearchIcon />
            <input
              className="inp"
              placeholder="Filter agents…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
        )}
        <div className="panel">
          {loading ? (
            <LoadingRows />
          ) : loadError && agents.length === 0 ? (
            <div className="launch-empty">
              <div>
                <h3>Agents are unavailable.</h3>
                <p>A failed request is not treated as an empty agent library.</p>
              </div>
              <div className="empty-actions">
                <button
                  className="btn"
                  type="button"
                  onClick={() => {
                    setLoading(true);
                    void load();
                  }}
                >
                  Retry now
                </button>
              </div>
            </div>
          ) : agents.length === 0 ? (
            <div className="empty">
              <div>No agents yet.</div>
              <div className="act">
                <Link className="btn" href="/app?action=new-agent#configuration">
                  Create your first agent
                </Link>
              </div>
            </div>
          ) : shown.length === 0 ? (
            <div className="empty">No agents match “{q}”.</div>
          ) : (
            <div className="rows">
              {shown.map((a) => (
                <div key={a.id}>
                  <button
                    type="button"
                    className="row click"
                    style={{ gridTemplateColumns: "16px 180px 1fr", cursor: "pointer" }}
                    onClick={() => toggle(a.id)}
                    aria-expanded={open === a.id}
                    aria-controls={`agent-revisions-${a.id}`}
                  >
                    <span className="faint" style={{ display: "grid" }}>
                      {open === a.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                    </span>
                    <span className="mono" style={{ fontSize: 12.5, color: "var(--accent)" }}>
                      {a.name}
                    </span>
                    <span className="task mut">
                      {a.description || "—"}
                      {/* The current revision's declaration, stated where an
                          operator actually looks. Rendered only once the
                          revisions are known — an unknown declaration shows
                          nothing rather than claiming "Offline". */}
                      {revs[a.id]?.[0] && (
                        <span className="chip" style={{ marginLeft: 8 }}>
                          network <b>{summarizeRequest(requestOf(revs[a.id][0].network))}</b>
                        </span>
                      )}
                    </span>
                  </button>
                  {open === a.id && (
                    <div
                      id={`agent-revisions-${a.id}`}
                      style={{
                        padding: "4px 16px 14px 42px",
                        borderBottom: "1px solid var(--border)",
                      }}
                    >
                      {(revs[a.id] || []).map((r, i) => (
                        <div
                          key={r.id}
                          className="chips"
                          style={{
                            padding: "8px 0",
                            borderBottom: "1px solid var(--border)",
                            alignItems: "center",
                          }}
                        >
                          <span className="chip">
                            rev <b>{r.rev}</b>
                          </span>
                          {i === 0 && <span className="badge ok">current</span>}
                          <span className="chip">
                            harness <b>{r.harness}</b>
                          </span>
                          <span className="chip">
                            model <b>{r.model}</b>
                          </span>
                          {r.system_prompt && <span className="chip">prompt set</span>}
                          {r.default_workspace && (
                            <span className="chip">
                              workspace <b>{workspaceLabel(r.default_workspace)}</b>
                            </span>
                          )}
                          {r.capability_bundles?.length > 0 && (
                            <span className="chip">
                              bundles <b>{bundleRefsLabel(r.capability_bundles)}</b>
                            </span>
                          )}
                          <span className="chip">
                            network <b>{summarizeRequest(requestOf(r.network))}</b>
                          </span>
                          <span className="chip">image {short(r.runner_image, 24)}</span>
                        </div>
                      ))}
                      <button
                        className="btn sm"
                        style={{ marginTop: 12 }}
                        disabled={!revs[a.id]}
                        onClick={() => setAddRev(a.id)}
                      >
                        Add revision
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </>
    );
  }
}

/* ─── Modals (unchanged flows, new chrome) ───────────────────────────── */

function AddRevision({
  agentId,
  current,
  onClose,
  onAdded,
}: {
  agentId: string;
  current?: Revision;
  onClose: () => void;
  onAdded: () => void;
}) {
  const { harnesses, loading: harnessesLoading, error: harnessesError, reload: reloadHarnesses } = useHarnesses();
  const [harness, setHarness] = useState(current?.harness || "claude-agent-sdk");
  const [model, setModel] = useState(current?.model || "claude-haiku-4-5");
  const [systemPrompt, setSystemPrompt] = useState(current?.system_prompt || "");
  const [workspace, setWorkspace] = useState<WorkspaceDraft>(specToDraft(current?.default_workspace));
  const [pins, setPins] = useState<BundleRef[]>(current?.capability_bundles ?? []);
  const [requirements, setRequirements] = useState<ConnectionRequirement[]>(
    current?.connection_requirements ?? []
  );
  const [network, setNetwork] = useState<NetworkRequest>(
    current?.network ?? { mode: "offline", targets: [], duration_secs: null }
  );
  // Spec A: the revision is where an EXISTING agent changes policy. Options
  // come from the policy summaries; the initial value is the current
  // revision's attachment, resolved id → name once the list loads.
  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [policyName, setPolicyName] = useState<string | null>(null);
  const currentPolicyName =
    policies.find((p) => p.id === current?.policy_id)?.name ?? null;
  useEffect(() => {
    let active = true;
    apiGetCached<{ policies: PolicySummary[] }>("/policies", { maxAgeMs: 30_000 })
      .then((r) => active && setPolicies(r.policies))
      .catch(() => {});
    return () => {
      active = false;
    };
  }, []);
  const effectivePolicyName = policyName ?? currentPolicyName;
  // The governing ceiling shown beside the declaration. /policies summaries
  // carry no content, so the selected policy's detail is fetched for its
  // network.max_mode; a failed read renders "unknown", never a false floor.
  const [ceiling, setCeiling] = useState<NetworkGrantMode | null>(null);
  useEffect(() => {
    // Show "unknown" the instant the policy changes, rather than leaving the
    // previous policy's ceiling on screen until the new read resolves.
    setCeiling(null);
    const name = policyName ?? currentPolicyName;
    if (!name) return;
    let live = true;
    apiGetCached<{ content: PolicyContent }>(`/policies/${encodeURIComponent(name)}`, {
      maxAgeMs: 30_000,
    })
      .then((d) => live && setCeiling(networkOf(d.content).max_mode))
      // A failed read must not assert a ceiling we did not read.
      .catch(() => live && setCeiling(null));
    return () => {
      live = false;
    };
  }, [policyName, currentPolicyName]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const dirty =
    harness !== (current?.harness || "claude-agent-sdk") ||
    model !== (current?.model || "claude-haiku-4-5") ||
    systemPrompt !== (current?.system_prompt || "") ||
    (policyName !== null && policyName !== currentPolicyName) ||
    JSON.stringify(workspace) !== JSON.stringify(specToDraft(current?.default_workspace)) ||
    JSON.stringify(pins) !== JSON.stringify(current?.capability_bundles ?? []) ||
    JSON.stringify(requirements) !== JSON.stringify(current?.connection_requirements ?? []) ||
    // Compare what would actually be SENT: targets typed under `approved` are
    // kept in state across a mode toggle, and a declaration that sends none is
    // not an edit just because they are still held.
    JSON.stringify(requestForWire(network)) !==
      JSON.stringify(current?.network ?? { mode: "offline", targets: [], duration_secs: null });

  const submit = async () => {
    setErr("");
    setBusy(true);
    try {
      // Inherits image/budgets from the latest revision; the policy is sent
      // only when the operator changed it here (omitted → inherit).
      // The workspace is sent explicitly (WYSIWYG): scratch clears a default.
      // Capability pins are WYSIWYG too: exactly the name@version refs
      // shown in the picker are attached (§17 #7 — nothing floats, and an
      // existing pin never upgrades unless its version was changed here).
      // Requirements are WYSIWYG as well (sent explicitly, incl. [] to clear).
      // The network declaration is WYSIWYG too (sent unconditionally); a run
      // narrows it to the policy ceiling server-side — the browser never judges.
      await apiPost(`/agents/${agentId}/revisions`, {
        harness,
        model,
        system_prompt: systemPrompt.trim() || null,
        ...(policyName !== null && policyName !== currentPolicyName
          ? { policy: policyName }
          : {}),
        default_workspace: draftToInput(workspace),
        capability_bundles: pins.map((p) => `${p.name}@${p.version}`),
        connection_requirements: requirements,
        // Defense in depth: only send a declaration we actually have. With no
        // `current` revision (still loading / failed load) `network` is the
        // offline default, and sending it would OVERWRITE the agent's real
        // declaration — the server inherits only when the field is ABSENT.
        // `requestForWire` decides what the mode is allowed to carry: core
        // REFUSES public+targets, and ACCEPTS offline+targets — which would
        // store authority the editor stopped showing the moment the mode left
        // `approved`.
        ...(current ? { network: requestForWire(network) } : {}),
      });
      onAdded();
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <ModalShell
      title={`Append revision ${current ? current.rev + 1 : 1}`}
      sub="Revisions are immutable. Running sessions keep their frozen spec; new runs use this one."
      onClose={onClose}
      dirty={dirty}
    >
      <div className="field">
        <span className="lab">Harness</span>
        {harnessesLoading ? (
          <span className="helper">Loading runtime catalog…</span>
        ) : harnessesError ? (
          <div className="catalog-state error-state">
            <span>{harnessesError}</span>
            <button className="btn sm" type="button" onClick={reloadHarnesses}>Retry</button>
          </div>
        ) : (
          <HarnessPicker
            harnesses={harnesses}
            value={harness}
            onChange={(h) => {
              setHarness(h);
              setModel(defaultModelFor(harnesses, h)); // never carry a cross-harness model
            }}
          />
        )}
      </div>
      <label className="field">
        <span className="lab">Model</span>
        <select className="inp" value={model} onChange={(e) => setModel(e.target.value)}>
          {modelsFor(harnesses, harness).map((m) => (
            <option key={m.id} value={m.id}>
              {m.display_name}
            </option>
          ))}
        </select>
      </label>
      <label className="field">
        <span className="lab">System prompt (optional)</span>
        <textarea
          className="inp"
          style={{ minHeight: 70 }}
          value={systemPrompt}
          onChange={(e) => setSystemPrompt(e.target.value)}
        />
      </label>
      <label className="field">
        <span className="lab">Policy</span>
        <select
          className="inp"
          value={effectivePolicyName ?? ""}
          onChange={(e) => setPolicyName(e.target.value)}
          disabled={policies.length === 0}
        >
          {policies.length === 0 && <option value="">Loading policies…</option>}
          {policies.map((p) => (
            <option key={p.id} value={p.name}>
              {p.name} · v{p.version}
              {p.id === current?.policy_id ? " (current)" : ""}
            </option>
          ))}
        </select>
        <span className="helper">
          Governs every run of this revision. <Link href="/app/governance">Author policies in Governance.</Link>
        </span>
      </label>
      <WorkspacePicker draft={workspace} onChange={setWorkspace} />
      <BundlePicker pins={pins} onChange={setPins} />
      <RequirementsEditor value={requirements} onChange={setRequirements} />
      <div className="sectitle">Network access</div>
      <p className="helper">
        Governing policy ceiling:{" "}
        <strong>{ceiling ? MODE_LABEL[ceiling] : "unknown"}</strong>
        {ceiling ? null : " — could not read the policy; a run will still enforce it."}
      </p>
      <NetworkRequestEditor value={network} onChange={setNetwork} />
      {err && <div className="err">{err}</div>}
      <div className="spread" style={{ marginTop: 14 }}>
        <span className="helper">Inherits image · budgets.</span>
        <button className="btn primary" onClick={submit} disabled={busy || harnessesLoading || !!harnessesError}>
          {busy ? "Appending…" : "Append revision"}
        </button>
      </div>
    </ModalShell>
  );
}
