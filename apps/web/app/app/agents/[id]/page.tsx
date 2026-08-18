"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Agent,
  apiGet,
  apiGetCached,
  bundleRefsLabel,
  PolicySummary,
  Revision,
  workspaceLabel,
} from "../../../lib/api";
import { Breadcrumb } from "../../../components/Breadcrumb";
import { LoadingRows, short } from "../../../components/bits";
import { StateError } from "../../../components/state";
import { AddRevision } from "../../../components/AddRevision";
import { requestOf, summarizeRequest } from "../../../lib/network";

// The agent detail page.
//
// Opening an agent used to expand a six-column strip inside the list, where a
// whole system prompt was reduced to the words "prompt set" and the policy,
// budgets, tool requirements and workspace were not shown at all. Everything
// an agent declares is already on `GET /agents/{id}` — this page shows it,
// grouped under the SAME headings the composer uses to collect it, so the
// screen you read matches the screen you filled in.
//
// Read-only by design: an agent is append-only (editing means appending a
// revision), so changes go through the revision flow, not here.
export default function AgentDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [agent, setAgent] = useState<Agent | null>(null);
  const [revisions, setRevisions] = useState<Revision[]>([]);
  const [policies, setPolicies] = useState<PolicySummary[]>([]);
  const [coreError, setCoreError] = useState<unknown>(null);
  const [refreshError, setRefreshError] = useState("");
  const [selectedRev, setSelectedRev] = useState<number | null>(null);
  const [editing, setEditing] = useState(false);

  const load = useCallback(async () => {
    try {
      const detail = await apiGet<{ agent: Agent; revisions: Revision[] }>(`/agents/${id}`);
      setAgent(detail.agent);
      setRevisions(detail.revisions);
      setCoreError(null);
      setRefreshError("");
    } catch (error) {
      // Keep any snapshot already on screen; the failure surfaces either as
      // the whole-page state (no snapshot) or as a note above it.
      setCoreError(error);
      setRefreshError(String(error));
    }
    try {
      // Names, not ids: `policy_id` is opaque and the composer names the rules.
      const response = await apiGetCached<{ policies: PolicySummary[] }>("/policies", {
        maxAgeMs: 30_000,
      });
      setPolicies(response.policies);
    } catch {
      // A missing name falls back to the id below — never blocks the page.
    }
  }, [id]);

  useEffect(() => {
    void load();
  }, [load]);

  // Everything below reads ONE revision. Newest is what runs use today;
  // picking an older one shows exactly what a run of that vintage froze.
  const current = revisions[0];
  const shown = revisions.find((r) => r.rev === selectedRev) ?? current;
  const isCurrent = shown != null && current != null && shown.rev === current.rev;

  if (!agent) {
    return (
      <div className="automation-detail">
        <header className="automation-detail-head">
          <div>
            <Breadcrumb leaf={short(id)} />
            <div className="automation-title-line">
              <h1>Agent</h1>
            </div>
          </div>
        </header>
        {coreError ? (
          <StateError
            error={coreError}
            onRetry={() => void load()}
            notFoundHref="/app/agents"
            notFoundLabel="All agents"
          />
        ) : (
          <LoadingRows />
        )}
      </div>
    );
  }

  const policyName =
    policies.find((p) => p.id === shown?.policy_id)?.name ?? shown?.policy_id ?? "—";
  const budgetEntries = Object.entries(shown?.budgets ?? {});

  return (
    <div className="automation-detail">
      <header className="automation-detail-head">
        <div>
          <Breadcrumb leaf={agent.name} />
          <div className="automation-title-line">
            <span className="automation-kind">Agent</span>
            <h1>{agent.name}</h1>
            {shown && (
              <span className={`badge ${isCurrent ? "ok" : ""}`}>
                v{shown.rev}
                {isCurrent ? " · current" : " · historical"}
              </span>
            )}
          </div>
          <p className="automation-intro">
            {agent.description || "No description."}
            {" · "}
            <Link className="link" href="/app/agents">
              All agents
            </Link>
          </p>
        </div>
        <div className="automation-actions">
          <button
            className="btn sm"
            type="button"
            disabled={!current}
            onClick={() => setEditing(true)}
          >
            Edit agent
          </button>
        </div>
      </header>

      {refreshError && (
        <div className="note">Refresh failed — showing the last loaded state. {refreshError}</div>
      )}

      {!shown ? (
        <div className="empty">This agent has no revisions yet.</div>
      ) : (
        <>
          {/* The composer collects an agent under these headings; this page
              reports it back under the same ones, in the same order. */}
          <section className="automation-detail-section">
            <h2>Agent</h2>
            <div className="contract-vars">
              <Row label="Name" value={agent.name} />
              <Row label="Description" value={agent.description || "—"} />
              <Row label="Agent id" value={agent.id} mono />
              <Row label="Created" value={new Date(agent.created_at).toLocaleString()} />
            </div>
          </section>

          <section className="automation-detail-section">
            <h2>Runtime</h2>
            <div className="contract-vars">
              <Row label="Harness" value={shown.harness} mono />
              <Row label="Model" value={shown.model} mono />
              <Row label="Runner image" value={shown.runner_image} mono />
            </div>
          </section>

          <section className="automation-detail-section">
            <h2>System instructions</h2>
            {shown.system_prompt ? (
              // Verbatim and complete. The list said "prompt set", which is the
              // one thing about a prompt that tells you nothing.
              <pre className="panel pad agent-prompt">{shown.system_prompt}</pre>
            ) : (
              <div className="empty">No system instructions on this revision.</div>
            )}
          </section>

          <section className="automation-detail-section">
            <h2>What it works on, and with what</h2>
            <div className="contract-vars">
              <Row
                label="Workspace"
                value={
                  shown.default_workspace
                    ? workspaceLabel(shown.default_workspace)
                    : "Scratch sandbox — nothing is mounted"
                }
              />
              <Row
                label="Capability pins"
                value={
                  shown.capability_bundles?.length
                    ? bundleRefsLabel(shown.capability_bundles)
                    : "None pinned"
                }
              />
            </div>

            <div className="sectitle">apps &amp; tools</div>
            {shown.connection_requirements?.length ? (
              <div className="contract-vars">
                {shown.connection_requirements.map((req) => (
                  <div className="row contract-var" key={req.slot}>
                    <span>
                      <b className="mono">{req.slot}</b>
                      <small className="faint" style={{ display: "block" }}>
                        {req.connector.slug || req.connector.url}
                      </small>
                    </span>
                    <span className="faint">
                      <span className="chip">
                        {req.binding_mode === "organization"
                          ? "the organisation's account"
                          : "the invoking user's account"}
                      </span>
                      {req.required_tools.length > 0 && (
                        <small className="mono" style={{ display: "block", marginTop: 4 }}>
                          requires: {req.required_tools.join(", ")}
                        </small>
                      )}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="empty">No brokered tools declared.</div>
            )}
          </section>

          <section className="automation-detail-section">
            <h2>Policy</h2>
            <div className="contract-vars">
              <div className="row contract-var">
                <span>Rules</span>
                <span className="faint">
                  {policyName === "—" ? (
                    "—"
                  ) : (
                    <Link className="link" href={`/app/governance/${policyName}`}>
                      {policyName}
                    </Link>
                  )}
                </span>
              </div>
              {budgetEntries.length > 0 ? (
                budgetEntries.map(([key, value]) => (
                  <Row key={key} label={key} value={String(value)} mono />
                ))
              ) : (
                <Row label="Budgets" value="Policy defaults" />
              )}
            </div>
          </section>

          <section className="automation-detail-section">
            <h2>Network access</h2>
            <div className="contract-vars">
              <Row label="Declared" value={summarizeRequest(requestOf(shown.network))} />
            </div>
            <p className="helper">A run may only narrow what the agent declares — never widen it.</p>
          </section>

          <section className="automation-detail-section">
            <h2>Revisions</h2>
            <p className="helper">
              Editing an agent appends a revision; running sessions keep the one they started
              with. Select one to read exactly what it froze.
            </p>
            <div className="contract-vars">
              {revisions.map((rev, index) => {
                const active = rev.rev === shown.rev;
                return (
                  <button
                    type="button"
                    key={rev.id}
                    className={`row contract-var agent-rev-row${active ? " on" : ""}`}
                    aria-pressed={active}
                    onClick={() => setSelectedRev(rev.rev)}
                  >
                    <span>
                      <b className="mono">v{rev.rev}</b>
                      {index === 0 && <span className="badge ok">current</span>}
                    </span>
                    <span className="faint">
                      {new Date(rev.created_at).toLocaleString()} ·{" "}
                      <span className="mono">
                        {rev.harness} · {rev.model}
                      </span>
                    </span>
                  </button>
                );
              })}
            </div>
          </section>
        </>
      )}

      {/* Editing appends a revision rather than mutating one, so the flow is
          the same one the list used to hide behind an expander. */}
      {editing && (
        <AddRevision
          agentId={agent.id}
          current={current}
          onClose={() => setEditing(false)}
          onAdded={() => {
            setEditing(false);
            // Show the revision that was just appended, not the one being read.
            setSelectedRev(null);
            void load();
          }}
        />
      )}
    </div>
  );
}

function Row({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="row contract-var">
      <span>{label}</span>
      <span className={mono ? "faint mono" : "faint"}>{value}</span>
    </div>
  );
}
