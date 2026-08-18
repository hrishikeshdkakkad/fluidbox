"use client";

import { Suspense, useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ChevronRight, Search as SearchIcon } from "lucide-react";
import { apiGetCached, Agent, Revision } from "../../lib/api";
import { LoadingRows, PageHead } from "../../components/bits";
import { requestOf, summarizeRequest } from "../../lib/network";

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
  const [revs, setRevs] = useState<Record<string, Revision[]>>({});
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
            <div className="agent-table" role="table" aria-label="Agents">
              <div className="agent-thead" role="row">
                <span role="columnheader">agent</span>
                <span role="columnheader">harness</span>
                <span role="columnheader">model</span>
                <span role="columnheader">network</span>
                <span role="columnheader" className="agent-th-revs">
                  revisions
                </span>
                <span aria-hidden />
              </div>
              {shown.map((a) => {
                const current = revs[a.id]?.[0];
                const count = revs[a.id]?.length ?? 0;
                return (
                  // The row opens the agent. It used to expand a strip that
                  // squashed a whole system prompt down to "prompt set" and
                  // showed neither the rules, the tools, nor the budgets; the
                  // detail page reports all of it. A link also retires an
                  // interactive `role="row"` holding `role="cell"` children,
                  // which was never a valid table for a screen reader.
                  <Link key={a.id} href={`/app/agents/${a.id}`} className="agent-tr" role="row">
                    <span className="agent-td-name" role="cell">
                      <strong>{a.name}</strong>
                      <small>{a.description || "—"}</small>
                    </span>
                    <span className="agent-td-mono" role="cell">
                      {current?.harness ?? ""}
                    </span>
                    <span className="agent-td-mono" role="cell">
                      {current?.model ?? ""}
                    </span>
                    <span role="cell">
                      {current && (
                        <span className="run-kind">
                          {summarizeRequest(requestOf(current.network))}
                        </span>
                      )}
                    </span>
                    <span className="agent-td-revs" role="cell">
                      {count > 0 ? `v${current!.rev} · ${count}` : ""}
                    </span>
                    <ChevronRight className="agent-chevron" aria-hidden />
                  </Link>
                );
              })}
            </div>
          )}
        </div>
      </>
    );
  }
}

/* ─── Modals (unchanged flows, new chrome) ───────────────────────────── */

