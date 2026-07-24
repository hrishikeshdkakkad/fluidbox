"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  apiGet,
  apiPost,
  Approval,
  isTerminal,
  Session,
  workspaceLabel,
} from "./lib/api";
import { AutomationPanel } from "./components/AutomationPanel";
import { ResourceOverview } from "./components/ResourceOverview";
import { AddServerWizard } from "./capabilities/AddServerWizard";
import {
  MintedAutomation,
  RunComposer,
  RunMode,
  ShowAutomationSecrets,
} from "./components/RunComposer";
import { AutoPill, LoadingRows, Pill, short, timeAgo } from "./components/bits";
import { useSmartPolling } from "./lib/useSmartPolling";

type OperateView = "history" | "automations";

export default function Runs() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [view, setView] = useState<OperateView>("history");
  const [composerMode, setComposerMode] = useState<RunMode | null>(null);
  const [agentComposer, setAgentComposer] = useState(false);
  const [showCapabilityWizard, setShowCapabilityWizard] = useState(false);
  const [minted, setMinted] = useState<MintedAutomation | null>(null);
  const [automationCount, setAutomationCount] = useState<number | null>(null);
  const [automationRefresh, setAutomationRefresh] = useState(0);
  const [resourceRefresh, setResourceRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [hasSnapshot, setHasSnapshot] = useState(false);
  const [offline, setOffline] = useState(false);
  const [actionErr, setActionErr] = useState("");

  const load = useCallback(async () => {
    try {
      const [sessionResponse, approvalResponse] = await Promise.all([
        apiGet<{ sessions: Session[] }>("/sessions?limit=50"),
        apiGet<{ approvals: Approval[] }>("/approvals"),
      ]);
      setSessions(sessionResponse.sessions);
      setApprovals(approvalResponse.approvals);
      setHasSnapshot(true);
      setOffline(false);
    } catch {
      // Keep the last good snapshot, but never present a failed first read as
      // real zero activity.
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useSmartPolling(load, 2500);

  const selectView = (nextView: OperateView) => {
    setView(nextView);
    const nextUrl = nextView === "automations" ? "/?view=automations" : "/";
    window.history.replaceState({}, "", nextUrl);
  };

  const decide = async (id: string, decision: string) => {
    setActionErr("");
    try {
      await apiPost(`/approvals/${id}/decision`, { decision });
      void load();
    } catch (error) {
      setActionErr(`The decision could not be saved. ${String(error)}`);
    }
  };

  const active = sessions.filter((session) => !isTerminal(session.status)).length;
  const done = sessions.filter((session) => session.status === "completed").length;
  const terminal = sessions.filter((session) => isTerminal(session.status)).length;
  const completionRate = terminal > 0 ? `${Math.round((done / terminal) * 100)}%` : "—";

  return (
    <>
      <Suspense fallback={null}>
        <QueryActions
          setView={setView}
          setComposerMode={setComposerMode}
          setAgentComposer={setAgentComposer}
          setShowCapabilityWizard={setShowCapabilityWizard}
        />
      </Suspense>
      <header className="dashboard-header">
        <div>
          <h1>Overview</h1>
          <p>Configure, automate, and monitor governed agent runs.</p>
        </div>
        <button className="btn primary" type="button" onClick={() => setComposerMode("once")}>
          New Run
        </button>
      </header>

      <section className="overview-panel panel" aria-labelledby="operations-summary-heading">
        <div className="overview-panel-head">
          <div>
            <h2 id="operations-summary-heading">Operations</h2>
            <p>Current activity across manual runs and automations.</p>
          </div>
          <span className="overview-status">
            <span className={`signal ${offline ? "down" : ""}`} />
            {offline ? "Offline" : loading && !hasSnapshot ? "Checking" : "Operational"}
          </span>
        </div>
        <div className="ops-strip" aria-label="Run summary">
          <div className="ops-metric">
            <span className="metric-label">Active</span>
            <strong>{hasSnapshot ? active : "—"}</strong>
            <small>{hasSnapshot ? (active === 1 ? "sandbox running" : "sandboxes running") : "control plane unavailable"}</small>
          </div>
          <div className={`ops-metric ${approvals.length ? "attention" : ""}`}>
            <span className="metric-label">Needs Review</span>
            <strong>{hasSnapshot ? approvals.length : "—"}</strong>
            <small>{hasSnapshot ? (approvals.length ? "decision required" : "no pending decisions") : "status unavailable"}</small>
          </div>
          <div className="ops-metric">
            <span className="metric-label">Completed</span>
            <strong>{hasSnapshot ? done : "—"}</strong>
            <small>{hasSnapshot ? "recent runs" : "history unavailable"}</small>
          </div>
          <div className="ops-metric">
            <span className="metric-label">Success Rate</span>
            <strong>{hasSnapshot ? completionRate : "—"}</strong>
            <small>{hasSnapshot ? "terminal runs" : "history unavailable"}</small>
          </div>
        </div>
      </section>

      <ResourceOverview
        refreshKey={resourceRefresh}
        onCreateAgent={() => setAgentComposer(true)}
        onAddCapability={() => setShowCapabilityWizard(true)}
      />

      {actionErr && <div className="err">{actionErr}</div>}

      {approvals.length > 0 && (
        <section className="attention-section">
          <div className="section-heading">
            <div>
              <span className="section-kicker">Action required</span>
              <h2>Needs your attention</h2>
            </div>
            <span className="section-note">Policy paused these runs before acting.</span>
          </div>
          <div className="attention-list">
            {approvals.map((approval) => (
              <div className="approval" key={approval.id}>
                <span className="approval-label">Review</span>
                <div className="txt">
                  <div className="h">
                    Waiting for you{approval.risk ? ` · ${approval.risk}` : ""} · expires{" "}
                    {new Date(approval.expires_at).toLocaleTimeString()}
                  </div>
                  <div className="d">
                    <b className="mono">{approval.tool}</b>{" "}
                    <span className="mono mut">{approval.summary}</span>{" "}
                    <Link href={`/sessions/${approval.session_id}`} className="link mono approval-session-link">
                      {short(approval.session_id)}
                    </Link>
                  </div>
                </div>
                <div className="acts">
                  <button className="btn human sm" type="button" onClick={() => decide(approval.id, "approved_once")}>
                    Approve once
                  </button>
                  <button className="btn sm" type="button" onClick={() => decide(approval.id, "approved_session")}>
                    Whole session
                  </button>
                  <button className="btn sm ghost danger" type="button" onClick={() => decide(approval.id, "denied")}>
                    Deny
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="tabs operate-tabs" id="operations" role="tablist" aria-label="Runs and automations">
        <button
          className={`tab ${view === "history" ? "active" : ""}`}
          type="button"
          role="tab"
          aria-selected={view === "history"}
          onClick={() => selectView("history")}
        >
          Run history <span className="n">{sessions.length}</span>
        </button>
        <button
          className={`tab ${view === "automations" ? "active" : ""}`}
          type="button"
          role="tab"
          aria-selected={view === "automations"}
          onClick={() => selectView("automations")}
        >
          Automations {automationCount !== null && <span className="n">{automationCount}</span>}
        </button>
      </div>

      {view === "history" ? (
        <section className="operate-view" role="tabpanel">
          <div className="section-heading recent-heading">
            <div>
              <span className="section-kicker">Every invocation</span>
              <h2>Run history</h2>
            </div>
            <span className="section-note">Manual and automated runs share one timeline.</span>
          </div>

          <div className="run-list">
            {loading ? (
              <LoadingRows />
            ) : offline && !hasSnapshot ? (
              <div className="launch-empty">
                <div>
                  <h3>Control plane unavailable.</h3>
                  <p>Run history could not be loaded. Your browser will keep retrying in the background.</p>
                </div>
                <div className="empty-actions">
                  <button className="btn" type="button" onClick={() => void load()}>
                    Retry now
                  </button>
                </div>
              </div>
            ) : sessions.length === 0 ? (
              <div className="launch-empty">
                <div>
                  <h3>Your workspace is ready.</h3>
                  <p>Configure a run now; you can launch it once or add an automation before saving.</p>
                </div>
                <div className="empty-actions">
                  <button className="btn primary" type="button" onClick={() => setComposerMode("once")}>
                    Configure a run
                  </button>
                  <button className="btn" type="button" onClick={() => setAgentComposer(true)}>
                    Create an agent
                  </button>
                </div>
              </div>
            ) : (
              <div className="run-rows">
                {sessions.map((session) => (
                  <Link key={session.id} href={`/sessions/${session.id}`} className="run-row">
                    <span className="run-copy">
                      <strong>{session.task}</strong>
                      <small>
                        <span className="mono">{short(session.id)}</span>
                        <span>·</span>
                        <span>{session.trigger?.kind || "manual"}</span>
                        {session.repo_source && (
                          <><span>·</span><span>{workspaceLabel(session.repo_source)}</span></>
                        )}
                      </small>
                    </span>
                    <span className="run-status">
                      <Pill status={session.status} />
                      {session.autonomy === "autonomous" && <AutoPill autonomy={session.autonomy} />}
                    </span>
                    <span className="run-time">{timeAgo(session.created_at)}</span>
                  </Link>
                ))}
              </div>
            )}
          </div>
        </section>
      ) : (
        <div className="operate-view" role="tabpanel">
          <AutomationPanel
            onNew={() => setComposerMode("automation")}
            refreshKey={automationRefresh}
            onCountChange={setAutomationCount}
          />
        </div>
      )}

      {composerMode && (
        <RunComposer
          initialMode={composerMode}
          onClose={() => setComposerMode(null)}
          onRunCreated={() => {
            setComposerMode(null);
            selectView("history");
            void load();
          }}
          onAutomationCreated={(automation) => {
            setComposerMode(null);
            setMinted(automation);
            setAutomationRefresh((current) => current + 1);
            selectView("automations");
          }}
        />
      )}

      {agentComposer && (
        <RunComposer
          agentOnly
          onClose={() => setAgentComposer(false)}
          onRunCreated={() => {}}
          onAutomationCreated={() => {}}
          onAgentCreated={() => {
            setAgentComposer(false);
            setResourceRefresh((current) => current + 1);
          }}
        />
      )}

      {showCapabilityWizard && (
        <AddServerWizard
          onClose={() => {
            setShowCapabilityWizard(false);
            setResourceRefresh((current) => current + 1);
          }}
        />
      )}

      {minted && <ShowAutomationSecrets minted={minted} onClose={() => setMinted(null)} />}
    </>
  );
}

function QueryActions({
  setView,
  setComposerMode,
  setAgentComposer,
  setShowCapabilityWizard,
}: {
  setView: React.Dispatch<React.SetStateAction<OperateView>>;
  setComposerMode: React.Dispatch<React.SetStateAction<RunMode | null>>;
  setAgentComposer: React.Dispatch<React.SetStateAction<boolean>>;
  setShowCapabilityWizard: React.Dispatch<React.SetStateAction<boolean>>;
}) {
  const params = useSearchParams();
  const query = params.toString();

  useEffect(() => {
    const requestedView = params.get("view");
    const action = params.get("action");
    if (requestedView === "automations") setView("automations");
    if (action === "new-agent") setAgentComposer(true);
    if (action === "add-capability") setShowCapabilityWizard(true);
    if (action === "new-run") setComposerMode("once");

    if (action) {
      const consumed = new URLSearchParams(query);
      consumed.delete("action");
      window.history.replaceState({}, "", consumed.size > 0 ? `/?${consumed}` : "/");
    }
  }, [params, query, setAgentComposer, setComposerMode, setShowCapabilityWizard, setView]);

  return null;
}
