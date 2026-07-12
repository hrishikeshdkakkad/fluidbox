"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { ArrowRight, Inbox, Pause, Play, Plus, ShieldCheck } from "lucide-react";
import {
  apiGet,
  apiPost,
  isTerminal,
  Session,
  Agent,
  Revision,
  Approval,
  workspaceLabel,
} from "./lib/api";
import { Pill, AutoPill, ModalShell, LoadingRows, short, timeAgo } from "./components/bits";

export default function Runs() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ sessions: Session[] }>("/sessions?limit=50");
      setSessions(r.sessions);
      const a = await apiGet<{ approvals: Approval[] }>("/approvals");
      setApprovals(a.approvals);
    } catch {
      /* offline handled by sidebar */
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    const t = setInterval(load, 2500);
    return () => {
      clearTimeout(first);
      clearInterval(t);
    };
  }, [load]);

  const decide = async (id: string, decision: string) => {
    await apiPost(`/approvals/${id}/decision`, { decision, decided_by: "dashboard" });
    load();
  };

  const active = sessions.filter((s) => !isTerminal(s.status)).length;
  const done = sessions.filter((s) => s.status === "completed").length;
  const terminal = sessions.filter((s) => isTerminal(s.status)).length;
  const completionRate = terminal > 0 ? `${Math.round((done / terminal) * 100)}%` : "—";

  return (
    <>
      <section className="home-hero">
        <div className="home-copy">
          <div className="home-kicker">
            <span className="signal" /> Governed execution, live
          </div>
          <h1>
            Agents at work,
            <br />
            <em>under your control.</em>
          </h1>
          <p>
            Launch work in isolated sandboxes, intervene when policy asks, and keep a
            complete record of what happened.
          </p>
        </div>
        <button className="btn primary hero-action" onClick={() => setShowNew(true)}>
          <Plus /> Start a run
        </button>
      </section>

      <section className="ops-strip" aria-label="Run summary">
        <div className="ops-metric">
          <span className="metric-label">Active now</span>
          <strong>{active}</strong>
          <small>{active === 1 ? "sandbox in progress" : "sandboxes in progress"}</small>
        </div>
        <div className={`ops-metric ${approvals.length ? "attention" : ""}`}>
          <span className="metric-label">Needs review</span>
          <strong>{approvals.length}</strong>
          <small>{approvals.length ? "your decision is required" : "nothing waiting on you"}</small>
        </div>
        <div className="ops-metric">
          <span className="metric-label">Completed</span>
          <strong>{done}</strong>
          <small>across recent history</small>
        </div>
        <div className="ops-metric">
          <span className="metric-label">Completion rate</span>
          <strong>{completionRate}</strong>
          <small>of terminal runs</small>
        </div>
      </section>

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
            {approvals.map((a) => (
              <div className="approval" key={a.id}>
                <span className="icon">
                  <Pause size={16} />
                </span>
                <div className="txt">
                  <div className="h">
                    Waiting for you{a.risk ? ` · ${a.risk}` : ""} · expires{" "}
                    {new Date(a.expires_at).toLocaleTimeString()}
                  </div>
                  <div className="d">
                    <b className="mono">{a.tool}</b>{" "}
                    <span className="mono mut">{a.summary}</span>{" "}
                    <Link href={`/sessions/${a.session_id}`} className="link mono" style={{ fontSize: 12 }}>
                      {short(a.session_id)}
                    </Link>
                  </div>
                </div>
                <div className="acts">
                  <button className="btn human sm" onClick={() => decide(a.id, "approved_once")}>
                    Approve once
                  </button>
                  <button className="btn sm" onClick={() => decide(a.id, "approved_session")}>
                    Whole session
                  </button>
                  <button className="btn sm ghost danger" onClick={() => decide(a.id, "denied")}>
                    Deny
                  </button>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <div className="section-heading recent-heading">
        <div>
          <span className="section-kicker">Workspace activity</span>
          <h2>Recent runs</h2>
        </div>
        <span className="section-note">{sessions.length} in recent history</span>
      </div>

      <div className="run-list">
        {loading ? (
          <LoadingRows />
        ) : sessions.length === 0 ? (
          <div className="launch-empty">
            <div className="empty-mark"><Inbox /></div>
            <div>
              <h3>Your workspace is ready.</h3>
              <p>Start with a task, or create a reusable agent with its own tools and policy.</p>
            </div>
            <div className="empty-actions">
              <button className="btn primary" onClick={() => setShowNew(true)}>
                <Play /> Start a run
              </button>
              <Link className="btn" href="/agents/new">
                Create an agent <ArrowRight />
              </Link>
            </div>
          </div>
        ) : (
          <div className="run-rows">
            {sessions.map((s) => (
              <Link key={s.id} href={`/sessions/${s.id}`} className="run-row">
                <span className={`run-glyph ${s.status}`}><ShieldCheck /></span>
                <span className="run-copy">
                  <strong>{s.task}</strong>
                  <small>
                    <span className="mono">{short(s.id)}</span>
                    <span>·</span>
                    <span>{s.trigger?.kind || "manual"}</span>
                    {s.repo_source && <><span>·</span><span>{workspaceLabel(s.repo_source)}</span></>}
                  </small>
                </span>
                <span className="run-status">
                  <Pill status={s.status} />
                  {s.autonomy === "autonomous" && <AutoPill autonomy={s.autonomy} />}
                </span>
                <span className="run-time">
                  {timeAgo(s.created_at)}
                </span>
                <ArrowRight className="run-arrow" />
              </Link>
            ))}
          </div>
        )}
      </div>
      {showNew && <NewRun onClose={() => setShowNew(false)} onCreated={load} />}
    </>
  );
}

function NewRun({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [agent, setAgent] = useState("claude-fixer");
  const [task, setTask] = useState("");
  const [agentDefault, setAgentDefault] = useState("scratch");
  const [autonomous, setAutonomous] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    apiGet<{ agents: Agent[] }>("/agents").then((r) => setAgents(r.agents)).catch(() => {});
  }, []);

  // Show what "agent default" resolves to for the selected agent.
  useEffect(() => {
    const a = agents.find((x) => x.name === agent);
    if (!a) return;
    apiGet<{ revisions: Revision[] }>(`/agents/${a.id}`)
      .then((r) => setAgentDefault(workspaceLabel(r.revisions[0]?.default_workspace)))
      .catch(() => setAgentDefault("scratch"));
  }, [agent, agents]);

  const submit = async () => {
    setErr("");
    if (!task.trim()) {
      setErr("A task is required.");
      return;
    }
    setBusy(true);
    try {
      // The workspace comes from the agent's revision (set when composing
      // the agent); per-run overrides remain an API affordance.
      await apiPost("/sessions", { agent, task, autonomous });
      onCreated();
      onClose();
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <ModalShell
      title="New run"
      sub="Describe the outcome. Fluidbox will provision a fresh sandbox and freeze the run specification before work begins."
      onClose={onClose}
      wide
    >
      <label className="field">
        <span className="lab">What should the agent accomplish?</span>
        <textarea
          className="inp run-task-input"
          placeholder="For example: review the latest pull request, identify the regression, and prepare a safe patch…"
          value={task}
          onChange={(e) => setTask(e.target.value)}
        />
      </label>

      <div className="run-config-grid">
        <label className="field">
          <span className="lab">Agent</span>
          <select className="inp" value={agent} onChange={(e) => setAgent(e.target.value)}>
            {agents.map((a) => (
              <option key={a.id} value={a.name}>
                {a.name}
              </option>
            ))}
          </select>
        </label>

        <div className="field">
          <span className="lab">Workspace</span>
          <div className="read-only-field">
            <span className="mono">{agentDefault}</span>
            <small>Inherited from agent</small>
          </div>
        </div>
      </div>

      <button
        type="button"
        className={`toggle mode-card ${autonomous ? "on" : ""}`}
        onClick={() => setAutonomous((v) => !v)}
        style={{ marginBottom: 6 }}
        aria-pressed={autonomous}
      >
        <span className="sw" />
        <span>
          <strong>{autonomous ? "Autonomous run" : "Supervised run"}</strong>
          <span className="faint mode-description">
            {autonomous
              ? "Policy fallback decides risky actions without waiting for a person."
              : "Risky actions pause and wait for your approval."}
          </span>
        </span>
      </button>

      {err && <div className="err">{err}</div>}

      <div className="modal-footer">
        <span className="helper">The agent’s revision, tools, policy, and workspace are frozen at launch.</span>
        <button className="btn primary" onClick={submit} disabled={busy}>
          <Play /> {busy ? "Starting…" : "Start run"}
        </button>
      </div>
    </ModalShell>
  );
}
