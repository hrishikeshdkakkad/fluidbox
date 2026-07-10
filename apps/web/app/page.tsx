"use client";

import { useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { apiGet, apiPost, isTerminal, Session, Agent, Revision, workspaceLabel } from "./lib/api";
import { Pill, AutoPill, PageHead, short } from "./components/bits";
import {
  WorkspacePicker,
  WorkspaceDraft,
  emptyDraft,
  draftToInput,
} from "./components/WorkspacePicker";

export default function Operations() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [showNew, setShowNew] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ sessions: Session[] }>("/sessions?limit=50");
      setSessions(r.sessions);
    } catch {
      /* offline handled by rail */
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 2500);
    return () => clearInterval(t);
  }, [load]);

  const active = sessions.filter((s) => !isTerminal(s.status)).length;
  const done = sessions.filter((s) => s.status === "completed").length;

  return (
    <>
      <PageHead
        eyebrow="control plane"
        title="Operations"
        sub="Every run is a fresh, governed sandbox. Watch, approve, inspect."
        right={
          <button className="btn primary" onClick={() => setShowNew(true)}>
            + New Run
          </button>
        }
      />

      <div className="grid cards" style={{ marginBottom: 22 }}>
        <div className="panel stat">
          <div className="k">Active runs</div>
          <div className="v tnum">{active}</div>
        </div>
        <div className="panel stat">
          <div className="k">Completed</div>
          <div className="v tnum">{done}</div>
        </div>
        <div className="panel stat">
          <div className="k">Total sessions</div>
          <div className="v tnum">{sessions.length}</div>
        </div>
      </div>

      <div className="panel">
        {sessions.length === 0 ? (
          <div className="empty">no runs yet — start one with “New Run”</div>
        ) : (
          <div className="rows">
            {sessions.map((s) => (
              <Link key={s.id} href={`/sessions/${s.id}`} className="row sessions-row">
                <span className="id">{short(s.id)}</span>
                <span className="task">{s.task}</span>
                <span style={{ display: "flex", gap: 8, alignItems: "center" }}>
                  <Pill status={s.status} />
                  <AutoPill autonomy={s.autonomy} />
                </span>
                <span className="meta">{timeAgo(s.created_at)}</span>
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
  const [workspace, setWorkspace] = useState<WorkspaceDraft>(emptyDraft("default"));
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
      setErr("task is required");
      return;
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = { agent, task, autonomous };
      const ws = draftToInput(workspace);
      if (ws !== undefined) body.workspace = ws;
      await apiPost("/sessions", body);
      onCreated();
      onClose();
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <div className="overlay" onClick={onClose}>
      <div className="panel modal" onClick={(e) => e.stopPropagation()}>
        <div className="mh">
          <div>
            <div className="eyebrow" style={{ margin: 0 }}>
              new run
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, marginTop: 4 }}>
              Compose a governed run
            </div>
          </div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <label className="field">
            <span className="lab">Agent definition</span>
            <select className="inp" value={agent} onChange={(e) => setAgent(e.target.value)}>
              {agents.map((a) => (
                <option key={a.id} value={a.name}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>

          <label className="field">
            <span className="lab">Task</span>
            <textarea
              className="inp"
              style={{ minHeight: 90 }}
              placeholder="e.g. find and fix the failing test"
              value={task}
              onChange={(e) => setTask(e.target.value)}
            />
          </label>

          <WorkspacePicker
            draft={workspace}
            onChange={setWorkspace}
            defaultOptionLabel={`agent default (${agentDefault})`}
          />

          <div
            className={`toggle ${autonomous ? "on" : ""}`}
            onClick={() => setAutonomous((v) => !v)}
            style={{ marginBottom: 6 }}
          >
            <span className="sw" />
            <span>
              Autonomous
              <span className="mut" style={{ marginLeft: 8, fontSize: 12 }}>
                {autonomous
                  ? "no human in the loop — policy fallback decides risky tools"
                  : "supervised — risky tools pause for approval"}
              </span>
            </span>
          </div>

          {err && <div className="err">{err}</div>}

          <div className="spread" style={{ marginTop: 18 }}>
            <span className="mut" style={{ fontSize: 12 }}>
              A fresh sandbox is provisioned on start.
            </span>
            <button className="btn primary" onClick={submit} disabled={busy}>
              {busy ? "starting…" : "▶ Start run"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function timeAgo(iso: string): string {
  const d = new Date(iso).getTime();
  const s = Math.floor((Date.now() - d) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}
