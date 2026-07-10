"use client";

import { useEffect, useState, useCallback } from "react";
import { apiGet, apiPost, Agent, Revision } from "../lib/api";
import { PageHead, short } from "../components/bits";

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [revs, setRevs] = useState<Record<string, Revision[]>>({});
  const [showNew, setShowNew] = useState(false);
  const [addRev, setAddRev] = useState<string | null>(null);

  const load = useCallback(async () => {
    const r = await apiGet<{ agents: Agent[] }>("/agents");
    setAgents(r.agents);
  }, []);

  const loadRevs = useCallback(async (id: string) => {
    const r = await apiGet<{ revisions: Revision[] }>(`/agents/${id}`);
    setRevs((prev) => ({ ...prev, [id]: r.revisions }));
  }, []);

  useEffect(() => {
    load().catch(() => {});
  }, [load]);

  const toggle = async (id: string) => {
    if (open === id) {
      setOpen(null);
      return;
    }
    setOpen(id);
    if (!revs[id]) await loadRevs(id);
  };

  return (
    <>
      <PageHead
        eyebrow="registry"
        title="Agents"
        sub="Versioned recipes. Editing an agent appends an immutable revision — it never mutates one."
        right={
          <button className="btn primary" onClick={() => setShowNew(true)}>
            + New Agent
          </button>
        }
      />

      <div className="panel">
        {agents.length === 0 ? (
          <div className="empty">no agents</div>
        ) : (
          <div className="rows">
            {agents.map((a) => (
              <div key={a.id}>
                <div
                  className="row"
                  style={{ gridTemplateColumns: "180px 1fr 90px", cursor: "pointer" }}
                  onClick={() => toggle(a.id)}
                >
                  <span className="mono" style={{ color: "var(--accent)" }}>
                    {a.name}
                  </span>
                  <span className="task">{a.description || "—"}</span>
                  <span className="meta">{open === a.id ? "▲ hide" : "▼ revs"}</span>
                </div>
                {open === a.id && (
                  <div style={{ padding: "6px 18px 16px", background: "var(--ground)" }}>
                    {(revs[a.id] || []).map((r, i) => (
                      <div key={r.id} className="chips" style={{ padding: "8px 0", borderBottom: "1px solid var(--line-soft)", alignItems: "center" }}>
                        <span className="chip">
                          rev <b>{r.rev}</b>
                        </span>
                        {i === 0 && (
                          <span className="chip" style={{ color: "var(--good)", borderColor: "#275a3f" }}>current</span>
                        )}
                        <span className="chip">
                          harness <b>{r.harness}</b>
                        </span>
                        <span className="chip">
                          model <b>{r.model}</b>
                        </span>
                        {r.system_prompt && <span className="chip">prompt set</span>}
                        <span className="chip">image {short(r.runner_image, 24)}</span>
                      </div>
                    ))}
                    <button
                      className="btn sm ghost"
                      style={{ marginTop: 12 }}
                      onClick={() => setAddRev(a.id)}
                    >
                      + Add revision
                    </button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {showNew && (
        <NewAgent
          onClose={() => setShowNew(false)}
          onCreated={() => {
            setShowNew(false);
            load();
          }}
        />
      )}

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
}

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
  const [model, setModel] = useState(current?.model || "claude-haiku-4-5");
  const [systemPrompt, setSystemPrompt] = useState(current?.system_prompt || "");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    setBusy(true);
    try {
      // Inherits harness/policy/image/budgets from the latest revision.
      await apiPost(`/agents/${agentId}/revisions`, {
        model,
        system_prompt: systemPrompt.trim() || null,
      });
      onAdded();
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
              append revision
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, marginTop: 4 }}>
              rev {current ? current.rev + 1 : 1}
            </div>
          </div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <p className="mut" style={{ fontSize: 12.5, marginTop: 0 }}>
            Revisions are immutable — this appends a new one. Running sessions keep their frozen
            spec; new runs use this revision.
          </p>
          <label className="field">
            <span className="lab">Model</span>
            <select className="inp" value={model} onChange={(e) => setModel(e.target.value)}>
              <option value="claude-haiku-4-5">claude-haiku-4-5</option>
              <option value="claude-sonnet-5">claude-sonnet-5</option>
              <option value="claude-opus-4-8">claude-opus-4-8</option>
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
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 14 }}>
            <span className="mut" style={{ fontSize: 12 }}>
              inherits harness · policy · image · budgets
            </span>
            <button className="btn primary" onClick={submit} disabled={busy}>
              {busy ? "appending…" : "Append revision"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function NewAgent({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [model, setModel] = useState("claude-haiku-4-5");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    if (!name.trim()) {
      setErr("name is required");
      return;
    }
    setBusy(true);
    try {
      await apiPost("/agents", {
        name: name.trim(),
        description: description.trim() || null,
        model,
        system_prompt: systemPrompt.trim() || null,
        policy: "default",
      });
      onCreated();
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  return (
    <div className="overlay" onClick={onClose}>
      <div className="panel modal" onClick={(e) => e.stopPropagation()}>
        <div className="mh">
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 15 }}>New agent definition</div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <label className="field">
            <span className="lab">Name</span>
            <input className="inp mono" value={name} onChange={(e) => setName(e.target.value)} placeholder="pr-fixer" />
          </label>
          <label className="field">
            <span className="lab">Description</span>
            <input className="inp" value={description} onChange={(e) => setDescription(e.target.value)} />
          </label>
          <label className="field">
            <span className="lab">Model</span>
            <select className="inp" value={model} onChange={(e) => setModel(e.target.value)}>
              <option value="claude-haiku-4-5">claude-haiku-4-5</option>
              <option value="claude-sonnet-5">claude-sonnet-5</option>
              <option value="claude-opus-4-8">claude-opus-4-8</option>
            </select>
          </label>
          <label className="field">
            <span className="lab">System prompt (optional)</span>
            <textarea className="inp" style={{ minHeight: 70 }} value={systemPrompt} onChange={(e) => setSystemPrompt(e.target.value)} />
          </label>
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="mut" style={{ fontSize: 12 }}>
              policy: default · creates revision 1
            </span>
            <button className="btn primary" onClick={submit} disabled={busy}>
              {busy ? "creating…" : "Create agent"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
