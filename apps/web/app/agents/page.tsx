"use client";

import { useEffect, useState, useCallback } from "react";
import { apiGet, apiPost, Agent, Revision } from "../lib/api";
import { PageHead, short } from "../components/bits";

export default function Agents() {
  const [agents, setAgents] = useState<Agent[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [revs, setRevs] = useState<Record<string, Revision[]>>({});
  const [showNew, setShowNew] = useState(false);

  const load = useCallback(async () => {
    const r = await apiGet<{ agents: Agent[] }>("/agents");
    setAgents(r.agents);
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
    if (!revs[id]) {
      const r = await apiGet<{ revisions: Revision[] }>(`/agents/${id}`);
      setRevs((prev) => ({ ...prev, [id]: r.revisions }));
    }
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
                    {(revs[a.id] || []).map((r) => (
                      <div key={r.id} className="chips" style={{ padding: "8px 0", borderBottom: "1px solid var(--line-soft)" }}>
                        <span className="chip">
                          rev <b>{r.rev}</b>
                        </span>
                        <span className="chip">
                          harness <b>{r.harness}</b>
                        </span>
                        <span className="chip">
                          model <b>{r.model}</b>
                        </span>
                        <span className="chip">image {short(r.runner_image, 24)}</span>
                      </div>
                    ))}
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
    </>
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
