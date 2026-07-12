"use client";

import { Suspense, useEffect, useState, useCallback } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { Bot, ChevronDown, ChevronRight, Plus, Search as SearchIcon } from "lucide-react";
import {
  apiGet,
  apiPost,
  Agent,
  BundleRef,
  Revision,
  workspaceLabel,
  bundleRefsLabel,
} from "../lib/api";
import { BundlePicker } from "../components/BundlePicker";
import { HarnessPicker } from "../components/HarnessPicker";

// Per-harness models. Switching the harness re-defaults the model to the
// first entry. UI convenience only: the server validates the harness id but
// does NOT check the model belongs to the harness, so a mismatched model
// fails (murkily) at model-call time, not with a clean 422.
const REV_MODELS: Record<string, string[]> = {
  "claude-agent-sdk": ["claude-haiku-4-5", "claude-sonnet-5", "claude-opus-4-8"],
  codex: ["gpt-5.4-mini", "gpt-5.4", "gpt-5.6-sol"],
};
import { LoadingRows, ModalShell, PageHead, short } from "../components/bits";
import {
  WorkspacePicker,
  WorkspaceDraft,
  specToDraft,
  draftToInput,
} from "../components/WorkspacePicker";

type Tab = "agents" | "policies";

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
  const tab = ((params.get("tab") as Tab) || "agents") as Tab;
  const setTab = (t: Tab) => router.replace(t === "agents" ? "/agents" : `/agents?tab=${t}`);

  const [agents, setAgents] = useState<Agent[]>([]);
  const [open, setOpen] = useState<string | null>(null);
  const [revs, setRevs] = useState<Record<string, Revision[]>>({});
  const [addRev, setAddRev] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ agents: Agent[] }>("/agents");
      setAgents(r.agents);
    } finally {
      setLoading(false);
    }
  }, []);

  const loadRevs = useCallback(async (id: string) => {
    const r = await apiGet<{ revisions: Revision[] }>(`/agents/${id}`);
    setRevs((prev) => ({ ...prev, [id]: r.revisions }));
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load().catch(() => {}), 0);
    return () => clearTimeout(first);
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
        title="Agents"
        sub="Versioned recipes and the policies that govern them. Editing appends an immutable revision — running sessions keep their frozen spec."
        right={
          tab === "agents" ? (
            <Link className="btn primary" href="/agents/new">
              <Plus /> New agent
            </Link>
          ) : undefined
        }
      />

      <div className="tabs">
        <button className={`tab ${tab === "agents" ? "active" : ""}`} onClick={() => setTab("agents")}>
          Agents
          <span className="n">{agents.length}</span>
        </button>
        <button className={`tab ${tab === "policies" ? "active" : ""}`} onClick={() => setTab("policies")}>
          Policies
        </button>
      </div>

      {tab === "policies" ? <PoliciesTab /> : agentsList()}

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
          ) : agents.length === 0 ? (
            <div className="empty">
              <Bot />
              <div>No agents yet.</div>
              <div className="act">
                <Link className="btn" href="/agents/new">
                  <Plus /> Create your first agent
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
                    <span className="task mut">{a.description || "—"}</span>
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
                          <span className="chip">image {short(r.runner_image, 24)}</span>
                        </div>
                      ))}
                      <button className="btn sm" style={{ marginTop: 12 }} onClick={() => setAddRev(a.id)}>
                        <Plus /> Add revision
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

/* ─── Policies tab (YAML editor, versioned saves) ────────────────────── */

interface PolicyRow {
  id: string;
  name: string;
  version: number;
  yaml_source: string;
}

function PoliciesTab() {
  const [policies, setPolicies] = useState<PolicyRow[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [yaml, setYaml] = useState("");
  const [name, setName] = useState("");
  const [validity, setValidity] = useState<{ ok: boolean; msg: string } | null>(null);
  const [saved, setSaved] = useState(false);

  const load = useCallback(async () => {
    const r = await apiGet<{ policies: PolicyRow[] }>("/policies");
    setPolicies(r.policies);
    if (!selected && r.policies.length) {
      const first = r.policies[0];
      setSelected(first.id);
      setName(first.name);
      setYaml(first.yaml_source);
    }
  }, [selected]);

  useEffect(() => {
    const first = window.setTimeout(() => void load().catch(() => {}), 0);
    return () => clearTimeout(first);
  }, [load]);

  const pick = (p: PolicyRow) => {
    setSelected(p.id);
    setName(p.name);
    setYaml(p.yaml_source);
    setValidity(null);
    setSaved(false);
  };

  const validate = async () => {
    try {
      const r = await apiPost<{ valid: boolean; name: string }>("/policies/validate", { yaml });
      setValidity({ ok: true, msg: `valid · ${r.name}` });
    } catch (e) {
      setValidity({ ok: false, msg: String(e).replace(/^Error:\s*/, "") });
    }
  };

  const save = async () => {
    setSaved(false);
    try {
      await apiPost("/policies", { name, yaml });
      setValidity({ ok: true, msg: "saved — new version created" });
      setSaved(true);
      load();
    } catch (e) {
      setValidity({ ok: false, msg: String(e).replace(/^Error:\s*/, "") });
    }
  };

  return (
    <>
      <p className="helper" style={{ margin: "0 0 12px", maxWidth: 640 }}>
        First match wins over tool calls. Fail-safe defaults: unknown tools ask a human, and
        autonomy narrows authority — it never widens it. Saving creates a new version; in-flight
        runs keep their snapshot.
      </p>
      <div style={{ display: "grid", gridTemplateColumns: "200px 1fr", gap: 16, alignItems: "start" }}>
        <div className="panel">
          <div className="rows">
            {policies.map((p) => (
              <div
                key={p.id}
                className="row click"
                style={{
                  gridTemplateColumns: "1fr",
                  cursor: "pointer",
                  background: selected === p.id ? "var(--raised)" : undefined,
                }}
                onClick={() => pick(p)}
              >
                <span className="mono" style={{ fontSize: 12.5, color: selected === p.id ? "var(--accent)" : "var(--ink)" }}>
                  {p.name}
                  <span className="faint" style={{ marginLeft: 8, fontSize: 11 }}>
                    v{p.version}
                  </span>
                </span>
              </div>
            ))}
          </div>
        </div>

        <div>
          <textarea
            className="inp code"
            value={yaml}
            onChange={(e) => {
              setYaml(e.target.value);
              setSaved(false);
            }}
            spellCheck={false}
          />
          <div className="spread" style={{ marginTop: 12 }}>
            <div className="mono" style={{ fontSize: 12.5 }}>
              {validity && (
                <span style={{ color: validity.ok ? "var(--green)" : "var(--red)" }}>
                  {validity.ok ? "✓ " : "✗ "}
                  {validity.msg}
                </span>
              )}
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn" onClick={validate}>
                Validate
              </button>
              <button className="btn primary" onClick={save}>
                {saved ? "✓ Saved" : "Save version"}
              </button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
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
  const [harness, setHarness] = useState(current?.harness || "claude-agent-sdk");
  const [model, setModel] = useState(current?.model || "claude-haiku-4-5");
  const [systemPrompt, setSystemPrompt] = useState(current?.system_prompt || "");
  const [workspace, setWorkspace] = useState<WorkspaceDraft>(specToDraft(current?.default_workspace));
  const [pins, setPins] = useState<BundleRef[]>(current?.capability_bundles ?? []);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    setBusy(true);
    try {
      // Inherits policy/image/budgets from the latest revision.
      // The workspace is sent explicitly (WYSIWYG): scratch clears a default.
      // Capability pins are WYSIWYG too: exactly the name@version refs
      // shown in the picker are attached (§17 #7 — nothing floats, and an
      // existing pin never upgrades unless its version was changed here).
      await apiPost(`/agents/${agentId}/revisions`, {
        harness,
        model,
        system_prompt: systemPrompt.trim() || null,
        default_workspace: draftToInput(workspace),
        capability_bundles: pins.map((p) => `${p.name}@${p.version}`),
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
    >
      <div className="field">
        <span className="lab">Harness</span>
        <HarnessPicker
          value={harness}
          onChange={(h) => {
            setHarness(h);
            setModel(REV_MODELS[h]?.[0] ?? ""); // never carry a cross-harness model
          }}
        />
      </div>
      <label className="field">
        <span className="lab">Model</span>
        <select className="inp" value={model} onChange={(e) => setModel(e.target.value)}>
          {(REV_MODELS[harness] ?? []).map((m) => (
            <option key={m} value={m}>
              {m}
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
      <WorkspacePicker draft={workspace} onChange={setWorkspace} />
      <BundlePicker pins={pins} onChange={setPins} />
      {err && <div className="err">{err}</div>}
      <div className="spread" style={{ marginTop: 14 }}>
        <span className="helper">Inherits harness · policy · image · budgets.</span>
        <button className="btn primary" onClick={submit} disabled={busy}>
          {busy ? "Appending…" : "Append revision"}
        </button>
      </div>
    </ModalShell>
  );
}
