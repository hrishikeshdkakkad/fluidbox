"use client";

// Full-page agent composer. An agent is a versioned recipe: identity +
// model/instructions (the SYSTEM prompt — who the agent is; the task is
// asked per run) + default workspace + pinned capability bundles. The right
// rail previews exactly what freezes into revision 1.

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Check, Play } from "lucide-react";
import { apiPost, BundleRef } from "../../lib/api";
import { PageHead } from "../../components/bits";
import { BundlePicker } from "../../components/BundlePicker";
import { HarnessPicker } from "../../components/HarnessPicker";
import {
  WorkspacePicker,
  WorkspaceDraft,
  emptyDraft,
  draftToInput,
} from "../../components/WorkspacePicker";

const MODELS = [
  {
    id: "claude-haiku-4-5",
    name: "Haiku 4.5",
    hint: "Fast and inexpensive — the default for most agents.",
  },
  {
    id: "claude-sonnet-5",
    name: "Sonnet 5",
    hint: "Balanced depth and speed for harder tasks.",
  },
  {
    id: "claude-opus-4-8",
    name: "Opus 4.8",
    hint: "Deepest reasoning; slowest and priciest.",
  },
];

export default function NewAgent() {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [harness, setHarness] = useState("claude-agent-sdk");
  const [model, setModel] = useState("claude-haiku-4-5");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [workspace, setWorkspace] = useState<WorkspaceDraft>(emptyDraft("scratch"));
  const [pins, setPins] = useState<BundleRef[]>([]);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    if (!name.trim()) {
      setErr("A name is required.");
      return;
    }
    setBusy(true);
    try {
      const bundles = pins.map((p) => `${p.name}@${p.version}`);
      await apiPost("/agents", {
        name: name.trim(),
        description: description.trim() || null,
        harness,
        model,
        system_prompt: systemPrompt.trim() || null,
        policy: "default",
        default_workspace: draftToInput(workspace),
        capability_bundles: bundles.length > 0 ? bundles : null,
      });
      router.push("/agents");
    } catch (e) {
      setErr(String(e));
      setBusy(false);
    }
  };

  const wsLabel =
    workspace.mode === "scratch"
      ? "scratch"
      : workspace.mode === "local"
        ? `local: ${workspace.path.trim() || "—"}`
        : (workspace.repository || workspace.cloneUrl.trim() || "—") +
          (workspace.ref.trim() ? `@${workspace.ref.trim()}` : "");

  return (
    <>
      <PageHead
        crumbs={[{ href: "/agents", label: "Agents" }]}
        title="New agent"
        sub="Compose a versioned recipe. Everything here freezes into revision 1 — editing later appends revision 2, it never mutates."
      />

      <div className="composer">
        <div className="col">
          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              Identity
            </div>
            <label className="field">
              <span className="lab">Name</span>
              <input
                className="inp mono"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="pr-fixer"
                autoFocus
              />
            </label>
            <label className="field" style={{ marginBottom: 0 }}>
              <span className="lab">Description (optional)</span>
              <input
                className="inp"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Reviews pull requests and fixes what it finds"
              />
            </label>
          </div>

          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              Harness
            </div>
            <HarnessPicker value={harness} onChange={setHarness} />
            <p className="helper" style={{ margin: "8px 0 0" }}>
              The brain that runs inside the sandbox. Every harness speaks the same runner
              contract, so policy, approvals, and the audit ledger work identically.
            </p>
          </div>

          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              Model
            </div>
            <div className="opt-grid">
              {MODELS.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  className={`opt ${model === m.id ? "on" : ""}`}
                  onClick={() => setModel(m.id)}
                >
                  <span className="t">
                    {m.name}
                    {model === m.id && <Check />}
                  </span>
                  <div className="id">{m.id}</div>
                  <div className="d">{m.hint}</div>
                </button>
              ))}
            </div>
          </div>

          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              Instructions
            </div>
            <label className="field" style={{ marginBottom: 0 }}>
              <span className="lab">System prompt (optional) — who this agent is</span>
              <textarea
                className="inp mono"
                style={{ minHeight: 120, fontSize: 12.5, lineHeight: 1.6 }}
                value={systemPrompt}
                onChange={(e) => setSystemPrompt(e.target.value)}
                placeholder={"You are a careful reviewer. Prefer minimal diffs, cite file:line,\nand never touch generated code."}
              />
            </label>
            <p className="helper" style={{ margin: "8px 0 0" }}>
              The system prompt travels with the agent. The <i>task</i> — what to do this time
              — is asked on every run.
            </p>
          </div>

          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              Default workspace
            </div>
            <WorkspacePicker draft={workspace} onChange={setWorkspace} />
            <p className="helper" style={{ margin: "2px 0 0" }}>
              Where runs start unless overridden at run time.
            </p>
          </div>

          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              Capabilities
            </div>
            <BundlePicker pins={pins} onChange={setPins} />
            <p className="helper" style={{ margin: "2px 0 0" }}>
              Attach ≠ allow — every tool call still passes the permission gate under the
              agent&apos;s policy.
            </p>
          </div>
        </div>

        <aside className="preview">
          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              Revision 1 preview
            </div>
            <div className="spec-row">
              <span className="k">name</span>
              <span className="v" style={{ color: name.trim() ? "var(--accent)" : "var(--ink-3)" }}>
                {name.trim() || "unnamed"}
              </span>
            </div>
            <div className="spec-row">
              <span className="k">harness</span>
              <span className="v">{harness}</span>
            </div>
            <div className="spec-row">
              <span className="k">model</span>
              <span className="v">{model}</span>
            </div>
            <div className="spec-row">
              <span className="k">policy</span>
              <span className="v">default</span>
            </div>
            <div className="spec-row">
              <span className="k">workspace</span>
              <span className="v">{wsLabel}</span>
            </div>
            <div className="spec-row">
              <span className="k">bundles</span>
              <span className="v">
                {pins.length === 0 ? "none" : pins.map((p) => `${p.name}@${p.version}`).join(" · ")}
              </span>
            </div>
            <div className="spec-row">
              <span className="k">prompt</span>
              <span className="v">
                {systemPrompt.trim()
                  ? `${systemPrompt.trim().split("\n").length} line${systemPrompt.trim().split("\n").length === 1 ? "" : "s"}`
                  : "none"}
              </span>
            </div>
            <div className="spec-row">
              <span className="k">inherits</span>
              <span className="v">image · budgets</span>
            </div>
          </div>

          {err && <div className="err" style={{ marginTop: 0 }}>{err}</div>}

          <button className="btn primary" onClick={submit} disabled={busy} style={{ justifyContent: "center" }}>
            <Play /> {busy ? "Creating…" : "Create agent"}
          </button>
          <p className="helper" style={{ margin: 0, textAlign: "center" }}>
            Agents are append-only — in-flight runs are never affected by later revisions.
          </p>
        </aside>
      </div>
    </>
  );
}
