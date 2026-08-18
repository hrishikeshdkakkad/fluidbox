"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  apiGetCached,
  apiPost,
  BundleRef,
  ConnectionRequirement,
  NetworkGrantMode,
  NetworkRequest,
  PolicyContent,
  PolicySummary,
  Revision,
} from "../lib/api";
import { BundlePicker } from "./BundlePicker";
import { RequirementsEditor } from "./RequirementsEditor";
import { HarnessPicker } from "./HarnessPicker";
import { useHarnesses, modelsFor, defaultModelFor } from "../lib/harnesses";
import { ModalShell } from "./bits";
import { WorkspacePicker, WorkspaceDraft, specToDraft, draftToInput } from "./WorkspacePicker";
import { NetworkRequestEditor } from "./NetworkRequestEditor";
import { MODE_LABEL, networkOf, requestForWire } from "../lib/network";

// Appending a revision IS how an agent is edited — the definition is
// append-only, so a running session keeps the spec it started with. Lifted
// out of app/agents/page.tsx when the list stopped expanding rows: editing an
// agent now happens on that agent's own page, which is also the only place
// that shows what the current revision actually declares.
export function AddRevision({
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
