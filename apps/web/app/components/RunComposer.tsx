"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Agent,
  apiGet,
  apiPost,
  BundleRef,
  Connection,
  Revision,
  TriggerSubscription,
} from "../lib/api";
import { AddServerWizard } from "../capabilities/AddServerWizard";
import { defaultModelFor, modelsFor, useHarnesses } from "../lib/harnesses";
import { BundlePicker } from "./BundlePicker";
import { HarnessPicker } from "./HarnessPicker";
import {
  draftToInput,
  emptyDraft,
  specToDraft,
  WorkspaceDraft,
  WorkspacePicker,
} from "./WorkspacePicker";
import { ModalShell } from "./bits";

export type RunMode = "once" | "automation";
type TriggerKind = "api" | "schedule" | "event";
type AgentChoice = "existing" | "new";
type ComposerStep = "run" | "agent" | "resources" | "controls" | "review";

export interface MintedAutomation {
  subscription: TriggerSubscription;
  token: string;
  callback_secret: string | null;
  ingress_path?: string | null;
  rotated?: boolean;
}

const STEP_LABELS: Record<ComposerStep, string> = {
  run: "Run",
  agent: "Agent",
  resources: "Workspace & tools",
  controls: "Controls",
  review: "Review",
};

function workspaceSummary(workspace: WorkspaceDraft): string {
  if (workspace.mode === "scratch") return "Scratch sandbox";
  if (workspace.mode === "local") return workspace.path.trim() || "Local path not set";
  if (workspace.mode === "git") {
    const repository = workspace.repository || workspace.cloneUrl.trim() || "Repository not set";
    return workspace.ref.trim() ? `${repository}@${workspace.ref.trim()}` : repository;
  }
  return "Agent default";
}

export function RunComposer({
  initialMode = "once",
  agentOnly = false,
  onClose,
  onRunCreated,
  onAutomationCreated,
  onAgentCreated,
}: {
  initialMode?: RunMode;
  agentOnly?: boolean;
  onClose: () => void;
  onRunCreated: () => void;
  onAutomationCreated: (minted: MintedAutomation) => void;
  onAgentCreated?: () => void;
}) {
  const { harnesses, loading: harnessesLoading, error: harnessesError, reload: reloadHarnesses } = useHarnesses();
  const steps = useMemo<ComposerStep[]>(
    () => (agentOnly ? ["agent", "resources", "review"] : ["run", "agent", "resources", "controls", "review"]),
    [agentOnly]
  );
  const [stepIndex, setStepIndex] = useState(0);
  const step = steps[stepIndex];
  const stageRef = useRef<HTMLDivElement>(null);

  const [mode, setMode] = useState<RunMode>(initialMode);
  const [task, setTask] = useState("");
  const [autonomous, setAutonomous] = useState(false);

  const [agents, setAgents] = useState<Agent[]>([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [agentChoice, setAgentChoice] = useState<AgentChoice>(agentOnly ? "new" : "existing");
  const [selectedAgentName, setSelectedAgentName] = useState("");
  const [revisionLoading, setRevisionLoading] = useState(false);
  const [revisionTouched, setRevisionTouched] = useState(false);

  const [newAgentName, setNewAgentName] = useState("");
  const [description, setDescription] = useState("");
  const [harness, setHarness] = useState("claude-agent-sdk");
  const [model, setModel] = useState("claude-haiku-4-5");
  const [systemPrompt, setSystemPrompt] = useState("");
  const [workspace, setWorkspace] = useState<WorkspaceDraft>(emptyDraft("scratch"));
  const [pins, setPins] = useState<BundleRef[]>([]);
  const [capabilityRefresh, setCapabilityRefresh] = useState(0);
  const [addingMcp, setAddingMcp] = useState(false);

  const [kind, setKind] = useState<TriggerKind>("api");
  const [automationName, setAutomationName] = useState("");
  const [allowTask, setAllowTask] = useState(false);
  const [allowWorkspace, setAllowWorkspace] = useState(false);
  const [callbackUrl, setCallbackUrl] = useState("");
  const [concurrency, setConcurrency] = useState("allow");
  const [cron, setCron] = useState("");
  const [timezone, setTimezone] = useState("UTC");
  const [missedPolicy, setMissedPolicy] = useState("skip");
  const [connections, setConnections] = useState<Connection[]>([]);
  const [connection, setConnection] = useState("");
  const [repositories, setRepositories] = useState("");
  const [evOpened, setEvOpened] = useState(true);
  const [evReopened, setEvReopened] = useState(true);
  const [evSync, setEvSync] = useState(false);
  const [pubComment, setPubComment] = useState(true);
  const [pubCheck, setPubCheck] = useState(false);
  const [capabilityKeepList, setCapabilityKeepList] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    let active = true;
    apiGet<{ agents: Agent[] }>("/agents")
      .then((response) => {
        if (!active) return;
        setAgents(response.agents);
        if (response.agents.length === 0) {
          setAgentChoice("new");
        } else {
          setSelectedAgentName((current) => current || response.agents[0].name);
        }
      })
      .catch((reason) => active && setErr(`Agents could not be loaded. ${String(reason)}`))
      .finally(() => active && setAgentsLoading(false));
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (agentChoice !== "existing" || !selectedAgentName) return;
    const selected = agents.find((candidate) => candidate.name === selectedAgentName);
    if (!selected) return;
    let active = true;
    const start = window.setTimeout(() => {
      setRevisionLoading(true);
      setErr("");
      apiGet<{ revisions: Revision[] }>(`/agents/${selected.id}`)
        .then((response) => {
          if (!active) return;
          const latest = response.revisions[0] ?? null;
          if (latest) {
            setHarness(latest.harness);
            setModel(latest.model);
            setSystemPrompt(latest.system_prompt || "");
            setWorkspace(specToDraft(latest.default_workspace));
            setPins(latest.capability_bundles ?? []);
          }
          setRevisionTouched(false);
        })
        .catch((reason) => active && setErr(`The agent revision could not be loaded. ${String(reason)}`))
        .finally(() => active && setRevisionLoading(false));
    }, 0);
    return () => {
      active = false;
      window.clearTimeout(start);
    };
  }, [agentChoice, agents, selectedAgentName]);

  useEffect(() => {
    if (mode !== "automation" || kind !== "event" || connections.length > 0) return;
    apiGet<{ connections: Connection[] }>("/connections")
      .then((response) => {
        const activeApps = response.connections.filter(
          (candidate) => candidate.provider === "github_app" && candidate.status === "active"
        );
        setConnections(activeApps);
        setConnection((current) => current || activeApps[0]?.id || "");
      })
      .catch(() => {});
  }, [connections.length, kind, mode]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      stageRef.current?.focus({ preventScroll: true });
      stageRef.current?.closest<HTMLElement>(".modal")?.scrollTo({ top: 0 });
    }, 0);
    return () => window.clearTimeout(timer);
  }, [stepIndex]);

  const touchRevision = () => {
    if (agentChoice === "existing") setRevisionTouched(true);
  };

  const chooseNewAgent = () => {
    const defaultHarness = harnesses.find((candidate) => candidate.available)?.id || "claude-agent-sdk";
    setAgentChoice("new");
    setHarness(defaultHarness);
    setModel(defaultModelFor(harnesses, defaultHarness) || "claude-haiku-4-5");
    setSystemPrompt("");
    setWorkspace(emptyDraft("scratch"));
    setPins([]);
    setRevisionTouched(false);
  };

  const validateStep = (): string => {
    if (step === "run") {
      if (mode === "once" && !task.trim()) return "Describe what this run should accomplish.";
      if (mode === "automation" && !automationName.trim()) return "Give this automation a unique name.";
    }
    if (step === "agent") {
      if (agentsLoading || revisionLoading) return "Wait for the agent configuration to finish loading.";
      if (agentChoice === "existing" && !selectedAgentName) return "Choose an agent or create one here.";
      if (agentChoice === "new" && !newAgentName.trim()) return "Give the new agent a name.";
      if (harnessesError) return "Reload the runtime catalog before continuing.";
      if (harnessesLoading || harnesses.length === 0 || !model) return "Wait for the runtime and model catalog to load.";
    }
    if (step === "resources") {
      if (workspace.mode === "local" && !workspace.path.trim()) return "Enter the local workspace path.";
      if (workspace.mode === "git" && !(workspace.repository || workspace.cloneUrl.trim())) {
        return "Choose a repository or provide its public clone URL.";
      }
    }
    if (step === "controls" && mode === "automation") {
      if (kind === "schedule" && !cron.trim()) return "Enter the schedule as a cron expression.";
      if (kind === "event" && !connection) return "Choose an active GitHub App connection.";
    }
    return "";
  };

  const next = () => {
    const issue = validateStep();
    if (issue) {
      setErr(issue);
      return;
    }
    setErr("");
    setStepIndex((current) => Math.min(current + 1, steps.length - 1));
  };

  const previous = () => {
    setErr("");
    setAddingMcp(false);
    setStepIndex((current) => Math.max(0, current - 1));
  };

  const submit = async () => {
    setErr("");
    setBusy(true);
    let createdAgent: Agent | null = null;
    try {
      let runAgentName = selectedAgentName;
      if (agentChoice === "new") {
        const response = await apiPost<{ agent: Agent }>("/agents", {
          name: newAgentName.trim(),
          description: description.trim() || null,
          harness,
          model,
          system_prompt: systemPrompt.trim() || null,
          policy: "default",
          default_workspace: draftToInput(workspace),
          capability_bundles: pins.map((pin) => `${pin.name}@${pin.version}`),
        });
        createdAgent = response.agent;
        runAgentName = response.agent.name;
      } else if (revisionTouched) {
        const selected = agents.find((candidate) => candidate.name === selectedAgentName);
        if (!selected) throw new Error("The selected agent is no longer available.");
        await apiPost(`/agents/${selected.id}/revisions`, {
          harness,
          model,
          system_prompt: systemPrompt.trim() || null,
          default_workspace: draftToInput(workspace),
          capability_bundles: pins.map((pin) => `${pin.name}@${pin.version}`),
        });
        setRevisionTouched(false);
      }

      if (agentOnly) {
        onAgentCreated?.();
        return;
      }

      if (mode === "once") {
        await apiPost("/sessions", { agent: runAgentName, task: task.trim(), autonomous });
        onRunCreated();
        return;
      }

      const body: Record<string, unknown> = {
        agent: runAgentName,
        name: automationName.trim(),
        allow_task_override: allowTask,
        allow_workspace_override: allowWorkspace,
        autonomous,
      };
      if (task.trim()) body.task_template = task.trim();
      if (callbackUrl.trim()) body.callback_url = callbackUrl.trim();
      if (concurrency !== "allow") body.concurrency_policy = concurrency;
      if (capabilityKeepList.trim()) {
        body.capabilities = capabilityKeepList.split(",").map((value) => value.trim()).filter(Boolean);
      }
      if (kind === "schedule") {
        body.schedule = {
          cron: cron.trim(),
          timezone: timezone.trim() || "UTC",
          missed_run_policy: missedPolicy,
        };
      }
      if (kind === "event") {
        body.connection = connection;
        const selectedRepositories = repositories.split(",").map((repository) => repository.trim()).filter(Boolean);
        if (selectedRepositories.length > 0) body.repositories = selectedRepositories;
        body.events = [
          ...(evOpened ? ["pull_request.opened"] : []),
          ...(evReopened ? ["pull_request.reopened"] : []),
          ...(evSync ? ["pull_request.synchronize"] : []),
        ];
        body.publish = [
          ...(pubComment ? ["pr_comment"] : []),
          ...(pubCheck ? ["check"] : []),
        ];
      }

      const response = await apiPost<{
        subscription: TriggerSubscription;
        token: string;
        callback_secret: string | null;
        ingress_path: string | null;
      }>("/triggers", body);
      onAutomationCreated(response);
    } catch (reason) {
      if (createdAgent) {
        setAgents((current) => [...current, createdAgent as Agent]);
        setSelectedAgentName(createdAgent.name);
        setAgentChoice("existing");
      }
      setErr(String(reason));
      setBusy(false);
    }
  };

  const templateHint =
    kind === "schedule"
      ? "You can use {{fire_time}} in these instructions."
      : kind === "event"
        ? "Pull request values such as {{repository}}, {{pr_number}}, and {{pr_title}} are available."
        : "API callers can supply values for placeholders such as {{ticket}}.";

  const agentDisplayName = agentChoice === "new" ? newAgentName.trim() || "New agent" : selectedAgentName;
  const finalAction = agentOnly ? "Create Agent" : mode === "once" ? "Start Run" : "Save Automation";

  return (
    <ModalShell
      title={agentOnly ? "Create Agent" : "Configure Run"}
      sub={
        agentOnly
          ? "Define the agent, give it a workspace and capabilities, then review one immutable revision."
          : "Everything needed for this run lives in one guided flow — including a new agent or MCP server."
      }
      onClose={onClose}
      wide
    >
      <nav className="creation-steps" aria-label="Creation progress">
        {steps.map((candidate, index) => (
          <button
            key={candidate}
            type="button"
            className={`${index === stepIndex ? "current" : ""} ${index < stepIndex ? "complete" : ""}`}
            onClick={() => index < stepIndex && setStepIndex(index)}
            disabled={index > stepIndex}
          >
            <span>{index + 1}</span>
            {STEP_LABELS[candidate]}
          </button>
        ))}
      </nav>

      <div className="creation-stage" ref={stageRef} tabIndex={-1}>
        {step === "run" && (
          <>
            <div className="stage-heading">
              <span className="section-kicker">Step 1</span>
              <h2>What should happen?</h2>
              <p>Launch once now, or save the same governed run behind a trigger.</p>
            </div>
            <div className="run-mode-selector" aria-label="Run frequency">
              <button
                type="button"
                className={`run-mode-option ${mode === "once" ? "selected" : ""}`}
                aria-pressed={mode === "once"}
                onClick={() => setMode("once")}
              >
                <span><strong>Run once</strong><small>Start a fresh sandbox now</small></span>
              </button>
              <button
                type="button"
                className={`run-mode-option ${mode === "automation" ? "selected" : ""}`}
                aria-pressed={mode === "automation"}
                onClick={() => setMode("automation")}
              >
                <span><strong>Automation</strong><small>Start from an API, schedule, or event</small></span>
              </button>
            </div>
            {mode === "automation" && (
              <div className="automation-setup">
                <label className="field">
                  <span className="lab">Automation name</span>
                  <input className="inp mono" value={automationName} onChange={(event) => setAutomationName(event.target.value)} placeholder="weekday-incident-triage" autoFocus />
                </label>
                <div className="field">
                  <span className="lab">Start this run from</span>
                  <div className="seg trigger-kind-selector">
                    <button type="button" className={kind === "api" ? "on" : ""} onClick={() => setKind("api")}>API call</button>
                    <button type="button" className={kind === "schedule" ? "on" : ""} onClick={() => setKind("schedule")}>Schedule</button>
                    <button type="button" className={kind === "event" ? "on" : ""} onClick={() => setKind("event")}>Pull request</button>
                  </div>
                </div>
              </div>
            )}
            <label className="field">
              <span className="lab">
                {mode === "once" ? "What should the agent accomplish?" : "What should happen each time?"}
                {mode === "automation" && <span className="optional-label"> optional template</span>}
              </span>
              <textarea
                className="inp run-task-input"
                value={task}
                onChange={(event) => setTask(event.target.value)}
                placeholder={mode === "once" ? "Review the latest changes, identify regressions, and prepare a safe patch…" : "Investigate {{ticket}} and report the root cause…"}
                autoFocus={mode === "once"}
              />
              {mode === "automation" && <span className="field-hint">{templateHint}</span>}
            </label>
          </>
        )}

        {step === "agent" && (
          <>
            <div className="stage-heading">
              <span className="section-kicker">Agent definition</span>
              <h2>{agentOnly ? "Define the new agent" : agents.length === 0 && !agentsLoading ? "Create the first agent" : "Choose or create the agent"}</h2>
              <p>The agent owns the reusable runtime, model, and identity. The run-specific task stays separate.</p>
            </div>
            {!agentOnly && (
              <div className="choice-cards" aria-label="Agent source">
                <button
                  type="button"
                  className={agentChoice === "existing" ? "selected" : ""}
                  disabled={agents.length === 0}
                  onClick={() => setAgentChoice("existing")}
                >
                  <strong>Use an existing agent</strong>
                  <span>{agents.length > 0 ? `${agents.length} available` : "None created yet"}</span>
                </button>
                <button type="button" className={agentChoice === "new" ? "selected" : ""} onClick={chooseNewAgent}>
                  <strong>Create a new agent</strong>
                  <span>Define it without leaving this run</span>
                </button>
              </div>
            )}

            {agentChoice === "existing" ? (
              <div className="field">
                <span className="lab">Agent</span>
                <div className="opt-grid">
                  {agents.map((candidate) => (
                    <button
                      key={candidate.id}
                      type="button"
                      className={`opt ${selectedAgentName === candidate.name ? "on" : ""}`}
                      onClick={() => setSelectedAgentName(candidate.name)}
                    >
                      <span className="t">
                        {candidate.name}
                        {selectedAgentName === candidate.name && (
                          <span className="selected-label">Selected</span>
                        )}
                      </span>
                    </button>
                  ))}
                </div>
                <span className="field-hint">Changes below append a new revision; active runs keep their original frozen revision.</span>
              </div>
            ) : (
              <div className="agent-creator-grid">
                <label className="field">
                  <span className="lab">Name</span>
                  <input className="inp mono" value={newAgentName} onChange={(event) => setNewAgentName(event.target.value)} placeholder="release-reviewer" autoFocus />
                </label>
                <label className="field">
                  <span className="lab">Description <span className="optional-label">optional</span></span>
                  <input className="inp" value={description} onChange={(event) => setDescription(event.target.value)} placeholder="Reviews changes and prepares a concise release report" />
                </label>
              </div>
            )}

            {harnessesLoading || revisionLoading ? (
              <div className="catalog-state"><strong>Loading runtime catalog…</strong><span>Fetching supported harnesses and models from the control plane.</span></div>
            ) : harnessesError ? (
              <div className="catalog-state error-state">
                <div><strong>Runtime catalog did not load.</strong><span>{harnessesError}</span></div>
                <button className="btn" type="button" onClick={reloadHarnesses}>Retry</button>
              </div>
            ) : (
              <>
                <div className="agent-creator-section">
                  <span className="lab">Runtime</span>
                  <HarnessPicker
                    harnesses={harnesses}
                    value={harness}
                    onChange={(nextHarness) => {
                      setHarness(nextHarness);
                      setModel(defaultModelFor(harnesses, nextHarness));
                      touchRevision();
                    }}
                  />
                </div>
                <div className="agent-creator-section">
                  <span className="lab">Model</span>
                  <div className="opt-grid compact-options">
                    {modelsFor(harnesses, harness).map((candidate) => (
                      <button
                        key={candidate.id}
                        type="button"
                        className={`opt ${model === candidate.id ? "on" : ""}`}
                        onClick={() => {
                          setModel(candidate.id);
                          touchRevision();
                        }}
                      >
                        <span className="t">{candidate.display_name}{model === candidate.id && <span className="selected-label">Selected</span>}</span>
                        <span className="id">{candidate.id}</span>
                        <span className="d">{candidate.hint}</span>
                      </button>
                    ))}
                  </div>
                </div>
              </>
            )}
            <label className="field">
              <span className="lab">System instructions <span className="optional-label">optional</span></span>
              <textarea
                className="inp mono agent-instructions"
                value={systemPrompt}
                onChange={(event) => {
                  setSystemPrompt(event.target.value);
                  touchRevision();
                }}
                placeholder="You are a careful reviewer. Prefer minimal changes and explain consequential decisions."
              />
            </label>
          </>
        )}

        {step === "resources" && (
          addingMcp ? (
            <AddServerWizard
              embedded
              onClose={() => setAddingMcp(false)}
              onCompleted={(bundle) => {
                setCapabilityRefresh((current) => current + 1);
                if (bundle && !pins.some((pin) => pin.name === bundle.name)) {
                  setPins((current) => [...current, { id: "", name: bundle.name, version: bundle.version }]);
                  touchRevision();
                }
              }}
            />
          ) : (
            <>
              <div className="stage-heading">
                <span className="section-kicker">Run context</span>
                <h2>Give the agent what it needs</h2>
                <p>Select the workspace and attach existing capability bundles, or connect a new MCP server here.</p>
              </div>
              {agentChoice === "existing" && (
                <div className="revision-note"><strong>Revision-safe change</strong><span>Any workspace or capability change will append a new revision to {selectedAgentName} before this run starts.</span></div>
              )}
              <WorkspacePicker
                draft={workspace}
                onChange={(nextWorkspace) => {
                  setWorkspace(nextWorkspace);
                  touchRevision();
                }}
              />
              <BundlePicker
                pins={pins}
                refreshKey={capabilityRefresh}
                onAddServer={() => setAddingMcp(true)}
                onChange={(nextPins) => {
                  setPins(nextPins);
                  touchRevision();
                }}
              />
            </>
          )
        )}

        {step === "controls" && (
          <>
            <div className="stage-heading">
              <span className="section-kicker">Governance</span>
              <h2>{mode === "once" ? "Choose the run boundary" : "Configure the trigger and boundary"}</h2>
              <p>Supervised runs pause before risky actions. Autonomous runs defer to the configured policy.</p>
            </div>

            {mode === "automation" && kind === "schedule" && (
              <div className="automation-config-grid">
                <label className="field">
                  <span className="lab">Schedule</span>
                  <input className="inp mono" value={cron} onChange={(event) => setCron(event.target.value)} placeholder="0 7 * * 1-5" />
                  <span className="field-hint">Standard 5-field cron, or 6 fields with seconds.</span>
                </label>
                <label className="field">
                  <span className="lab">Timezone</span>
                  <input className="inp mono" value={timezone} onChange={(event) => setTimezone(event.target.value)} placeholder="America/Chicago" />
                </label>
                <label className="field automation-grid-span">
                  <span className="lab">If a scheduled time was missed</span>
                  <select className="inp" value={missedPolicy} onChange={(event) => setMissedPolicy(event.target.value)}>
                    <option value="skip">Record the gap and resume the cadence</option>
                    <option value="catch_up">Start exactly one make-up run</option>
                  </select>
                </label>
              </div>
            )}

            {mode === "automation" && kind === "event" && (
              <div className="event-config">
                <label className="field">
                  <span className="lab">GitHub App connection</span>
                  <select className="inp" value={connection} onChange={(event) => setConnection(event.target.value)}>
                    {connections.length === 0 && <option value="">No active GitHub App connections</option>}
                    {connections.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.display_name}</option>)}
                  </select>
                </label>
                <label className="field">
                  <span className="lab">Repositories <span className="optional-label">optional</span></span>
                  <input className="inp mono" value={repositories} onChange={(event) => setRepositories(event.target.value)} placeholder="acme/site, acme/api" />
                  <span className="field-hint">Leave empty to use every repository visible to the connection.</span>
                </label>
                <div className="event-options">
                  <div>
                    <span className="lab">Events</span>
                    <label className="check"><input type="checkbox" checked={evOpened} onChange={(event) => setEvOpened(event.target.checked)} />Pull request opened</label>
                    <label className="check"><input type="checkbox" checked={evReopened} onChange={(event) => setEvReopened(event.target.checked)} />Pull request reopened</label>
                    <label className="check"><input type="checkbox" checked={evSync} onChange={(event) => setEvSync(event.target.checked)} />Every new commit <span className="faint">(cost amplifier)</span></label>
                  </div>
                  <div>
                    <span className="lab">Publish result</span>
                    <label className="check"><input type="checkbox" checked={pubComment} onChange={(event) => setPubComment(event.target.checked)} />Update one PR comment</label>
                    <label className="check"><input type="checkbox" checked={pubCheck} onChange={(event) => setPubCheck(event.target.checked)} />Create a check run</label>
                  </div>
                </div>
              </div>
            )}

            <button type="button" className={`toggle mode-card ${autonomous ? "on" : ""}`} onClick={() => setAutonomous((current) => !current)} aria-pressed={autonomous}>
              <span className="sw" />
              <span>
                <strong>{autonomous ? "Autonomous runs" : "Supervised runs"}</strong>
                <span className="faint mode-description">{autonomous ? "Policy fallback decides risky actions without waiting for a person." : "Risky actions pause and wait for your approval."}</span>
              </span>
            </button>

            {mode === "automation" && (
              <details className="advanced-config">
                <summary>Advanced automation controls</summary>
                <div className="advanced-config-body">
                  <label className="check"><input type="checkbox" checked={allowTask} onChange={(event) => setAllowTask(event.target.checked)} />Allow the caller to override the task</label>
                  <label className="check"><input type="checkbox" checked={allowWorkspace} onChange={(event) => setAllowWorkspace(event.target.checked)} />Allow a narrower workspace override within this automation&apos;s authority</label>
                  <label className="field">
                    <span className="lab">When another run is already active</span>
                    <select className="inp" value={concurrency} onChange={(event) => setConcurrency(event.target.value)}>
                      <option value="allow">Allow runs to overlap</option>
                      <option value="skip_if_running">Skip and record the invocation</option>
                      <option value="replace">Cancel the active run and start the new one</option>
                    </select>
                  </label>
                  <label className="field">
                    <span className="lab">Capability keep-list <span className="optional-label">optional</span></span>
                    <input className="inp mono" value={capabilityKeepList} onChange={(event) => setCapabilityKeepList(event.target.value)} placeholder="Empty keeps every attached bundle" />
                    <span className="field-hint">Comma-separated bundle names; this can only remove capabilities.</span>
                  </label>
                  <label className="field">
                    <span className="lab">Signed callback URL <span className="optional-label">optional</span></span>
                    <input className="inp" value={callbackUrl} onChange={(event) => setCallbackUrl(event.target.value)} placeholder="https://your-service.example/fluidbox/callback" />
                  </label>
                </div>
              </details>
            )}
          </>
        )}

        {step === "review" && (
          <>
            <div className="stage-heading">
              <span className="section-kicker">Ready to save</span>
              <h2>Review the frozen configuration</h2>
              <p>{agentOnly ? "This becomes revision 1 of the new agent." : "This is the configuration the run will use at launch."}</p>
            </div>
            <div className="review-grid">
              {!agentOnly && (
                <div className="review-card">
                  <span>Execution</span>
                  <strong>{mode === "once" ? "Run once" : automationName}</strong>
                  <small>{mode === "once" ? task : `${kind} trigger${task.trim() ? ` · ${task}` : ""}`}</small>
                </div>
              )}
              <div className="review-card">
                <span>Agent</span>
                <strong>{agentDisplayName}</strong>
                <small>{harness} · {model}</small>
              </div>
              <div className="review-card">
                <span>Workspace</span>
                <strong>{workspaceSummary(workspace)}</strong>
                <small>{pins.length} capability bundle{pins.length === 1 ? "" : "s"} attached</small>
              </div>
              {!agentOnly && (
                <div className="review-card">
                  <span>Governance</span>
                  <strong>{autonomous ? "Autonomous" : "Supervised"}</strong>
                  <small>{autonomous ? "Policy fallback handles risky actions" : "Risky actions wait for approval"}</small>
                </div>
              )}
            </div>
            {agentChoice === "existing" && revisionTouched && (
              <div className="revision-note"><strong>One new revision will be appended</strong><span>{selectedAgentName} remains immutable; this run uses the new workspace, model, instructions, and capability pins.</span></div>
            )}
          </>
        )}
      </div>

      {err && <div className="err creation-error">{err}</div>}

      <div className="modal-footer creation-footer">
        <div>
          {stepIndex > 0 && <button className="btn ghost" type="button" onClick={previous} disabled={busy}>Back</button>}
        </div>
        <span className="helper">Step {stepIndex + 1} of {steps.length}</span>
        {step === "review" ? (
          <button className="btn primary" type="button" onClick={submit} disabled={busy}>
            {busy ? "Saving…" : finalAction}
          </button>
        ) : (
          <button className="btn primary" type="button" onClick={next} disabled={addingMcp}>
            Continue
          </button>
        )}
      </div>
    </ModalShell>
  );
}

export function ShowAutomationSecrets({
  minted,
  onClose,
}: {
  minted: MintedAutomation;
  onClose: () => void;
}) {
  const curl = [
    "curl -X POST \\",
    `  -H "Authorization: Bearer ${minted.token}" \\`,
    '  -H "Idempotency-Key: my-key-1" \\',
    '  -H "Content-Type: application/json" \\',
    `  -d '{"context": {"ticket": "INC-42"}}' \\`,
    `  <control-plane>/v1/triggers/${minted.subscription.id}/invoke`,
  ].join("\n");

  return (
    <ModalShell
      title={minted.rotated ? "Token rotated" : `Automation “${minted.subscription.name}” saved`}
      sub="Copy these now. The token is stored hashed and the secret sealed, so neither can be shown again."
      onClose={onClose}
    >
      <label className="field">
        <span className="lab">Scoped trigger token</span>
        <pre className="token">{minted.token}</pre>
      </label>
      {minted.callback_secret && (
        <label className="field">
          <span className="lab">Callback signing secret</span>
          <pre className="token">{minted.callback_secret}</pre>
        </label>
      )}
      {minted.ingress_path && (
        <label className="field">
          <span className="lab">Event ingress</span>
          <pre className="token">{`<control-plane>${minted.ingress_path}`}</pre>
        </label>
      )}
      {!minted.rotated && (
        <label className="field">
          <span className="lab">Invoke example</span>
          <pre className="token token-example">{curl}</pre>
        </label>
      )}
      <div className="modal-footer secret-footer">
        <span className="helper">Store these values in your secret manager.</span>
        <button className="btn primary" type="button" onClick={onClose}>I copied them</button>
      </div>
    </ModalShell>
  );
}
