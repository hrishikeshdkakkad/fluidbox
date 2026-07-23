"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Agent,
  apiGetCached,
  apiPost,
  BundleRef,
  Connection,
  ConnectionRequirement,
  connectionMatchesConnector,
  isToolConnection,
  ownerBadge,
  Revision,
  TriggerSubscription,
} from "../lib/api";
import { AddServerWizard } from "../capabilities/AddServerWizard";
import { defaultModelFor, modelsFor, useHarnesses } from "../lib/harnesses";
import { useAuthMe } from "../lib/useAuthMe";
import { BundlePicker } from "./BundlePicker";
import { HarnessPicker } from "./HarnessPicker";
import { describeSchedule, localTimezone, parseCron, ScheduleBuilder } from "./ScheduleBuilder";
import {
  draftToInput,
  emptyDraft,
  specToDraft,
  WorkspaceDraft,
  WorkspacePicker,
} from "./WorkspacePicker";
import { ModalShell } from "./bits";
import { useSessionDraft } from "../lib/useSessionDraft";

export type RunMode = "once" | "automation";
type TriggerKind = "api" | "schedule" | "event";
type AgentChoice = "existing" | "new";
type PendingAgentSwitch =
  | { choice: "existing"; name: string }
  | { choice: "new" };

interface RunComposerDraft {
  version: 1;
  mode: RunMode;
  task: string;
  autonomous: boolean;
  agentChoice: AgentChoice;
  selectedAgentName: string;
  revisionTouched: boolean;
  newAgentName: string;
  description: string;
  harness: string;
  model: string;
  systemPrompt: string;
  workspace: WorkspaceDraft;
  pins: BundleRef[];
  requirements: ConnectionRequirement[];
  bindings: Record<string, string>;
  kind: TriggerKind;
  automationName: string;
  allowTask: boolean;
  allowWorkspace: boolean;
  callbackUrl: string;
  concurrency: string;
  cron: string;
  timezone: string;
  missedPolicy: string;
  connection: string;
  repositories: string;
  evOpened: boolean;
  evReopened: boolean;
  evSync: boolean;
  pubComment: boolean;
  pubCheck: boolean;
  capabilityKeepList: string;
}

function isRunComposerDraft(value: unknown): value is RunComposerDraft {
  if (!value || typeof value !== "object") return false;
  const draft = value as Partial<RunComposerDraft>;
  return (
    draft.version === 1 &&
    (draft.mode === "once" || draft.mode === "automation") &&
    (draft.agentChoice === "existing" || draft.agentChoice === "new") &&
    typeof draft.task === "string" &&
    !!draft.workspace &&
    typeof draft.workspace === "object" &&
    Array.isArray(draft.pins) &&
    Array.isArray(draft.requirements)
  );
}

export interface MintedAutomation {
  subscription: TriggerSubscription;
  token: string;
  callback_secret: string | null;
  ingress_path?: string | null;
  rotated?: boolean;
  /** Absolute, caller-facing URLs resolved by the control plane from
   *  FLUIDBOX_PUBLIC_URL. The dashboard cannot derive these — it reaches the
   *  API through a same-origin proxy — so the server hands them over. */
  base_url?: string | null;
  invoke_url?: string | null;
  poll_url_template?: string | null;
  ingress_url?: string | null;
}

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
  const me = useAuthMe();
  const { harnesses, loading: harnessesLoading, error: harnessesError, reload: reloadHarnesses } = useHarnesses();
  const formRef = useRef<HTMLDivElement>(null);

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
  // Phase C: the selected revision's declared brokered connection requirements,
  // and the invoking user's explicit per-slot binding overrides (slot →
  // connection id; "" = resolve automatically). Bindings ride POST /sessions.
  const [requirements, setRequirements] = useState<ConnectionRequirement[]>([]);
  const [bindings, setBindings] = useState<Record<string, string>>({});
  const [bindableConnections, setBindableConnections] = useState<Connection[]>([]);
  const [bindingConnectionsError, setBindingConnectionsError] = useState("");
  const [capabilityRefresh, setCapabilityRefresh] = useState(0);
  const [connectionRefresh, setConnectionRefresh] = useState(0);
  const [addingMcp, setAddingMcp] = useState(false);
  const [addingMcpDirty, setAddingMcpDirty] = useState(false);
  const [pendingAgentSwitch, setPendingAgentSwitch] = useState<PendingAgentSwitch | null>(null);

  const [kind, setKind] = useState<TriggerKind>("api");
  const [automationName, setAutomationName] = useState("");
  const [allowTask, setAllowTask] = useState(false);
  const [allowWorkspace, setAllowWorkspace] = useState(false);
  const [callbackUrl, setCallbackUrl] = useState("");
  const [concurrency, setConcurrency] = useState("allow");
  const [cron, setCron] = useState("");
  const [timezone, setTimezone] = useState(localTimezone);
  const [missedPolicy, setMissedPolicy] = useState("skip");
  const [connections, setConnections] = useState<Connection[]>([]);
  const [eventConnectionsError, setEventConnectionsError] = useState("");
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

  const draftKey = agentOnly
    ? "fluidbox:draft:new-agent"
    : "fluidbox:draft:run-composer";
  const draft = useMemo<RunComposerDraft>(
    () => ({
      version: 1,
      mode,
      task,
      autonomous,
      agentChoice,
      selectedAgentName,
      revisionTouched,
      newAgentName,
      description,
      harness,
      model,
      systemPrompt,
      workspace,
      pins,
      requirements,
      bindings,
      kind,
      automationName,
      allowTask,
      allowWorkspace,
      callbackUrl,
      concurrency,
      cron,
      timezone,
      missedPolicy,
      connection,
      repositories,
      evOpened,
      evReopened,
      evSync,
      pubComment,
      pubCheck,
      capabilityKeepList,
    }),
    [
      mode, task, autonomous, agentChoice, selectedAgentName, revisionTouched, newAgentName,
      description, harness, model, systemPrompt, workspace, pins, requirements, bindings, kind,
      automationName, allowTask, allowWorkspace, callbackUrl, concurrency, cron, timezone,
      missedPolicy, connection, repositories, evOpened, evReopened, evSync, pubComment, pubCheck,
      capabilityKeepList,
    ]
  );
  // Loading an existing revision is not user input. Only persist agent fields
  // when they belong to a new definition or the operator has actually edited
  // the existing revision; this avoids creating phantom drafts on every open.
  const hasAgentDefinitionDraft =
    agentChoice === "new"
      ? newAgentName.trim().length > 0 ||
        description.trim().length > 0 ||
        harness !== "claude-agent-sdk" ||
        model !== "claude-haiku-4-5" ||
        systemPrompt.trim().length > 0 ||
        workspace.mode !== "scratch" ||
        pins.length > 0 ||
        requirements.length > 0
      : revisionTouched;
  const hasDraft =
    mode !== initialMode ||
    task.trim().length > 0 ||
    autonomous ||
    hasAgentDefinitionDraft ||
    automationName.trim().length > 0 ||
    kind !== "api" ||
    allowTask ||
    allowWorkspace ||
    callbackUrl.trim().length > 0 ||
    concurrency !== "allow" ||
    cron.trim().length > 0 ||
    missedPolicy !== "skip" ||
    repositories.trim().length > 0 ||
    !evOpened ||
    !evReopened ||
    evSync ||
    !pubComment ||
    pubCheck ||
    capabilityKeepList.trim().length > 0;
  const restoreDraft = useCallback((saved: RunComposerDraft) => {
    if (!isRunComposerDraft(saved)) return;
    setMode(saved.mode);
    setTask(saved.task);
    setAutonomous(saved.autonomous);
    setAgentChoice(saved.agentChoice);
    setSelectedAgentName(saved.selectedAgentName);
    setRevisionTouched(saved.revisionTouched);
    setNewAgentName(saved.newAgentName);
    setDescription(saved.description);
    setHarness(saved.harness);
    setModel(saved.model);
    setSystemPrompt(saved.systemPrompt);
    setWorkspace(saved.workspace);
    setPins(saved.pins);
    setRequirements(saved.requirements);
    setBindings(saved.bindings);
    setKind(saved.kind);
    setAutomationName(saved.automationName);
    setAllowTask(saved.allowTask);
    setAllowWorkspace(saved.allowWorkspace);
    setCallbackUrl(saved.callbackUrl);
    setConcurrency(saved.concurrency);
    setCron(saved.cron);
    setTimezone(saved.timezone);
    setMissedPolicy(saved.missedPolicy);
    setConnection(saved.connection);
    setRepositories(saved.repositories);
    setEvOpened(saved.evOpened);
    setEvReopened(saved.evReopened);
    setEvSync(saved.evSync);
    setPubComment(saved.pubComment);
    setPubCheck(saved.pubCheck);
    setCapabilityKeepList(saved.capabilityKeepList);
  }, []);
  const clearDraft = useSessionDraft({
    key: draftKey,
    value: draft,
    onRestore: restoreDraft,
    shouldPersist: hasDraft,
  });

  useEffect(() => {
    let active = true;
    apiGetCached<{ agents: Agent[] }>("/agents", { maxAgeMs: 15_000 })
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
    if (agentChoice !== "existing" || !selectedAgentName || revisionTouched) return;
    const selected = agents.find((candidate) => candidate.name === selectedAgentName);
    if (!selected) return;
    let active = true;
    const start = window.setTimeout(() => {
      setRevisionLoading(true);
      setErr("");
      apiGetCached<{ revisions: Revision[] }>(`/agents/${selected.id}`, { maxAgeMs: 30_000 })
        .then((response) => {
          if (!active) return;
          const latest = response.revisions[0] ?? null;
          if (latest) {
            setHarness(latest.harness);
            setModel(latest.model);
            setSystemPrompt(latest.system_prompt || "");
            setWorkspace(specToDraft(latest.default_workspace));
            setPins(latest.capability_bundles ?? []);
            setRequirements(latest.connection_requirements ?? []);
            setBindings({}); // re-resolve automatically for the new agent
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
  }, [agentChoice, agents, revisionTouched, selectedAgentName]);

  useEffect(() => {
    if (mode !== "automation" || kind !== "event" || connections.length > 0) return;
    apiGetCached<{ connections: Connection[] }>("/connections", {
      maxAgeMs: 10_000,
      force: connectionRefresh > 0,
    })
      .then((response) => {
        const activeApps = response.connections.filter(
          (candidate) => candidate.provider === "github_app" && candidate.status === "active"
        );
        setEventConnectionsError("");
        setConnections(activeApps);
        setConnection((current) => current || activeApps[0]?.id || "");
      })
      .catch((reason) =>
        setEventConnectionsError(`GitHub App connections could not be loaded. ${String(reason)}`)
      );
  }, [connectionRefresh, connections.length, kind, mode]);

  // The invoking-user-visible connections used to offer per-slot binding options
  // for a "once" run whose agent declares brokered requirements. The list is
  // already viewer-filtered server-side; the server re-verifies every binding.
  useEffect(() => {
    if (mode !== "once" || requirements.length === 0 || bindableConnections.length > 0) return;
    apiGetCached<{ connections: Connection[] }>("/connections", {
      maxAgeMs: 10_000,
      force: connectionRefresh > 0,
    })
      .then((response) => {
        setBindingConnectionsError("");
        setBindableConnections(response.connections);
      })
      .catch((reason) =>
        setBindingConnectionsError(`Specific connection choices could not be loaded. ${String(reason)}`)
      );
  }, [bindableConnections.length, connectionRefresh, mode, requirements.length]);

  const touchRevision = () => {
    if (agentChoice === "existing") setRevisionTouched(true);
  };

  const commitExistingAgent = (name: string) => {
    setAgentChoice("existing");
    setSelectedAgentName(name);
    setRevisionTouched(false);
    setPendingAgentSwitch(null);
  };

  const commitNewAgent = () => {
    const defaultHarness = harnesses.find((candidate) => candidate.available)?.id || "claude-agent-sdk";
    setAgentChoice("new");
    setHarness(defaultHarness);
    setModel(defaultModelFor(harnesses, defaultHarness) || "claude-haiku-4-5");
    setSystemPrompt("");
    setWorkspace(emptyDraft("scratch"));
    setPins([]);
    setRequirements([]); // a new agent declares its requirements in the editor
    setBindings({});
    setRevisionTouched(false);
    setPendingAgentSwitch(null);
  };

  const requestExistingAgent = (name: string) => {
    if (agentChoice === "existing" && selectedAgentName === name) return;
    if (
      (agentChoice === "existing" && revisionTouched) ||
      (agentChoice === "new" && hasAgentDefinitionDraft)
    ) {
      setPendingAgentSwitch({ choice: "existing", name });
      return;
    }
    commitExistingAgent(name);
  };

  const requestNewAgent = () => {
    if (agentChoice === "new") return;
    if (revisionTouched) {
      setPendingAgentSwitch({ choice: "new" });
      return;
    }
    commitNewAgent();
  };

  const confirmAgentSwitch = () => {
    if (!pendingAgentSwitch) return;
    if (pendingAgentSwitch.choice === "new") commitNewAgent();
    else commitExistingAgent(pendingAgentSwitch.name);
  };

  // One always-live gate instead of five per-step gates. The form is a single
  // surface now, so the primary action states what is still missing rather than
  // discovering it a step at a time. Order mirrors the form top-to-bottom so the
  // message always points at the nearest unfinished field.
  const blockingIssue = useMemo<string>(() => {
    if (!agentOnly) {
      if (mode === "automation" && !automationName.trim()) return "Give this automation a unique name.";
      if (mode === "automation" && kind === "schedule" && !cron.trim()) {
        return "Enter the schedule as a cron expression.";
      }
      if (mode === "automation" && kind === "event" && eventConnectionsError) {
        return "Reload GitHub App connections before continuing.";
      }
      if (mode === "automation" && kind === "event" && !connection) {
        return "Choose an active GitHub App connection.";
      }
      if (mode === "once" && !task.trim()) return "Describe what this run should accomplish.";
    }
    if (agentsLoading || revisionLoading) return "Loading the agent configuration…";
    if (agentChoice === "existing" && !selectedAgentName) return "Choose an agent or create one here.";
    if (agentChoice === "new" && !newAgentName.trim()) return "Give the new agent a name.";
    if (harnessesError) return "Reload the runtime catalog before continuing.";
    if (harnessesLoading || harnesses.length === 0 || !model) return "Loading the runtime and model catalog…";
    if (workspace.mode === "local" && !workspace.path.trim()) return "Enter the local workspace path.";
    if (workspace.mode === "git" && !(workspace.repository || workspace.cloneUrl.trim())) {
      return "Choose a repository or provide its public clone URL.";
    }
    return "";
  }, [
    agentOnly, mode, automationName, kind, cron, connection, eventConnectionsError, task, agentsLoading, revisionLoading,
    agentChoice, selectedAgentName, newAgentName, harnessesError, harnessesLoading, harnesses.length,
    model, workspace,
  ]);

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
          // Send the draft brokered requirements (incl. any appended by the
          // embedded add-server flow); the server revalidates each. Omitted when
          // empty so plain agents are unaffected.
          ...(requirements.length > 0 ? { connection_requirements: requirements } : {}),
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
          ...(requirements.length > 0 ? { connection_requirements: requirements } : {}),
        });
        setRevisionTouched(false);
      }

      if (agentOnly) {
        clearDraft();
        onAgentCreated?.();
        return;
      }

      if (mode === "once") {
        // Explicit per-slot bindings (design "Explicit binding"): send only the
        // slots a connection was picked for; omitted slots auto-resolve. The
        // server re-verifies each (tenant, usable, connector match, snapshot)
        // and returns actionable 4xx messages we surface verbatim.
        const explicit = Object.fromEntries(
          Object.entries(bindings).filter(([, connId]) => connId)
        );
        const body: Record<string, unknown> = {
          agent: runAgentName,
          task: task.trim(),
          autonomous,
        };
        if (Object.keys(explicit).length > 0) body.bindings = explicit;
        await apiPost("/sessions", body);
        clearDraft();
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
        base_url: string | null;
        invoke_url: string | null;
        poll_url_template: string | null;
        ingress_url: string | null;
      }>("/triggers", body);
      clearDraft();
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

  const kindLabel = kind === "api" ? "API call" : kind === "schedule" ? "Schedule" : "Pull request";
  const bindingLabel = (slot: string): string => {
    const id = bindings[slot];
    if (!id) return "resolve automatically";
    return bindableConnections.find((candidate) => candidate.id === id)?.display_name ?? "selected connection";
  };

  return (
    <ModalShell
      title={agentOnly ? "Create Agent" : "Configure Run"}
      sub={
        agentOnly
          ? "Define the agent, give it a workspace and capabilities. Everything here becomes one immutable revision."
          : "Everything this run freezes is on this page. The panel on the right updates as you go."
      }
      onClose={onClose}
      maxWidth="min(1120px, 96vw)"
      dirty={addingMcp && addingMcpDirty}
    >
      {addingMcp ? (
        <AddServerWizard
          embedded
          me={me}
          onDirtyChange={setAddingMcpDirty}
          onClose={() => {
            setAddingMcpDirty(false);
            setAddingMcp(false);
          }}
          onCompleted={(result) => {
            setCapabilityRefresh((current) => current + 1);
            if (!result) return;
            const bundle = result.bundle;
            if (bundle && !pins.some((pin) => pin.name === bundle.name)) {
              setPins((current) => [...current, { id: "", name: bundle.name, version: bundle.version }]);
              touchRevision();
            }
            if (result.connection && result.snapshot) {
              const conn = result.connection;
              const endpoint = conn.metadata?.endpoint_url ?? conn.metadata?.base_url ?? "";
              const base = (result.slug ?? "server").replace(/[^a-z0-9-]/gi, "-").toLowerCase() || "server";
              const bindingMode = conn.owner_type === "user" ? "invoking_user" : "organization";
              let slot = base;
              let n = 2;
              while (requirements.some((r) => r.slot === slot)) slot = `${base}-${n++}`;
              setRequirements((current) => [
                ...current,
                {
                  slot,
                  connector: { url: endpoint, slug: result.slug ?? null },
                  required_tools: result.snapshot!.tools.map((t) => t.name),
                  binding_mode: bindingMode,
                },
              ]);
              setBindings((current) => ({ ...current, [slot]: conn.id }));
              touchRevision();
            }
          }}
        />
      ) : (
      <div className="rc-grid">
        <div className="rc-form" ref={formRef}>

        {!agentOnly && (
          <ComposerSection
            index={1}
            title="How it starts"
            hint="Launch once now, or save the same governed run behind a trigger."
          >
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
              <>
                <div className="automation-setup">
                  <label className="field">
                    <span className="lab">Automation name</span>
                    <input className="inp mono" value={automationName} onChange={(event) => setAutomationName(event.target.value)} placeholder="weekday-incident-triage" />
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

                {/* The chosen trigger configures itself right here. Previously these
                    fields lived two screens away in a "Controls" step, so picking
                    "Schedule" told you nothing about what a schedule needs. */}
                <div className="rc-trigger-detail" key={kind}>
                  {kind === "api" && (
                    <p className="rc-trigger-note">
                      Saving mints a scoped trigger token. Only that token can invoke this
                      automation — it can never reach the rest of the API.
                    </p>
                  )}

                  {kind === "schedule" && (
                    <>
                      <ScheduleBuilder
                        cron={cron}
                        timezone={timezone}
                        onCron={setCron}
                        onTimezone={setTimezone}
                      />
                      <label className="field">
                        <span className="lab">If a scheduled time was missed</span>
                        <select className="inp" value={missedPolicy} onChange={(event) => setMissedPolicy(event.target.value)}>
                          <option value="skip">Record the gap and resume the cadence</option>
                          <option value="catch_up">Start exactly one make-up run</option>
                        </select>
                      </label>
                    </>
                  )}

                  {kind === "event" && (
                    <div className="event-config">
                      {eventConnectionsError && (
                        <div className="catalog-state error-state" role="alert">
                          <div>
                            <strong>GitHub App connections are unavailable.</strong>
                            <span>{eventConnectionsError}</span>
                          </div>
                          <button
                            className="btn"
                            type="button"
                            onClick={() => setConnectionRefresh((current) => current + 1)}
                          >
                            Retry
                          </button>
                        </div>
                      )}
                      <label className="field">
                        <span className="lab">GitHub App connection</span>
                        <select className="inp" value={connection} onChange={(event) => setConnection(event.target.value)}>
                          {connections.length === 0 && (
                            <option value="">
                              {eventConnectionsError
                                ? "Connections unavailable"
                                : "No active GitHub App connections"}
                            </option>
                          )}
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
                </div>
              </>
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
              />
              {mode === "automation" && <span className="field-hint">{templateHint}</span>}
            </label>
          </ComposerSection>
        )}

        <ComposerSection
          index={agentOnly ? 1 : 2}
          title={agentOnly ? "Define the new agent" : agents.length === 0 && !agentsLoading ? "Create the first agent" : "Agent"}
          hint={
            agentOnly
              ? "The agent owns the reusable runtime, model, and identity. Each run supplies its own task."
              : "The agent owns the reusable runtime, model, and identity. The task above stays per-run."
          }
        >
          <>
            {!agentOnly && (
              <div className="choice-cards" aria-label="Agent source">
                <button
                  type="button"
                  className={agentChoice === "existing" ? "selected" : ""}
                  disabled={agents.length === 0}
                  onClick={() =>
                    requestExistingAgent(selectedAgentName || agents[0]?.name || "")
                  }
                >
                  <strong>Use an existing agent</strong>
                  <span>{agents.length > 0 ? `${agents.length} available` : "None created yet"}</span>
                </button>
                <button type="button" className={agentChoice === "new" ? "selected" : ""} onClick={requestNewAgent}>
                  <strong>Create a new agent</strong>
                  <span>Define it without leaving this run</span>
                </button>
              </div>
            )}

            {pendingAgentSwitch && (
              <div className="context-switch-confirm" role="alert">
                <span>
                  <strong>Switch agent context?</strong>
                  <small>
                    Unsaved agent configuration will be replaced. The run task and trigger draft stay saved.
                  </small>
                </span>
                <span className="discard-actions">
                  <button
                    className="btn sm ghost"
                    type="button"
                    onClick={() => setPendingAgentSwitch(null)}
                  >
                    Keep current
                  </button>
                  <button className="btn sm danger" type="button" onClick={confirmAgentSwitch}>
                    Switch
                  </button>
                </span>
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
                      onClick={() => requestExistingAgent(candidate.name)}
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
                  <input
                    className="inp mono"
                    value={newAgentName}
                    onChange={(event) => setNewAgentName(event.target.value)}
                    placeholder="release-reviewer"
                  />
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
        </ComposerSection>

        <ComposerSection
          index={agentOnly ? 2 : 3}
          title="Workspace & tools"
          hint="What the agent can see and call. Attaching a tool is not the same as allowing it — every call still passes the permission gate."
        >
          <>
            {agentChoice === "existing" && (
              <div className="revision-note">
                <strong>Revision-safe change</strong>
                <span>Any workspace or capability change appends a new revision to {selectedAgentName} before this run starts.</span>
              </div>
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
            {mode === "once" && requirements.length > 0 && (
              <div className="field">
                <span className="lab">Connection bindings</span>
                <span className="field-hint">
                  This agent needs brokered connections. Leave a slot on “Resolve automatically”
                  to let the server pick per its binding mode, or bind a specific connection you
                  can use.
                </span>
                {bindingConnectionsError && (
                  <div className="catalog-state error-state" role="status">
                    <div>
                      <strong>Specific binding choices are unavailable.</strong>
                      <span>
                        Automatic server-side resolution still works. {bindingConnectionsError}
                      </span>
                    </div>
                    <button
                      className="btn"
                      type="button"
                      onClick={() => setConnectionRefresh((current) => current + 1)}
                    >
                      Retry choices
                    </button>
                  </div>
                )}
                <div className="opt-list">
                  {requirements.map((req) => {
                    const matches = bindableConnections.filter(
                      (c) =>
                        c.status === "active" &&
                        isToolConnection(c) &&
                        connectionMatchesConnector(c, req.connector.url)
                    );
                    return (
                      <div key={req.slot} className="rc-binding-row">
                        <div className="chips" style={{ alignItems: "center" }}>
                          <span className="chip mono">{req.slot}</span>
                          <span className="faint" style={{ fontSize: 11.5 }}>
                            {req.connector.slug ? `${req.connector.slug} · ` : ""}
                            {req.connector.url}
                          </span>
                          <span className="badge">
                            {req.binding_mode === "organization" ? "organization" : "invoking user"}
                          </span>
                        </div>
                        <div className="faint" style={{ fontSize: 11 }}>
                          requires: {req.required_tools.join(", ")}
                        </div>
                        <select
                          className="inp"
                          value={bindings[req.slot] ?? ""}
                          onChange={(event) =>
                            setBindings((current) => ({ ...current, [req.slot]: event.target.value }))
                          }
                        >
                          <option value="">Resolve automatically</option>
                          {matches.map((c) => {
                            const badge = ownerBadge(c, me?.user_id);
                            const suffix = badge ? ` (${badge.label}${badge.yours ? " · yours" : ""})` : "";
                            return (
                              <option key={c.id} value={c.id}>
                                {c.display_name}
                                {suffix}
                              </option>
                            );
                          })}
                        </select>
                        {matches.length === 0 && (
                          <span className="faint" style={{ fontSize: 11 }}>
                            No matching connection you can use — the server resolves it or reports
                            an actionable error.
                          </span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </>
        </ComposerSection>

        {!agentOnly && (
          <ComposerSection
            index={4}
            title="Governance"
            hint="Supervised runs pause before risky actions. Autonomous runs defer to the configured policy."
          >
            <>
              <button
                type="button"
                className={`toggle mode-card ${autonomous ? "on" : ""}`}
                onClick={() => setAutonomous((current) => !current)}
                aria-pressed={autonomous}
              >
                <span className="sw" />
                <span>
                  <strong>{autonomous ? "Autonomous runs" : "Supervised runs"}</strong>
                  <span className="faint mode-description">
                    {autonomous
                      ? "Policy fallback decides risky actions without waiting for a person."
                      : "Risky actions pause and wait for your approval."}
                  </span>
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
          </ComposerSection>
        )}
        </div>

        <aside className="rc-spec" aria-label="Configuration summary">
          <div className="rc-spec-inner">
            <div className="rc-spec-head">
              <span className="section-kicker">{agentOnly ? "Revision 1" : "Frozen at launch"}</span>
              <p>{agentOnly ? "This becomes the agent's first immutable revision." : "Resolved before the sandbox starts. In-flight runs keep this exact spec."}</p>
            </div>

            {!agentOnly && (
              <SpecRow
                label="Trigger"
                value={mode === "once" ? "Run once" : kindLabel}
                sub={
                  mode === "once"
                    ? "a fresh sandbox, started now"
                    : kind === "schedule"
                      ? `${cron.trim() ? describeSchedule(parseCron(cron), timezone) : "not set yet"} · missed → ${missedPolicy === "skip" ? "skip" : "catch up"}`
                      : kind === "event"
                        ? `${connections.find((c) => c.id === connection)?.display_name ?? "no connection"} · ${repositories.trim() || "all repositories"}`
                        : "invoked with a scoped trigger token"
                }
                pending={mode === "automation" && !automationName.trim()}
              />
            )}
            {!agentOnly && mode === "automation" && (
              <SpecRow label="Name" value={automationName.trim() || "unnamed"} pending={!automationName.trim()} />
            )}
            {!agentOnly && (
              <SpecRow
                label="Task"
                value={task.trim() || (mode === "once" ? "not described yet" : "supplied per invocation")}
                pending={mode === "once" && !task.trim()}
                clamp
              />
            )}

            <SpecRow
              label="Agent"
              value={agentDisplayName || "not chosen"}
              sub={`${harness} · ${model}`}
              pending={!agentDisplayName}
            />
            <SpecRow
              label="Workspace"
              value={workspaceSummary(workspace)}
              sub={`${pins.length} sandbox bundle${pins.length === 1 ? "" : "s"} attached`}
            />

            {requirements.length > 0 && (
              <div className="rc-row">
                <span className="rc-row-label">Connections</span>
                {requirements.map((req) => (
                  <span key={req.slot} className="rc-row-binding">
                    <span className="mono">{req.slot}</span>
                    <span className="faint"> → {mode === "once" ? bindingLabel(req.slot) : req.binding_mode === "organization" ? "organization" : "invoking user"}</span>
                  </span>
                ))}
              </div>
            )}

            {!agentOnly && (
              <SpecRow
                label="Governance"
                value={autonomous ? "Autonomous" : "Supervised"}
                sub={autonomous ? "policy fallback decides" : "risky actions wait for approval"}
              />
            )}

            {agentChoice === "existing" && revisionTouched && (
              <p className="rc-note">
                One new revision will be appended to {selectedAgentName}. Active runs keep the
                revision they started with.
              </p>
            )}

            {err && <div className="err rc-error">{err}</div>}

            <button
              className="btn primary rc-submit"
              type="button"
              onClick={submit}
              disabled={busy || !!blockingIssue}
            >
              {busy ? "Saving…" : finalAction}
            </button>
            {hasDraft && !busy && (
              <p className="rc-draft-note">Draft saved in this tab. Closing this panel will not lose it.</p>
            )}
            {blockingIssue && !busy && <p className="rc-blocker">{blockingIssue}</p>}
          </div>
        </aside>
      </div>
      )}
    </ModalShell>
  );
}

/** One numbered block of the composer. Sections are always visible — the
 *  progressive part is the content inside them reacting to earlier choices. */
function ComposerSection({
  index,
  title,
  hint,
  children,
}: {
  index: number;
  title: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rc-section">
      <header className="rc-section-head">
        <span className="rc-section-index">{index}</span>
        <div>
          <h3>{title}</h3>
          {hint && <p>{hint}</p>}
        </div>
      </header>
      <div className="rc-section-body">{children}</div>
    </section>
  );
}

/** A single line of the live spec panel. `pending` renders it as not-yet-set so
 *  the panel reads as a checklist of what is still missing. */
function SpecRow({
  label,
  value,
  sub,
  pending,
  clamp,
}: {
  label: string;
  value: string;
  sub?: string;
  pending?: boolean;
  clamp?: boolean;
}) {
  return (
    <div className={`rc-row ${pending ? "pending" : ""}`}>
      <span className="rc-row-label">{label}</span>
      <span className={`rc-row-value ${clamp ? "rc-clamp" : ""}`}>{value}</span>
      {sub && <span className="rc-row-sub">{sub}</span>}
    </div>
  );
}

/* ─── Automation integration contract ─────────────────────────────────────
   What a caller needs to actually integrate, in one copyable place: the real
   endpoint (absolute, from the control plane — never a `<placeholder>` host),
   the secrets that exist only in this response, the variables this automation
   declares, and the responses to expect. */

/** Placeholders the platform fills in itself, per trigger kind. Anything else
 *  in the template is the caller's to supply in `context`. */
const SYSTEM_VARIABLES: Record<string, string[]> = {
  schedule: ["fire_time"],
  event: ["repository", "pr_number", "pr_title"],
  api: [],
};

function templateVariables(template: string | null): string[] {
  if (!template) return [];
  const found = new Set<string>();
  for (const match of template.matchAll(/\{\{\s*([a-zA-Z0-9_.-]+)\s*\}\}/g)) {
    found.add(match[1]);
  }
  return [...found];
}

function CopyBlock({ label, value, hint }: { label: string; value: string; hint?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable — the text is selectable either way */
    }
  };
  return (
    <div className="field">
      <div className="contract-head">
        <span className="lab">{label}</span>
        <button type="button" className="btn ghost sm" onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre className="token">{value}</pre>
      {hint && <span className="field-hint">{hint}</span>}
    </div>
  );
}

export function ShowAutomationSecrets({
  minted,
  onClose,
}: {
  minted: MintedAutomation;
  onClose: () => void;
}) {
  const sub = minted.subscription;
  const kind = sub.trigger_kind;
  // Fall back to a relative path only if an older control plane omitted the
  // absolute URLs; the placeholder is then honest about being one.
  const invokeUrl = minted.invoke_url || `<control-plane>/v1/triggers/${sub.id}/invoke`;
  const pollUrl = minted.poll_url_template || `<control-plane>/v1/triggers/${sub.id}/runs/{session_id}`;

  const system = SYSTEM_VARIABLES[kind] ?? [];
  const declared = templateVariables(sub.task_template);
  const callerVars = declared.filter((name) => !system.includes(name));
  const systemVars = declared.filter((name) => system.includes(name));

  const contextExample =
    callerVars.length > 0
      ? `{"context": {${callerVars.map((name) => `"${name}": "…"`).join(", ")}}}`
      : `{}`;

  const curl = [
    `curl -X POST '${invokeUrl}' \\`,
    `  -H 'Authorization: Bearer ${minted.token}' \\`,
    `  -H 'Content-Type: application/json' \\`,
    `  -H 'Idempotency-Key: <your-unique-key>' \\`,
    `  -d '${contextExample}'`,
  ].join("\n");

  const responseExample = [
    "200 OK",
    JSON.stringify(
      {
        session_id: "019f…",
        status: "queued",
        replay: false,
        poll_url: `/v1/triggers/${sub.id}/runs/{session_id}`,
      },
      null,
      2
    ),
  ].join("\n");

  return (
    <ModalShell
      title={minted.rotated ? "Token rotated" : `“${sub.name}” is live`}
      sub="The token and signing secret exist only in this response — they are stored hashed and sealed and can never be shown again."
      onClose={onClose}
      maxWidth="min(760px, 96vw)"
      dirty
      discardTitle="Close without copying the secrets?"
      discardMessage="They cannot be shown again after this panel closes."
    >
      <div className="contract">
        <section className="contract-section">
          <h4>Secrets — copy these now</h4>
          <CopyBlock
            label="Trigger token"
            value={minted.token}
            hint="Scoped to this automation only: it can invoke this one subscription and poll the runs it created. It can never reach the rest of the API."
          />
          {minted.callback_secret && (
            <CopyBlock
              label="Callback signing secret"
              value={minted.callback_secret}
              hint="Verify every delivery before trusting it."
            />
          )}
        </section>

        <section className="contract-section">
          <h4>Endpoint</h4>
          <CopyBlock label="Invoke" value={`POST ${invokeUrl}`} />
          <CopyBlock
            label="Poll a run"
            value={`GET ${pollUrl}`}
            hint="Substitute the session_id returned by invoke."
          />
          {minted.ingress_url && (
            <CopyBlock
              label="Webhook ingress"
              value={minted.ingress_url}
              hint="Deliveries are authenticated by their signature, so this URL needs no token."
            />
          )}
        </section>

        <section className="contract-section">
          <h4>Variables</h4>
          {declared.length === 0 ? (
            <p className="contract-note">
              This automation&apos;s task has no placeholders, so callers send an empty body.
              Add <code>{"{{name}}"}</code> to the task template to accept values.
            </p>
          ) : (
            <div className="rows">
              {callerVars.map((name) => (
                <div key={name} className="row contract-var">
                  <span className="mono">{`{{${name}}}`}</span>
                  <span className="faint">
                    you supply it in <code>context</code>
                  </span>
                </div>
              ))}
              {systemVars.map((name) => (
                <div key={name} className="row contract-var">
                  <span className="mono">{`{{${name}}}`}</span>
                  <span className="faint">filled in by fluidbox</span>
                </div>
              ))}
            </div>
          )}
          <p className="contract-note">
            <strong>{sub.allow_task_override ? "Task override allowed" : "Task override refused"}</strong> ·{" "}
            <strong>{sub.allow_workspace_override ? "workspace override allowed" : "workspace override refused"}</strong>.
            Sending a refused field returns 400. Context values must be flat strings.
          </p>
        </section>

        <section className="contract-section">
          <h4>Request</h4>
          <CopyBlock
            label="Example"
            value={curl}
            hint="Idempotency-Key is optional but strongly recommended: replaying the same key returns the original run instead of starting a second one."
          />
        </section>

        <section className="contract-section">
          <h4>Responses</h4>
          <pre className="token">{responseExample}</pre>
          <div className="rows">
            <div className="row contract-var">
              <span className="mono">409</span>
              <span className="faint">
                a run is already active and this automation is set to{" "}
                <code>{sub.concurrency_policy}</code>, or the key was reused with a different body
              </span>
            </div>
            <div className="row contract-var">
              <span className="mono">400</span>
              <span className="faint">an override this subscription does not allow</span>
            </div>
            <div className="row contract-var">
              <span className="mono">401</span>
              <span className="faint">wrong token, or the token was revoked</span>
            </div>
          </div>
        </section>

        {minted.callback_secret && (
          <section className="contract-section">
            <h4>Result delivery</h4>
            <p className="contract-note">
              When the run finishes, fluidbox POSTs the result to your callback URL and retries
              with backoff over roughly an hour. Delivery is at-least-once — deduplicate on{" "}
              <code>x-fluidbox-delivery</code>.
            </p>
            <CopyBlock
              label="Signature"
              value={'x-fluidbox-signature: v1=hmac-sha256(secret, "{timestamp}.{body}")'}
              hint="Also sent: x-fluidbox-delivery (unique id) and x-fluidbox-timestamp. Verify before trusting the payload."
            />
          </section>
        )}
      </div>

      <div className="modal-footer secret-footer">
        <span className="helper">Store the token and secret in your secret manager.</span>
        <button className="btn primary" type="button" onClick={onClose}>
          I copied them
        </button>
      </div>
    </ModalShell>
  );
}
