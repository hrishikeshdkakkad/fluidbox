"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Agent,
  apiGet,
  apiGetCached,
  apiPatch,
  apiPost,
  TriggerDetail,
  TriggerSubscription,
} from "../../lib/api";
import { AutomationContract, CopyBlock, TemplateChips } from "../../components/AutomationContract";
import { AutomationActivity } from "../../components/AutomationPanel";
import { MintedAutomation, ShowAutomationSecrets } from "../../components/RunComposer";
import { ScheduleBuilder } from "../../components/ScheduleBuilder";
import { LoadingRows } from "../../components/bits";

/** Verbatim message from an apiPatch rejection (server body for 4xx/409). */
function errText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export default function AutomationDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [detail, setDetail] = useState<TriggerDetail | null>(null);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [loadErr, setLoadErr] = useState("");
  const [actionErr, setActionErr] = useState("");
  const [minted, setMinted] = useState<MintedAutomation | null>(null);

  const load = useCallback(async () => {
    try {
      const [detailResponse, agentResponse] = await Promise.all([
        apiGet<TriggerDetail>(`/triggers/${id}`),
        apiGetCached<{ agents: Agent[] }>("/agents", { maxAgeMs: 15_000 }),
      ]);
      setDetail(detailResponse);
      setAgents(agentResponse.agents);
      setLoadErr("");
    } catch (error) {
      // Keep the last good snapshot; surface the failure without blanking.
      setLoadErr(String(error));
    }
  }, [id]);
  useEffect(() => {
    void load();
  }, [load]);

  const toggle = async (subscription: TriggerSubscription) => {
    setActionErr("");
    try {
      await apiPost(`/triggers/${id}/${subscription.enabled ? "disable" : "enable"}`, {});
      await load();
    } catch (error) {
      setActionErr(String(error));
    }
  };

  const rotate = async (subscription: TriggerSubscription) => {
    setActionErr("");
    try {
      const response = await apiPost<{
        token: string;
        base_url: string | null;
        invoke_url: string | null;
        poll_url_template: string | null;
        ingress_url?: string | null;
      }>(`/triggers/${id}/rotate_token`, {});
      setMinted({
        subscription,
        token: response.token,
        callback_secret: null,
        rotated: true,
        base_url: response.base_url,
        invoke_url: response.invoke_url,
        poll_url_template: response.poll_url_template,
        ingress_url: response.ingress_url ?? null,
      });
    } catch (error) {
      setActionErr(String(error));
    }
  };

  if (!detail) {
    return (
      <div className="automation-detail">
        {loadErr ? <div className="err">{loadErr}</div> : <LoadingRows />}
      </div>
    );
  }
  const sub = detail.subscription;
  const agentName = agents.find((agent) => agent.id === sub.agent_id)?.name ?? null;
  return (
    <div className="automation-detail">
      <header className="automation-detail-head">
        <div>
          <div className="automation-title-line">
            <span className="automation-kind">
              {sub.trigger_kind === "schedule" ? "Schedule" : sub.trigger_kind === "event" ? "Event" : "API"}
            </span>
            <h1>{sub.name}</h1>
            <span className={`badge ${sub.enabled ? "ok" : ""}`}>
              {sub.enabled ? "enabled" : "disabled"}
            </span>
          </div>
          <p className="automation-intro">
            Runs{" "}
            {agentName ? (
              <Link className="link" href="/agents">
                <b>{agentName}</b>
              </Link>
            ) : (
              <span className="mono">{sub.agent_id.slice(0, 8)}</span>
            )}
            {detail.schedule?.next_fire_at && (
              <> · next run {new Date(detail.schedule.next_fire_at).toLocaleString()}</>
            )}
            {" · "}
            <Link className="link" href="/?view=automations">
              All automations
            </Link>
          </p>
        </div>
        <div className="automation-actions">
          <button className="btn ghost sm" type="button" onClick={() => void rotate(sub)}>
            Rotate token
          </button>
          <button className="btn sm" type="button" onClick={() => void toggle(sub)}>
            {sub.enabled ? "Disable" : "Enable"}
          </button>
        </div>
      </header>
      {loadErr && <div className="note">Refresh failed — showing the last loaded state. {loadErr}</div>}
      {actionErr && <div className="err">{actionErr}</div>}

      <section className="automation-detail-section">
        <h2>API</h2>
        <AutomationContract
          subscription={sub}
          invokeUrl={detail.invoke_url}
          pollUrl={detail.poll_url_template}
          ingressUrl={detail.ingress_url}
          token={null}
          updatedAt={sub.updated_at}
        />
      </section>

      <section className="automation-detail-section">
        <h2>Configuration</h2>
        <SettingsSection detail={detail} onSaved={load} />
      </section>

      <section className="automation-detail-section">
        <h2>Task template</h2>
        <TemplateSection detail={detail} onSaved={load} />
      </section>

      <section className="automation-detail-section">
        <h2>Activity</h2>
        <AutomationActivity id={sub.id} />
      </section>
      {minted && (
        <ShowAutomationSecrets
          minted={minted}
          onClose={() => {
            setMinted(null);
            void load();
          }}
        />
      )}
    </div>
  );
}

const CONCURRENCY_LABELS: Record<string, string> = {
  allow: "Allow runs to overlap",
  skip_if_running: "Skip and record the invocation",
  replace: "Cancel the active run and start the new one",
};
const MISSED_LABELS: Record<string, string> = {
  skip: "Record the gap and resume the cadence",
  catch_up: "Start exactly one make-up run",
};

function signedCallbackUrl(sub: TriggerSubscription): string {
  return sub.result_destinations.find((d) => d.kind === "signed_webhook")?.url ?? "";
}

function SettingsSection({
  detail,
  onSaved,
}: {
  detail: TriggerDetail;
  onSaved: () => Promise<void>;
}) {
  const sub = detail.subscription;
  const schedule = detail.schedule;
  const initialCallbackUrl = signedCallbackUrl(sub);

  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");
  const [newSecret, setNewSecret] = useState<string | null>(null);

  const [name, setName] = useState(sub.name);
  const [allowTask, setAllowTask] = useState(sub.allow_task_override);
  const [allowWorkspace, setAllowWorkspace] = useState(sub.allow_workspace_override);
  const [concurrency, setConcurrency] = useState(sub.concurrency_policy);
  const [callbackUrl, setCallbackUrl] = useState(initialCallbackUrl);
  const [cron, setCron] = useState(schedule?.cron ?? "");
  const [timezone, setTimezone] = useState(schedule?.timezone ?? "");
  const [missed, setMissed] = useState(schedule?.missed_run_policy ?? "skip");

  const startEditing = () => {
    // Seed the draft from the current server truth every time, so a reopened
    // editor never carries stale values from a previous, saved edit.
    setName(sub.name);
    setAllowTask(sub.allow_task_override);
    setAllowWorkspace(sub.allow_workspace_override);
    setConcurrency(sub.concurrency_policy);
    setCallbackUrl(initialCallbackUrl);
    setCron(schedule?.cron ?? "");
    setTimezone(schedule?.timezone ?? "");
    setMissed(schedule?.missed_run_policy ?? "skip");
    setErr("");
    setEditing(true);
  };

  const save = async () => {
    setSaving(true);
    setErr("");
    try {
      // Only touched fields ride the PATCH; the schedule object carries only its
      // own touched keys (the wire contract is partial by design).
      const body: Record<string, unknown> = {};
      if (name !== sub.name) body.name = name;
      if (allowTask !== sub.allow_task_override) body.allow_task_override = allowTask;
      if (allowWorkspace !== sub.allow_workspace_override) body.allow_workspace_override = allowWorkspace;
      if (concurrency !== sub.concurrency_policy) body.concurrency_policy = concurrency;
      if (callbackUrl !== initialCallbackUrl) body.callback_url = callbackUrl; // "" clears
      if (sub.trigger_kind === "schedule" && schedule) {
        const scheduleBody: Record<string, string> = {};
        if (cron !== schedule.cron) scheduleBody.cron = cron;
        if (timezone !== schedule.timezone) scheduleBody.timezone = timezone;
        if (missed !== schedule.missed_run_policy) scheduleBody.missed_run_policy = missed;
        if (Object.keys(scheduleBody).length > 0) body.schedule = scheduleBody;
      }
      if (Object.keys(body).length === 0) {
        setEditing(false);
        return; // nothing touched — do not send an empty PATCH
      }
      const response = await apiPatch<{ callback_secret: string | null }>(
        `/triggers/${sub.id}`,
        body
      );
      if (response.callback_secret) setNewSecret(response.callback_secret);
      setEditing(false);
      await onSaved();
    } catch (error) {
      // A 409 means a concurrent edit — the server's message (reload and retry)
      // is surfaced verbatim.
      setErr(errText(error));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div>
      {newSecret && (
        <div className="note">
          <p>New callback signing secret — copy it now, it will not be shown again.</p>
          <CopyBlock label="Signing secret" value={newSecret} />
          <button className="btn ghost sm" type="button" onClick={() => setNewSecret(null)}>
            Dismiss
          </button>
        </div>
      )}
      {!editing ? (
        <div>
          <div className="rows">
            <div className="row contract-var">
              <span>Name</span>
              <span className="faint">{sub.name}</span>
            </div>
            <div className="row contract-var">
              <span>Autonomy</span>
              <span className="faint">{sub.autonomy ?? "policy default"}</span>
            </div>
            <div className="row contract-var">
              <span>When another run is active</span>
              <span className="faint">
                {CONCURRENCY_LABELS[sub.concurrency_policy] ?? sub.concurrency_policy}
              </span>
            </div>
            <div className="row contract-var">
              <span>Task override</span>
              <span className="faint">{sub.allow_task_override ? "allowed" : "refused"}</span>
            </div>
            <div className="row contract-var">
              <span>Workspace override</span>
              <span className="faint">{sub.allow_workspace_override ? "allowed" : "refused"}</span>
            </div>
            <div className="row contract-var">
              <span>Signed callback</span>
              <span className="faint">{initialCallbackUrl || "none"}</span>
            </div>
            {sub.trigger_kind === "schedule" && schedule && (
              <>
                <div className="row contract-var">
                  <span>Schedule</span>
                  <span className="faint mono">{schedule.cron}</span>
                </div>
                <div className="row contract-var">
                  <span>Timezone</span>
                  <span className="faint">{schedule.timezone}</span>
                </div>
                <div className="row contract-var">
                  <span>If a scheduled time was missed</span>
                  <span className="faint">
                    {MISSED_LABELS[schedule.missed_run_policy] ?? schedule.missed_run_policy}
                  </span>
                </div>
                <div className="row contract-var">
                  <span>Next run</span>
                  <span className="faint">
                    {schedule.next_fire_at
                      ? new Date(schedule.next_fire_at).toLocaleString()
                      : "—"}
                  </span>
                </div>
              </>
            )}
          </div>
          <button className="btn ghost sm" type="button" onClick={startEditing}>
            Edit configuration
          </button>
        </div>
      ) : (
        <div className="field">
          <label className="field">
            <span className="lab">Name</span>
            <input className="inp" value={name} onChange={(event) => setName(event.target.value)} />
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={allowTask}
              onChange={(event) => setAllowTask(event.target.checked)}
            />
            Allow the caller to override the task
          </label>
          <label className="check">
            <input
              type="checkbox"
              checked={allowWorkspace}
              onChange={(event) => setAllowWorkspace(event.target.checked)}
            />
            Allow a narrower workspace override within this automation&apos;s authority
          </label>
          <label className="field">
            <span className="lab">When another run is already active</span>
            <select
              className="inp"
              value={concurrency}
              onChange={(event) => setConcurrency(event.target.value)}
            >
              <option value="allow">Allow runs to overlap</option>
              <option value="skip_if_running">Skip and record the invocation</option>
              <option value="replace">Cancel the active run and start the new one</option>
            </select>
          </label>
          <label className="field">
            <span className="lab">
              Signed callback URL <span className="optional-label">optional</span>
            </span>
            <input
              className="inp"
              value={callbackUrl}
              onChange={(event) => setCallbackUrl(event.target.value)}
              placeholder="https://your-service.example/fluidbox/callback"
            />
            <span className="field-hint">
              Clearing removes the signed callback; changing it mints a NEW signing secret shown once
            </span>
          </label>
          {sub.trigger_kind === "schedule" && schedule && (
            <>
              <ScheduleBuilder
                cron={cron}
                timezone={timezone}
                onCron={setCron}
                onTimezone={setTimezone}
              />
              <label className="field">
                <span className="lab">If a scheduled time was missed</span>
                <select
                  className="inp"
                  value={missed}
                  onChange={(event) => setMissed(event.target.value)}
                >
                  <option value="skip">Record the gap and resume the cadence</option>
                  <option value="catch_up">Start exactly one make-up run</option>
                </select>
              </label>
            </>
          )}
          {err && <div className="err">{err}</div>}
          <div className="automation-actions">
            <button
              className="btn primary sm"
              type="button"
              disabled={saving}
              onClick={() => void save()}
            >
              {saving ? "Saving…" : "Save configuration"}
            </button>
            <button
              className="btn ghost sm"
              type="button"
              disabled={saving}
              onClick={() => setEditing(false)}
            >
              Cancel
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function TemplateSection({ detail, onSaved }: { detail: TriggerDetail; onSaved: () => Promise<void> }) {
  const sub = detail.subscription;
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(sub.task_template ?? "");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState("");

  const save = async () => {
    setSaving(true);
    setErr("");
    try {
      await apiPatch(`/triggers/${sub.id}`, { task_template: draft });
      setEditing(false);
      await onSaved();
    } catch (error) {
      setErr(String(error)); // server names the missing placeholder/context
    } finally {
      setSaving(false);
    }
  };

  if (!editing) {
    return (
      <div>
        {sub.task_template ? (
          <>
            <pre className="token">{sub.task_template}</pre>
            <TemplateChips kind={sub.trigger_kind} template={sub.task_template} />
          </>
        ) : (
          <p className="contract-note">
            No template — every invocation must supply its own task (task override is on).
          </p>
        )}
        <button
          className="btn ghost sm"
          type="button"
          onClick={() => {
            setDraft(sub.task_template ?? "");
            setEditing(true);
          }}
        >
          Edit template
        </button>
      </div>
    );
  }
  return (
    <div className="field">
      <textarea
        className="inp run-task-input"
        value={draft}
        onChange={(event) => setDraft(event.target.value)}
      />
      <TemplateChips kind={sub.trigger_kind} template={draft} />
      <span className="field-hint">
        Future firings use the new template immediately; runs already in flight keep the
        configuration they started with.
      </span>
      {err && <div className="err">{err}</div>}
      <div className="automation-actions">
        <button className="btn primary sm" type="button" disabled={saving} onClick={() => void save()}>
          {saving ? "Saving…" : "Save template"}
        </button>
        <button className="btn ghost sm" type="button" disabled={saving} onClick={() => setEditing(false)}>
          Cancel
        </button>
      </div>
    </div>
  );
}
