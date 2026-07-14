"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Agent,
  apiGet,
  apiPost,
  ResultDelivery,
  Schedule,
  Session,
  TriggerInvocation,
  TriggerSubscription,
} from "../lib/api";
import { LoadingRows, Pill, short } from "./bits";
import { MintedAutomation, ShowAutomationSecrets } from "./RunComposer";

export function AutomationPanel({
  onNew,
  refreshKey = 0,
  onCountChange,
}: {
  onNew: () => void;
  refreshKey?: number;
  onCountChange?: (count: number) => void;
}) {
  const [subscriptions, setSubscriptions] = useState<TriggerSubscription[]>([]);
  const [schedules, setSchedules] = useState<Record<string, Schedule>>({});
  const [agents, setAgents] = useState<Agent[]>([]);
  const [minted, setMinted] = useState<MintedAutomation | null>(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [triggerResponse, agentResponse] = await Promise.all([
        apiGet<{ subscriptions: TriggerSubscription[]; schedules?: Schedule[] }>("/triggers"),
        apiGet<{ agents: Agent[] }>("/agents"),
      ]);
      setSubscriptions(triggerResponse.subscriptions);
      setSchedules(
        Object.fromEntries(
          (triggerResponse.schedules || []).map((schedule) => [schedule.subscription_id, schedule])
        )
      );
      setAgents(agentResponse.agents);
      onCountChange?.(triggerResponse.subscriptions.length);
    } catch {
      /* The sidebar reports control-plane connectivity. */
    } finally {
      setLoading(false);
    }
  }, [onCountChange]);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    return () => clearTimeout(first);
  }, [load, refreshKey]);

  const agentName = (id: string) => agents.find((agent) => agent.id === id)?.name || short(id);

  const setEnabled = async (subscription: TriggerSubscription, enabled: boolean) => {
    setErr("");
    try {
      await apiPost(`/triggers/${subscription.id}/${enabled ? "enable" : "disable"}`, {});
      await load();
    } catch (error) {
      setErr(String(error));
    }
  };

  const rotate = async (subscription: TriggerSubscription) => {
    setErr("");
    try {
      const response = await apiPost<{ token: string }>(
        `/triggers/${subscription.id}/rotate_token`,
        {}
      );
      setMinted({
        subscription,
        token: response.token,
        callback_secret: null,
        rotated: true,
      });
    } catch (error) {
      setErr(String(error));
    }
  };

  return (
    <section className="automation-panel" aria-labelledby="automations-heading">
      <div className="section-heading automation-heading">
        <div>
          <span className="section-kicker">Saved run configuration</span>
          <h2 id="automations-heading">Automations</h2>
          <p className="automation-intro">
            Configure when a run begins. Every firing still creates a normal governed run with its own audit trail.
          </p>
        </div>
        <button className="btn primary" type="button" onClick={onNew}>
          Configure automation
        </button>
      </div>

      {err && <div className="err automation-error">{err}</div>}

      <div className="run-list automation-list">
        {loading ? (
          <LoadingRows />
        ) : subscriptions.length === 0 ? (
          <div className="automation-empty">
            <div>
              <h3>No automated runs yet.</h3>
              <p>Add a schedule, API endpoint, or repository event to an existing run configuration.</p>
            </div>
            <button className="btn" type="button" onClick={onNew}>
              Configure one
            </button>
          </div>
        ) : (
          <div className="automation-rows">
            {subscriptions.map((subscription) => (
              <AutomationRow
                key={subscription.id}
                subscription={subscription}
                schedule={schedules[subscription.id]}
                agentName={agentName(subscription.agent_id)}
                onToggle={setEnabled}
                onRotate={rotate}
              />
            ))}
          </div>
        )}
      </div>

      {minted && <ShowAutomationSecrets minted={minted} onClose={() => setMinted(null)} />}
    </section>
  );
}

function KindIcon({ kind }: { kind: string }) {
  const label = kind === "schedule" ? "Schedule" : kind === "event" ? "Event" : "API";
  return (
    <span className="automation-kind">{label}</span>
  );
}

function triggerLabel(subscription: TriggerSubscription, schedule?: Schedule) {
  if (schedule) return `${schedule.cron} · ${schedule.timezone}`;
  if (subscription.trigger_kind === "event") {
    const events = (subscription.event_filter?.events || [])
      .map((event) => event.replace("pull_request.", ""))
      .join(", ");
    return events || "repository event";
  }
  return "scoped API endpoint";
}

function AutomationRow({
  subscription,
  schedule,
  agentName,
  onToggle,
  onRotate,
}: {
  subscription: TriggerSubscription;
  schedule?: Schedule;
  agentName: string;
  onToggle: (subscription: TriggerSubscription, enabled: boolean) => void;
  onRotate: (subscription: TriggerSubscription) => void;
}) {
  const [open, setOpen] = useState(false);
  const details = [
    subscription.pinned_revision_id ? "pinned revision" : null,
    subscription.autonomy === "autonomous" ? "autonomous" : "supervised",
    subscription.concurrency_policy !== "allow" ? subscription.concurrency_policy : null,
    subscription.capability_bundles?.length
      ? `${subscription.capability_bundles.length} capability filter${subscription.capability_bundles.length === 1 ? "" : "s"}`
      : null,
  ].filter(Boolean);

  return (
    <article className="automation-row">
      <div className="automation-row-main">
        <KindIcon kind={subscription.trigger_kind} />
        <div className="automation-copy">
          <div className="automation-title-line">
            <strong>{subscription.name}</strong>
            <span className={`badge ${subscription.enabled ? "ok" : ""}`}>
              {subscription.enabled ? "enabled" : "disabled"}
            </span>
          </div>
          <div className="automation-meta">
            <span>Runs <b>{agentName}</b></span>
            <span>·</span>
            <span className="mono">{triggerLabel(subscription, schedule)}</span>
          </div>
          {details.length > 0 && <div className="automation-detail-line">{details.join(" · ")}</div>}
          {schedule?.next_fire_at && (
            <div className="automation-detail-line">
              Next run {new Date(schedule.next_fire_at).toLocaleString()}
            </div>
          )}
        </div>
        <div className="automation-actions">
          <button className="btn ghost sm" type="button" onClick={() => setOpen((current) => !current)}>
            {open ? "Hide activity" : "Activity"}
          </button>
          <button className="btn ghost sm" type="button" onClick={() => onRotate(subscription)}>
            Rotate token
          </button>
          <button
            className="btn sm"
            type="button"
            onClick={() => onToggle(subscription, !subscription.enabled)}
          >
            {subscription.enabled ? "Disable" : "Enable"}
          </button>
        </div>
      </div>
      {open && <AutomationActivity id={subscription.id} />}
    </article>
  );
}

function AutomationActivity({ id }: { id: string }) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [deliveries, setDeliveries] = useState<ResultDelivery[]>([]);
  const [invocations, setInvocations] = useState<TriggerInvocation[]>([]);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const response = await apiGet<{
          sessions: Session[];
          deliveries: ResultDelivery[];
          invocations?: TriggerInvocation[];
        }>(`/triggers/${id}`);
        if (alive) {
          setSessions(response.sessions);
          setDeliveries(response.deliveries);
          setInvocations(response.invocations || []);
        }
      } catch {
        /* Keep the last successful activity snapshot. */
      }
    };
    void poll();
    const timer = setInterval(poll, 4000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [id]);

  return (
    <div className="automation-activity">
      <ActivityColumn title="Recent runs" empty="No runs yet.">
        {sessions.map((session) => (
          <div key={session.id} className="activity-line">
            <Link className="link mono" href={`/sessions/${session.id}`}>
              {short(session.id)}
            </Link>
            <span className="activity-task">{session.task}</span>
            <Pill status={session.status} />
          </div>
        ))}
      </ActivityColumn>

      <ActivityColumn title="Firings & skips" empty="No invocations yet.">
        {invocations.map((invocation) => (
          <div key={invocation.id} className="activity-line">
            <span className="activity-task mono" title={invocation.idempotency_key}>
              {invocation.idempotency_key}
            </span>
            {invocation.session_id ? (
              <Link className="link mono" href={`/sessions/${invocation.session_id}`}>
                {short(invocation.session_id)}
              </Link>
            ) : (
              <span className="badge warn" title={invocation.skip_reason || undefined}>
                {invocation.skip_reason ? "skipped" : "pending"}
              </span>
            )}
          </div>
        ))}
      </ActivityColumn>

      <ActivityColumn title="Result delivery" empty="No deliveries yet.">
        {deliveries.map((delivery) => (
          <div key={delivery.id} className="activity-line">
            <span className="activity-task mono">{(delivery.destination.url || "Internal result").slice(0, 32)}</span>
            <span className="faint">×{delivery.attempts}</span>
            <span className={`badge ${delivery.status === "delivered" ? "ok" : delivery.status === "failed" ? "err" : "warn"}`}>
              {delivery.status}
            </span>
          </div>
        ))}
      </ActivityColumn>
    </div>
  );
}

function ActivityColumn({
  title,
  empty,
  children,
}: {
  title: string;
  empty: string;
  children: React.ReactNode[];
}) {
  return (
    <div>
      <div className="sectitle automation-activity-title">{title}</div>
      {children.length === 0 ? <div className="automation-activity-empty">{empty}</div> : children}
    </div>
  );
}
