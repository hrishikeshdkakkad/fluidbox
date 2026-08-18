"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { StateError } from "./state";
import {
  Agent,
  apiGet,
  apiGetCached,
  apiPost,
  ResultDelivery,
  Schedule,
  Session,
  TriggerInvocation,
  TriggerSubscription,
} from "../lib/api";
import { LoadingRows, Pill, short } from "./bits";
import { useSmartPolling } from "../lib/useSmartPolling";

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
  const [err, setErr] = useState("");
  const [loadErr, setLoadErr] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [triggerResponse, agentResponse] = await Promise.all([
        apiGet<{ subscriptions: TriggerSubscription[]; schedules?: Schedule[] }>("/triggers"),
        apiGetCached<{ agents: Agent[] }>("/agents", { maxAgeMs: 15_000 }),
      ]);
      setSubscriptions(triggerResponse.subscriptions);
      setSchedules(
        Object.fromEntries(
          (triggerResponse.schedules || []).map((schedule) => [schedule.subscription_id, schedule])
        )
      );
      setAgents(agentResponse.agents);
      onCountChange?.(triggerResponse.subscriptions.length);
      setLoadErr("");
    } catch (error) {
      setLoadErr(`Automations could not be loaded. ${String(error)}`);
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

  // Token rotation lives on the automation's own page (behind a confirm), not
  // in this list: a credential-destroying control does not belong at the same
  // weight as "Activity" on a row you scan past.

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
      {loadErr && <div className="note automation-error">{loadErr}</div>}

      <div className="run-list automation-list">
        {loading ? (
          <LoadingRows />
        ) : loadErr && subscriptions.length === 0 ? (
          <div className="automation-empty">
            <div>
              <h3>Automations are unavailable.</h3>
              <p>A failed request is not treated as an empty automation list.</p>
            </div>
            <button
              className="btn"
              type="button"
              onClick={() => {
                setLoading(true);
                void load();
              }}
            >
              Retry now
            </button>
          </div>
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
              />
            ))}
          </div>
        )}
      </div>

    </section>
  );
}

/**
 * Fire this automation right now: POST /triggers/{id}/run-now creates a run
 * exactly as the subscription's own trigger would (template rendered with
 * fire_time = now, same concurrency policy), then navigates to the live run.
 * Event automations have no honest "now" (their task needs an event payload)
 * and disabled ones must be enabled first — no button in either case.
 */
function RunNowButton({ subscription }: { subscription: TriggerSubscription }) {
  const router = useRouter();
  const [state, setState] = useState<"idle" | "busy" | "failed">("idle");
  const [failure, setFailure] = useState("");

  if (subscription.trigger_kind === "event" || !subscription.enabled) return null;

  const runNow = async () => {
    if (state === "busy") return;
    setState("busy");
    try {
      const response = await apiPost<{ session_id?: string }>(
        `/triggers/${subscription.id}/run-now`,
        {}
      );
      if (response.session_id) {
        router.push(`/app/sessions/${response.session_id}`);
      } else {
        setFailure("The run could not be started.");
        setState("failed");
      }
    } catch (error) {
      setFailure(String(error));
      setState("failed");
    }
  };

  return (
    <button
      className="btn sm run-now"
      type="button"
      onClick={() => void runNow()}
      disabled={state === "busy"}
      title={
        state === "failed"
          ? failure
          : "Start a run from this configuration right now"
      }
    >
      {state === "busy" ? "Starting…" : state === "failed" ? "Retry" : "Run now"}
    </button>
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
}: {
  subscription: TriggerSubscription;
  schedule?: Schedule;
  agentName: string;
  onToggle: (subscription: TriggerSubscription, enabled: boolean) => void;
}) {
  const router = useRouter();
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
      {/* The WHOLE row opens the automation; inner buttons/links keep their
          own jobs (the guard lets any nested interactive element win). */}
      <div
        className="automation-row-main"
        onClick={(event) => {
          if ((event.target as HTMLElement).closest("button, a")) return;
          router.push(`/automations/${subscription.id}`);
        }}
      >
        <KindIcon kind={subscription.trigger_kind} />
        <div className="automation-copy">
          <div className="automation-title-line">
            <Link className="link" href={`/automations/${subscription.id}`}>
              <strong>{subscription.name}</strong>
            </Link>
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
        {/* One primary action. The row previously carried five of equal
            weight — including "Rotate token", which destroys a live
            credential — beside a row that already opens on click and a title
            that is already a link. "Open →" was the third way to do the same
            thing; rotation moved to the detail page, behind a confirm. */}
        <div className="automation-actions">
          <RunNowButton subscription={subscription} />
          <button className="btn ghost sm" type="button" onClick={() => setOpen((current) => !current)}>
            {open ? "Hide activity" : "Activity"}
          </button>
          <button
            className="btn ghost sm"
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

export function AutomationActivity({ id }: { id: string }) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [deliveries, setDeliveries] = useState<ResultDelivery[]>([]);
  const [invocations, setInvocations] = useState<TriggerInvocation[]>([]);
  const [hasSnapshot, setHasSnapshot] = useState(false);
  const [pollError, setPollError] = useState<unknown>(null);

  const poll = useCallback(async () => {
    try {
      const response = await apiGet<{
        sessions: Session[];
        deliveries: ResultDelivery[];
        invocations?: TriggerInvocation[];
      }>(`/triggers/${id}`);
      setSessions(response.sessions);
      setDeliveries(response.deliveries);
      setInvocations(response.invocations || []);
      setHasSnapshot(true);
      setPollError(null);
    } catch (error) {
      // Keeping the last good snapshot is the right call for a POLL — a blip
      // should not blank a panel someone is watching. What was wrong is that
      // before the FIRST success there is no snapshot to keep, so the error
      // was swallowed and the columns fell through to their empty copy:
      // "No runs yet." reported an outage as an automation that had never run.
      setPollError(error);
    }
  }, [id]);
  useSmartPolling(poll, 4000);

  // A failed read is never rendered as empty.
  if (!hasSnapshot && pollError) {
    return <StateError error={pollError} onRetry={() => void poll()} />;
  }

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
