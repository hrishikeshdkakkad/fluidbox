"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  apiGet,
  apiPost,
  Agent,
  ResultDelivery,
  Session,
  TriggerSubscription,
} from "../lib/api";
import { PageHead, Pill, short } from "../components/bits";

export default function Triggers() {
  const [subs, setSubs] = useState<TriggerSubscription[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [showNew, setShowNew] = useState(false);
  const [minted, setMinted] = useState<Minted | null>(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    try {
      const r = await apiGet<{ subscriptions: TriggerSubscription[] }>("/triggers");
      setSubs(r.subscriptions);
      const a = await apiGet<{ agents: Agent[] }>("/agents");
      setAgents(a.agents);
    } catch {
      /* offline handled by rail */
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const agentName = (id: string) => agents.find((a) => a.id === id)?.name || short(id);

  const setEnabled = async (sub: TriggerSubscription, enabled: boolean) => {
    setErr("");
    try {
      await apiPost(`/triggers/${sub.id}/${enabled ? "enable" : "disable"}`, {});
      load();
    } catch (e) {
      setErr(String(e));
    }
  };

  const rotate = async (sub: TriggerSubscription) => {
    setErr("");
    try {
      const r = await apiPost<{ token: string }>(`/triggers/${sub.id}/rotate_token`, {});
      setMinted({ subscription: sub, token: r.token, callback_secret: null, rotated: true });
    } catch (e) {
      setErr(String(e));
    }
  };

  return (
    <>
      <PageHead
        eyebrow="borrow the agent"
        title="Triggers"
        sub="Standing instructions that let an external caller borrow an agent with a scoped token. A trigger can only start the runs its subscription allows — overrides are opt-in and can only narrow authority; results return via signed callbacks."
        right={
          <button className="btn primary" onClick={() => setShowNew(true)}>
            + New trigger
          </button>
        }
      />

      {err && <div className="err">{err}</div>}

      <div className="panel">
        {subs.length === 0 ? (
          <div className="empty">no triggers — create one to borrow an agent over the API</div>
        ) : (
          <div className="rows">
            {subs.map((s) => (
              <TriggerRow
                key={s.id}
                sub={s}
                agentName={agentName(s.agent_id)}
                onToggle={setEnabled}
                onRotate={rotate}
              />
            ))}
          </div>
        )}
      </div>

      {showNew && (
        <NewTrigger
          agents={agents}
          onClose={() => setShowNew(false)}
          onCreated={(m) => {
            setShowNew(false);
            setMinted(m);
            load();
          }}
        />
      )}

      {minted && <ShowOnce minted={minted} onClose={() => setMinted(null)} />}
    </>
  );
}

function TriggerRow({
  sub,
  agentName,
  onToggle,
  onRotate,
}: {
  sub: TriggerSubscription;
  agentName: string;
  onToggle: (s: TriggerSubscription, enabled: boolean) => void;
  onRotate: (s: TriggerSubscription) => void;
}) {
  const [open, setOpen] = useState(false);
  const callback = sub.result_destinations.find((d) => d.kind === "signed_webhook");
  return (
    <div className="row" style={{ display: "block" }}>
      <div
        style={{ display: "grid", gridTemplateColumns: "1fr auto auto auto auto", gap: 10, alignItems: "center" }}
      >
        <span className="task">
          <b className="mono" style={{ color: "var(--accent)" }}>
            {sub.name}
          </b>
          <span className="mut" style={{ marginLeft: 8, fontSize: 12 }}>
            borrows {agentName}
            {sub.pinned_revision_id ? " (pinned rev)" : ""}
          </span>
          <span className="mut" style={{ marginLeft: 8, fontSize: 11.5 }}>
            {sub.task_template ? "template" : "no template"}
            {sub.allow_task_override ? " · task override" : ""}
            {sub.allow_workspace_override ? " · workspace override" : ""}
            {sub.autonomy === "autonomous" ? " · autonomous" : ""}
            {callback?.url ? ` · cb ${callback.url.slice(0, 34)}` : ""}
          </span>
        </span>
        <span className={`autopill ${sub.enabled ? "supervised" : "autonomous"}`}>
          {sub.enabled ? "enabled" : "disabled"}
        </span>
        <button className="btn ghost sm" onClick={() => onToggle(sub, !sub.enabled)}>
          {sub.enabled ? "disable" : "enable"}
        </button>
        <button className="btn ghost sm" onClick={() => onRotate(sub)}>
          rotate token
        </button>
        <button className="btn ghost sm" onClick={() => setOpen(!open)}>
          {open ? "hide" : "activity"}
        </button>
      </div>
      {open && <TriggerActivity id={sub.id} />}
    </div>
  );
}

function TriggerActivity({ id }: { id: string }) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [deliveries, setDeliveries] = useState<ResultDelivery[]>([]);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      try {
        const r = await apiGet<{ sessions: Session[]; deliveries: ResultDelivery[] }>(`/triggers/${id}`);
        if (alive) {
          setSessions(r.sessions);
          setDeliveries(r.deliveries);
        }
      } catch {
        /* ignore */
      }
    };
    poll();
    const t = setInterval(poll, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id]);

  return (
    <div style={{ marginTop: 10, display: "grid", gridTemplateColumns: "1fr 1fr", gap: 14 }}>
      <div>
        <div className="sectitle" style={{ marginTop: 0 }}>
          recent runs
        </div>
        {sessions.length === 0 ? (
          <div className="empty">no runs yet</div>
        ) : (
          sessions.map((s) => (
            <div key={s.id} className="spread" style={{ padding: "4px 0", gap: 8 }}>
              <Link className="link mono" href={`/sessions/${s.id}`} style={{ fontSize: 12 }}>
                {short(s.id)}
              </Link>
              <span className="mut" style={{ fontSize: 11.5, flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                {s.task}
              </span>
              <Pill status={s.status} />
            </div>
          ))
        )}
      </div>
      <div>
        <div className="sectitle" style={{ marginTop: 0 }}>
          result deliveries
        </div>
        {deliveries.length === 0 ? (
          <div className="empty">no deliveries yet</div>
        ) : (
          deliveries.map((d) => <DeliveryLine key={d.id} d={d} />)
        )}
      </div>
    </div>
  );
}

export function DeliveryLine({ d }: { d: ResultDelivery }) {
  const cls = d.status === "delivered" ? "supervised" : d.status === "failed" ? "autonomous" : "";
  return (
    <div className="spread" style={{ padding: "4px 0", gap: 8 }}>
      <span className="mono mut" style={{ fontSize: 11.5 }}>
        {(d.destination.url || "?").slice(0, 30)}
      </span>
      <span className="mut" style={{ fontSize: 11.5 }}>
        ×{d.attempts}
      </span>
      <span className={`autopill ${cls}`} title={d.last_error || undefined}>
        {d.status}
      </span>
    </div>
  );
}

interface Minted {
  subscription: TriggerSubscription;
  token: string;
  callback_secret: string | null;
  rotated?: boolean;
}

function NewTrigger({
  agents,
  onClose,
  onCreated,
}: {
  agents: Agent[];
  onClose: () => void;
  onCreated: (m: Minted) => void;
}) {
  const [agent, setAgent] = useState(agents[0]?.name || "");
  const [name, setName] = useState("");
  const [template, setTemplate] = useState("");
  const [allowTask, setAllowTask] = useState(false);
  const [allowWorkspace, setAllowWorkspace] = useState(false);
  const [autonomous, setAutonomous] = useState(false);
  const [callbackUrl, setCallbackUrl] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const submit = async () => {
    setErr("");
    if (!name.trim() || !agent) {
      setErr("agent and name are required");
      return;
    }
    setBusy(true);
    try {
      const body: Record<string, unknown> = {
        agent,
        name: name.trim(),
        allow_task_override: allowTask,
        allow_workspace_override: allowWorkspace,
        autonomous,
      };
      if (template.trim()) body.task_template = template;
      if (callbackUrl.trim()) body.callback_url = callbackUrl.trim();
      const r = await apiPost<{
        subscription: TriggerSubscription;
        token: string;
        callback_secret: string | null;
      }>("/triggers", body);
      onCreated({ subscription: r.subscription, token: r.token, callback_secret: r.callback_secret });
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
              new trigger
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, marginTop: 4 }}>
              borrow an agent over the API
            </div>
          </div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <label className="field">
            <span className="lab">Agent to borrow</span>
            <select className="inp" value={agent} onChange={(e) => setAgent(e.target.value)}>
              {agents.map((a) => (
                <option key={a.id} value={a.name}>
                  {a.name}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span className="lab">Name (unique)</span>
            <input
              className="inp"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="incident-triage"
            />
          </label>
          <label className="field">
            <span className="lab">
              Task template — {"{{key}}"} renders from the caller&apos;s context
            </span>
            <textarea
              className="inp"
              rows={3}
              value={template}
              onChange={(e) => setTemplate(e.target.value)}
              placeholder="Investigate ticket {{ticket}} and report the root cause."
            />
          </label>
          <label className="field" style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
            <input type="checkbox" checked={allowTask} onChange={(e) => setAllowTask(e.target.checked)} />
            <span className="lab" style={{ margin: 0 }}>
              allow caller task override (off by default)
            </span>
          </label>
          <label className="field" style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
            <input
              type="checkbox"
              checked={allowWorkspace}
              onChange={(e) => setAllowWorkspace(e.target.checked)}
            />
            <span className="lab" style={{ margin: 0 }}>
              allow caller workspace override (repo/ref/commit within authority)
            </span>
          </label>
          <label className="field" style={{ flexDirection: "row", gap: 8, alignItems: "center" }}>
            <input type="checkbox" checked={autonomous} onChange={(e) => setAutonomous(e.target.checked)} />
            <span className="lab" style={{ margin: 0 }}>
              autonomous runs (policy permitting)
            </span>
          </label>
          <label className="field">
            <span className="lab">Signed callback URL (optional — the secret is minted on create)</span>
            <input
              className="inp"
              value={callbackUrl}
              onChange={(e) => setCallbackUrl(e.target.value)}
              placeholder="https://your-service.example/fluidbox/callback"
            />
          </label>
          {err && <div className="err">{err}</div>}
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="mut" style={{ fontSize: 12 }}>
              the scoped token is shown once after creation
            </span>
            <button className="btn primary" onClick={submit} disabled={busy}>
              {busy ? "creating…" : "Create trigger"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ShowOnce({ minted, onClose }: { minted: Minted; onClose: () => void }) {
  const curl = [
    "curl -X POST \\",
    `  -H "Authorization: Bearer ${minted.token}" \\`,
    '  -H "Idempotency-Key: my-key-1" \\',
    '  -H "Content-Type: application/json" \\',
    `  -d '{"context": {"ticket": "INC-42"}}' \\`,
    `  <control-plane>/v1/triggers/${minted.subscription.id}/invoke`,
  ].join("\n");
  return (
    <div className="overlay" onClick={onClose}>
      <div className="panel modal" onClick={(e) => e.stopPropagation()}>
        <div className="mh">
          <div>
            <div className="eyebrow" style={{ margin: 0 }}>
              shown once
            </div>
            <div style={{ fontFamily: "var(--font-mono)", fontSize: 15, marginTop: 4 }}>
              {minted.rotated ? "token rotated" : `trigger '${minted.subscription.name}' created`}
            </div>
          </div>
          <button className="btn ghost sm" onClick={onClose}>
            esc
          </button>
        </div>
        <div className="mb">
          <p className="mut" style={{ fontSize: 12.5, marginTop: 0 }}>
            Copy these now — the token is stored hashed and the secret sealed; neither can be
            shown again.
          </p>
          <label className="field">
            <span className="lab">Scoped trigger token</span>
            <pre
              className="mono"
              style={{ fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}
            >
              {minted.token}
            </pre>
          </label>
          {minted.callback_secret && (
            <label className="field">
              <span className="lab">
                Callback signing secret — verify x-fluidbox-signature with it
              </span>
              <pre
                className="mono"
                style={{ fontSize: 12, whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 }}
              >
                {minted.callback_secret}
              </pre>
            </label>
          )}
          {!minted.rotated && (
            <label className="field">
              <span className="lab">Invoke example</span>
              <pre className="mono" style={{ fontSize: 11.5, whiteSpace: "pre-wrap", margin: 0 }}>
                {curl}
              </pre>
            </label>
          )}
          <div className="spread" style={{ marginTop: 16 }}>
            <span />
            <button className="btn primary" onClick={onClose}>
              I copied them
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
