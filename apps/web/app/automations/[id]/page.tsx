"use client";

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import {
  Agent,
  apiGet,
  apiGetCached,
  apiPost,
  TriggerDetail,
  TriggerSubscription,
} from "../../lib/api";
import { AutomationContract } from "../../components/AutomationContract";
import { AutomationActivity } from "../../components/AutomationPanel";
import { MintedAutomation, ShowAutomationSecrets } from "../../components/RunComposer";
import { LoadingRows } from "../../components/bits";

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
