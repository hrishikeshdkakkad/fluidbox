"use client";

import { use, useEffect, useRef, useState, useCallback } from "react";
import Link from "next/link";
import { Pause } from "lucide-react";
import {
  apiGet,
  apiPost,
  streamUrl,
  isTerminal,
  Session,
  Approval,
  Artifact,
  ResultDelivery,
  Usage,
  EventRow,
  workspaceLabel,
} from "../../lib/api";
import { Pill, AutoPill, DiffView, short } from "../../components/bits";

export default function SessionDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [session, setSession] = useState<Session | null>(null);
  const [usage, setUsage] = useState<Usage | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [deliveries, setDeliveries] = useState<ResultDelivery[]>([]);
  const seenSeq = useRef<Set<number>>(new Set());

  const loadMeta = useCallback(async () => {
    try {
      const s = await apiGet<{ session: Session; usage: Usage }>(`/sessions/${id}`);
      setSession(s.session);
      setUsage(s.usage);
      const a = await apiGet<{ approvals: Approval[] }>(`/sessions/${id}/approvals`);
      setApprovals(a.approvals);
      const ar = await apiGet<{ artifacts: Artifact[] }>(`/sessions/${id}/artifacts`);
      setArtifacts(ar.artifacts);
      const d = await apiGet<{ deliveries: ResultDelivery[] }>(`/sessions/${id}/deliveries`);
      setDeliveries(d.deliveries);
    } catch {
      /* ignore */
    }
  }, [id]);

  // Live SSE timeline.
  useEffect(() => {
    const es = new EventSource(streamUrl(id));
    es.onmessage = (e) => {
      try {
        const ev: EventRow = JSON.parse(e.data);
        if (seenSeq.current.has(ev.seq)) return;
        seenSeq.current.add(ev.seq);
        setEvents((prev) => [...prev, ev]);
        // React to lifecycle-relevant events by refreshing meta.
        if (
          ["session.status_changed", "approval.requested", "approval.decided", "run.result", "model.response"].includes(
            ev.type,
          )
        ) {
          loadMeta();
        }
      } catch {
        /* skip */
      }
    };
    es.onerror = () => {
      /* browser auto-reconnects with Last-Event-ID */
    };
    return () => es.close();
  }, [id, loadMeta]);

  useEffect(() => {
    const first = window.setTimeout(() => void loadMeta(), 0);
    const t = setInterval(loadMeta, 4000);
    return () => {
      clearTimeout(first);
      clearInterval(t);
    };
  }, [loadMeta]);

  const decide = async (approvalId: string, decision: string) => {
    await apiPost(`/approvals/${approvalId}/decision`, { decision, decided_by: "dashboard" });
    loadMeta();
  };

  const cancel = async () => {
    await apiPost(`/sessions/${id}/cancel`, {});
    loadMeta();
  };

  const pending = approvals.filter((a) => a.status === "pending");
  const diff = artifacts.find((a) => a.kind === "diff");
  const summary = artifacts.find((a) => a.kind === "summary");
  const terminal = session ? isTerminal(session.status) : false;

  return (
    <>
      <div className="pagehead">
        <div style={{ minWidth: 0 }}>
          <div className="crumbs">
            <Link href="/">Runs</Link>
            <span>/</span>
            <span className="mono">{short(id)}</span>
          </div>
          <h1
            className="title"
            title={session?.task || undefined}
            style={{
              fontSize: 18,
              display: "-webkit-box",
              WebkitLineClamp: 2,
              WebkitBoxOrient: "vertical",
              overflow: "hidden",
            }}
          >
            {session?.task || "…"}
          </h1>
          <div className="sub" style={{ display: "flex", gap: 10, alignItems: "center", marginTop: 8 }}>
            {session && <Pill status={session.status} />}
            {session && session.autonomy === "autonomous" && <AutoPill autonomy={session.autonomy} />}
            {session?.trigger && session.trigger.kind !== "manual" && (
              <span className="chip">
                via <b>{session.trigger.actor || session.trigger.kind}</b>
              </span>
            )}
          </div>
        </div>
        {session && !terminal && (
          <button className="btn danger" onClick={cancel}>
            Cancel run
          </button>
        )}
      </div>

      {/* Approval banners */}
      {pending.map((a) => (
        <div className="approval" key={a.id} style={{ marginBottom: 14 }}>
          <span className="icon">
            <Pause size={16} />
          </span>
          <div className="txt">
            <div className="h">Waiting for you{a.risk ? ` · ${a.risk}` : ""}</div>
            <div className="d">
              <b className="mono">{a.tool}</b>{" "}
              <span className="mono mut">{a.summary}</span>
            </div>
          </div>
          <div className="acts">
            <button className="btn human sm" onClick={() => decide(a.id, "approved_once")}>
              Approve once
            </button>
            <button className="btn sm" onClick={() => decide(a.id, "approved_session")}>
              Whole session
            </button>
            <button className="btn sm ghost danger" onClick={() => decide(a.id, "denied")}>
              Deny
            </button>
          </div>
        </div>
      ))}

      <div style={{ display: "grid", gridTemplateColumns: "1fr 300px", gap: 18, alignItems: "start" }}>
        {/* Timeline */}
        <div className="panel pad">
          <div className="sectitle" style={{ marginTop: 0 }}>
            timeline
          </div>
          {events.length === 0 ? (
            <div className="empty">waiting for events…</div>
          ) : (
            <div className="timeline">
              {events.map((ev) => (
                <TimelineItem key={ev.seq} ev={ev} />
              ))}
            </div>
          )}
        </div>

        {/* Cost + meta */}
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <div className="panel pad">
            <div className="sectitle" style={{ marginTop: 0 }}>
              cost & usage
            </div>
            <CostRow label="Cost" value={`$${(usage?.cost_usd || 0).toFixed(4)}`} />
            <CostRow label="Input tok" value={(usage?.input_tokens || 0).toLocaleString()} />
            <CostRow label="Output tok" value={(usage?.output_tokens || 0).toLocaleString()} />
            <CostRow label="Cache read" value={(usage?.cache_read_tokens || 0).toLocaleString()} />
            <CostRow label="Model calls" value={String(usage?.requests || 0)} />
          </div>

          {session && (
            <div className="panel pad">
              <div className="sectitle" style={{ marginTop: 0 }}>
                run spec
              </div>
              <div className="chips" style={{ flexDirection: "column", alignItems: "flex-start" }}>
                <span className="chip">
                  autonomy <b>{session.autonomy}</b>
                </span>
                <span className="chip">
                  workspace <b>{workspaceLabel(session.repo_source)}</b>
                </span>
                {session.base_commit && (
                  <span className="chip">
                    base <b>{session.base_commit.slice(0, 10)}</b>
                  </span>
                )}
              </div>
            </div>
          )}

          {(session?.run_spec?.capabilities?.length ?? 0) > 0 && (
            <div className="panel pad">
              <div className="sectitle" style={{ marginTop: 0 }}>
                frozen capabilities
              </div>
              {session!.run_spec!.capabilities!.map((b) => (
                <div
                  key={b.id}
                  style={{ padding: "5px 0", borderBottom: "1px solid var(--border)" }}
                >
                  <div className="mono" style={{ fontSize: 12 }}>
                    {b.name}@{b.version}
                  </div>
                  <div className="mut mono" style={{ fontSize: 10.5, marginTop: 2 }}>
                    {b.servers
                      .map((s) => `${s.name} (${s.class}, ${s.tools.length} tools)`)
                      .join(" · ")}
                  </div>
                </div>
              ))}
            </div>
          )}

          {deliveries.length > 0 && (
            <div className="panel pad">
              <div className="sectitle" style={{ marginTop: 0 }}>
                result deliveries
              </div>
              {deliveries.map((d) => (
                <div key={d.id} style={{ padding: "5px 0", borderBottom: "1px solid var(--border)" }}>
                  <div className="spread">
                    <span className="mono mut" style={{ fontSize: 11, overflow: "hidden", textOverflow: "ellipsis" }}>
                      {(d.destination.url || "?").slice(0, 26)}
                    </span>
                    <span
                      className={`badge ${
                        d.status === "delivered" ? "ok" : d.status === "failed" ? "err" : "warn"
                      }`}
                    >
                      {d.status} ×{d.attempts}
                    </span>
                  </div>
                  {d.last_error && d.status !== "delivered" && (
                    <div className="mut mono" style={{ fontSize: 10.5, marginTop: 2 }}>
                      {d.last_error.slice(0, 60)}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Result summary */}
      {summary && (
        <>
          <div className="sectitle">result</div>
          <div className="panel pad" style={{ whiteSpace: "pre-wrap", fontSize: 13.5 }}>
            {summary.content}
          </div>
        </>
      )}

      {/* Diff */}
      {diff && (
        <>
          <div className="sectitle">changes</div>
          <DiffView content={diff.content} />
        </>
      )}
    </>
  );
}

function CostRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="spread" style={{ padding: "5px 0", borderBottom: "1px solid var(--border)" }}>
      <span className="mut mono" style={{ fontSize: 11.5 }}>
        {label}
      </span>
      <span className="mono tnum" style={{ fontSize: 13 }}>
        {value}
      </span>
    </div>
  );
}

function TimelineItem({ ev }: { ev: EventRow }) {
  const d = ev.payload?.data || {};
  const s = (k: string) => (d[k] == null ? "" : String(d[k]));
  let cls = "";
  let tag = ev.type.split(".")[1] || ev.type;
  let body: React.ReactNode = ev.type;

  switch (ev.type) {
    case "session.created":
      body = (
        <>
          run created for agent <span className="em">{s("agent")}</span>
        </>
      );
      break;
    case "session.status_changed":
      cls = s("to") === "failed" || s("to") === "budget_exceeded" ? "danger" : s("to") === "completed" ? "good" : "accent";
      tag = "status";
      body = (
        <>
          → <span className="em">{s("to")}</span>
          {s("reason") ? ` · ${s("reason")}` : ""}
        </>
      );
      break;
    case "workspace.initialized":
      tag = "workspace";
      body = (
        <>
          workspace ready ({s("files")} files)
          {s("repo") ? (
            <span className="mut">
              {" "}
              · {s("repo")}
              {s("ref") ? ` @ ${s("ref")}` : ""}
            </span>
          ) : null}
        </>
      );
      break;
    case "agent.message":
      tag = s("role") === "system" ? "system" : "agent";
      body = <span style={{ color: s("role") === "system" ? "var(--ink-3)" : undefined }}>{s("text")}</span>;
      break;
    case "tool.requested":
      cls = "accent";
      tag = "tool";
      body = (
        <>
          <code>{s("tool")}</code> {s("summary")}
        </>
      );
      break;
    case "tool.decision": {
      const v = s("verdict");
      cls = v === "allow" ? "good" : "danger";
      tag = "decision";
      body = (
        <>
          {v === "allow" ? "✓ allowed" : "✗ denied"}{" "}
          <span className="mut">({s("source")})</span>
          {s("original_verdict") ? <span className="mut"> · was {s("original_verdict")}</span> : null}
        </>
      );
      break;
    }
    case "approval.requested":
      cls = "human";
      tag = "approval";
      body = (
        <>
          human approval requested for <code>{s("tool")}</code>
        </>
      );
      break;
    case "approval.decided":
      cls = "human";
      tag = "approval";
      body = (
        <>
          {s("decision")} by <span className="em">{s("decided_by")}</span>
        </>
      );
      break;
    case "model.response":
      tag = "model";
      body = (
        <span className="mut">
          {s("model")} · in {s("input_tokens")} out {s("output_tokens")} · ${Number(d.cost_usd || 0).toFixed(4)}
        </span>
      );
      break;
    case "budget.exceeded":
      cls = "danger";
      tag = "budget";
      body = (
        <>
          budget <span className="em">{s("budget")}</span> exceeded (limit {s("limit")})
        </>
      );
      break;
    case "run.result":
      cls = s("outcome") === "completed" ? "good" : "danger";
      tag = "result";
      body = <>run {s("outcome")}</>;
      break;
    case "run.error":
      cls = "danger";
      tag = "error";
      body = <span style={{ color: "var(--red)" }}>{s("message")}</span>;
      break;
    case "callback.delivered":
      cls = "good";
      tag = "callback";
      body = (
        <>
          result delivered to <span className="mono">{s("url")}</span>
          {Number(d.attempt || 1) > 1 ? ` (attempt ${s("attempt")})` : ""}
        </>
      );
      break;
    case "callback.failed":
      cls = "danger";
      tag = "callback";
      body = (
        <>
          callback to <span className="mono">{s("url")}</span> failed after {s("attempts")} attempts
        </>
      );
      break;
    case "capability.frozen":
      tag = "capability";
      body = (
        <>
          capabilities frozen: <span className="em">{((d.bundles as string[]) || []).join(", ")}</span>
          <span className="mut"> · {s("tools")} tools photographed</span>
        </>
      );
      break;
    case "tool.brokered": {
      const ok = d.ok === true;
      cls = ok ? "good" : "danger";
      tag = "brokered";
      body = (
        <>
          <code>{s("tool")}</code> executed by the control plane{" "}
          <span className="mut">
            ({ok ? "ok" : "failed"} · {s("latency_ms")}ms
            {s("error") ? ` · ${s("error")}` : ""})
          </span>
        </>
      );
      break;
    }
  }

  return (
    <div className={`tl-item ${cls}`}>
      <span className="node" />
      <div className="tl-line">
        <span className="tl-tag">{tag}</span>
        <span className="tl-body">{body}</span>
      </div>
    </div>
  );
}
