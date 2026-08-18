"use client";

import { use, useEffect, useRef, useState, useCallback } from "react";
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
} from "../../../lib/api";
import { ApprovalActions } from "../../../components/ApprovalActions";
import { Breadcrumb } from "../../../components/Breadcrumb";
import {
  Pill,
  AutoPill,
  DiffView,
  InlineMarkdown,
  LoadingRows,
  short,
} from "../../../components/bits";
import { StateError } from "../../../components/state";
import { useSmartPolling } from "../../../lib/useSmartPolling";

export default function SessionDetail({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [session, setSession] = useState<Session | null>(null);
  const [usage, setUsage] = useState<Usage | null>(null);
  const [events, setEvents] = useState<EventRow[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [deliveries, setDeliveries] = useState<ResultDelivery[]>([]);
  const [loading, setLoading] = useState(true);
  const [hasSnapshot, setHasSnapshot] = useState(false);
  const [loadError, setLoadError] = useState("");
  /** The rejection reason of the CORE /sessions/{id} read, kept as-is rather
   *  than flattened to a string: it is what tells a deleted run (404) apart
   *  from an outage, and offering "Retry now" for a 404 was the defect. */
  const [coreError, setCoreError] = useState<unknown>(null);
  const [actionError, setActionError] = useState("");
  const [actingOn, setActingOn] = useState<string | null>(null);
  const [streamReconnecting, setStreamReconnecting] = useState(false);
  const seenSeq = useRef<Set<number>>(new Set());

  const loadMeta = useCallback(async () => {
    const [core, approvalResult, artifactResult, deliveryResult] = await Promise.allSettled([
      apiGet<{ session: Session; usage: Usage }>(`/sessions/${id}`),
      apiGet<{ approvals: Approval[] }>(`/sessions/${id}/approvals`),
      apiGet<{ artifacts: Artifact[] }>(`/sessions/${id}/artifacts`),
      apiGet<{ deliveries: ResultDelivery[] }>(`/sessions/${id}/deliveries`),
    ]);
    const failed: string[] = [];

    if (core.status === "fulfilled") {
      setSession(core.value.session);
      setUsage(core.value.usage);
      setHasSnapshot(true);
      setCoreError(null);
    } else {
      failed.push("run");
      setCoreError(core.reason);
    }
    if (approvalResult.status === "fulfilled") {
      setApprovals(approvalResult.value.approvals);
    } else {
      failed.push("approvals");
    }
    if (artifactResult.status === "fulfilled") {
      setArtifacts(artifactResult.value.artifacts);
    } else {
      failed.push("artifacts");
    }
    if (deliveryResult.status === "fulfilled") {
      setDeliveries(deliveryResult.value.deliveries);
    } else {
      failed.push("deliveries");
    }

    setLoadError(
      failed.length > 0
        ? `Could not refresh ${failed.join(", ")}. Last successful values remain visible.`
        : ""
    );
    setLoading(false);
  }, [id]);

  // Live SSE timeline.
  useEffect(() => {
    const es = new EventSource(streamUrl(id));
    es.onopen = () => setStreamReconnecting(false);
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
      setStreamReconnecting(true);
      // The browser auto-reconnects with Last-Event-ID.
    };
    return () => es.close();
  }, [id, loadMeta]);

  useSmartPolling(loadMeta, 4000);

  const decide = async (approvalId: string, decision: string) => {
    setActionError("");
    setActingOn(approvalId);
    try {
      await apiPost(`/approvals/${approvalId}/decision`, { decision });
      await loadMeta();
    } catch (error) {
      setActionError(`The decision could not be saved. ${String(error)}`);
    } finally {
      setActingOn(null);
    }
  };

  const cancel = async () => {
    setActionError("");
    setActingOn("cancel");
    try {
      await apiPost(`/sessions/${id}/cancel`, {});
      await loadMeta();
    } catch (error) {
      setActionError(`The run could not be cancelled. ${String(error)}`);
    } finally {
      setActingOn(null);
    }
  };

  const pending = approvals.filter((a) => a.status === "pending");
  const diff = artifacts.find((a) => a.kind === "diff");
  const summary = artifacts.find((a) => a.kind === "summary");
  const terminal = session ? isTerminal(session.status) : false;
  // The session row already carries the summary, so the outcome can render
  // while the separate /artifacts read is still in flight; the artifact wins
  // once it lands because it is the fuller text.
  const resultText = summary?.content ?? session?.result_summary ?? null;

  /**
   * What the run actually did. For a finished run this is the whole point of
   * the page, so it renders ABOVE the timeline — it used to sit below ~60 rows
   * of tool/model/decision entries, which meant the one sentence a person came
   * for was the last thing they could reach. A live run has no outcome yet, so
   * there it stays below and the streaming timeline keeps the lead.
   */
  const outcome = (
    <>
      {resultText && (
        <>
          <div className="sectitle">result</div>
          <div className="panel pad" style={{ whiteSpace: "pre-wrap", fontSize: 13.5 }}>
            <InlineMarkdown text={resultText} />
          </div>
        </>
      )}
      {terminal && !resultText && !loadError && (
        <>
          <div className="sectitle">result</div>
          <div className="panel pad">
            <div className="empty">No result was collected for this run.</div>
          </div>
        </>
      )}
      {diff && (
        <>
          <div className="sectitle">changes</div>
          <DiffView content={diff.content} />
        </>
      )}
    </>
  );

  return (
    <>
      <div className="pagehead">
        <div style={{ minWidth: 0 }}>
          <Breadcrumb leaf={short(id)} />
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
          <button
            className="btn danger"
            type="button"
            onClick={cancel}
            disabled={actingOn === "cancel"}
          >
            {actingOn === "cancel" ? "Cancelling…" : "Cancel run"}
          </button>
        )}
      </div>

      {loadError && hasSnapshot && (
        <div className="err" role="alert">
          {loadError}{" "}
          <button
            className="btn sm"
            type="button"
            onClick={() => {
              setLoading(true);
              void loadMeta();
            }}
          >
            Retry now
          </button>
        </div>
      )}
      {actionError && <div className="err" role="alert">{actionError}</div>}

      {!hasSnapshot ? (
        <>
          {loading ? (
            <div className="panel">
              <LoadingRows />
            </div>
          ) : (
            // Reads the status: a deleted or mistyped run id renders
            // not-found (no Retry — retrying a 404 can never succeed), while a
            // 5xx or a dead control plane renders the outage card that does
            // offer one. This used to be a single hand-rolled outage card for
            // every failure.
            <StateError
              error={coreError}
              onRetry={() => {
                setLoading(true);
                void loadMeta();
              }}
            />
          )}
        </>
      ) : (
      <>
      {/* Approval banners */}
      {pending.map((a) => (
        <div className="approval" key={a.id} style={{ marginBottom: 14 }}>
          <span className="approval-label">Review</span>
          <div className="txt">
            <div className="h">Waiting for you{a.risk ? ` · ${a.risk}` : ""}</div>
            <div className="d">
              <b className="mono">{a.tool}</b>{" "}
              <span className="mono mut">{a.summary}</span>
            </div>
            {a.tool === "network.grant" && (
              <p className="helper" style={{ marginTop: 6 }}>
                This run is asking for network access before it starts. Authorizing grants it
                for the run only; the grant expires with the run.
              </p>
            )}
          </div>
          <ApprovalActions
            tool={a.tool}
            busy={actingOn === a.id}
            onDecide={(decision) => decide(a.id, decision)}
          />
        </div>
      ))}

      {terminal && outcome}

      <div className="session-detail-grid">
        {/* Timeline */}
        <div className="panel pad">
          <div className="sectitle" style={{ marginTop: 0 }}>
            timeline
          </div>
          {events.length === 0 ? (
            <div className="empty" aria-live="polite">
              {streamReconnecting ? "Live timeline is reconnecting…" : "Waiting for events…"}
            </div>
          ) : (
            <div className="timeline">
              {events.map((ev) => (
                <TimelineItem key={ev.seq} ev={ev} />
              ))}
            </div>
          )}
        </div>

        {/* Cost + meta */}
        <div className="session-detail-side">
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

      {/* A live run's outcome arrives later, so it stays below the timeline
          it is still writing. Terminal runs render it at the top instead. */}
      {!terminal && outcome}
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
          {v === "allow" ? "Allowed" : "Denied"}{" "}
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
    // NOTE: the case key is the control plane's event type — do not rename it.
    // `tag` and the body below are display copy only.
    case "capability.frozen":
      tag = "mcp";
      body = (
        <>
          MCP servers frozen: <span className="em">{((d.bundles as string[]) || []).join(", ")}</span>
          <span className="mut"> · {s("tools")} tools photographed</span>
        </>
      );
      break;
    case "network.grant.frozen": {
      const targets = (d.targets as string[]) || [];
      const parked = d.awaiting_authorization === true;
      // Amber while a human is being waited on, accent once it is in force.
      cls = parked ? "human" : "accent";
      tag = "network";
      body = (
        <>
          network grant <span className="em">{s("mode")}</span>
          {targets.length > 0 ? (
            <span className="mut"> · {targets.join(", ")}</span>
          ) : null}
          {parked ? <span className="mut"> · awaiting authorization</span> : null}
        </>
      );
      break;
    }
    case "network.denied":
      cls = "danger";
      tag = "network";
      body = (
        <>
          denied <span className="em">{s("target")}:{s("port")}</span>
          <span className="mut"> · {s("protocol")}</span>
          {s("rule") ? <span className="mut"> · {s("rule")}</span> : null}
        </>
      );
      break;
    case "network.denied.rollup": {
      const tops = (d.top_targets as string[]) || [];
      cls = "danger";
      tag = "network";
      body = (
        <>
          and <span className="em">{s("suppressed")}</span> more denials across{" "}
          {s("distinct_targets")}
          {d.targets_truncated === true ? "+" : ""} targets
          {tops.length > 0 ? <span className="mut"> · {tops.join(", ")}</span> : null}
        </>
      );
      break;
    }
    case "network.observation.degraded":
      // Amber, not red, and deliberately NOT silent: an observation gap must
      // never read as "there were no denials".
      cls = "human";
      tag = "network";
      body = (
        <>
          network observation unavailable
          {s("reason") ? <span className="mut"> · {s("reason")}</span> : null}
        </>
      );
      break;
    case "network.grant.revoked":
      cls = "mut";
      tag = "network";
      body = (
        <>
          network grant revoked
          {s("reason") ? <span className="mut"> · {s("reason")}</span> : null}
        </>
      );
      break;
    case "tool.brokered": {
      const ok = d.ok === true;
      const outcome = s("outcome");
      // An ambiguous dispatch is neither a success nor a proven failure — the
      // side effect may or may not have landed upstream, and it is never
      // retried automatically. Amber keeps it visually distinct from a
      // definite failure so an operator can act on it.
      cls = outcome === "ambiguous" ? "human" : ok ? "good" : "danger";
      tag = "brokered";
      body = (
        <>
          <code>{s("tool")}</code> executed by the control plane{" "}
          <span className="mut">
            ({outcome || (ok ? "ok" : "failed")} · {s("latency_ms")}ms
            {s("error") ? ` · ${s("error")}` : ""})
          </span>
        </>
      );
      break;
    }
    case "run.quiesce_requested":
      tag = "cancel";
      body = (
        <span className="mut">
          quiesce requested — waiting {s("deadline_secs")}s for the runner to stop
        </span>
      );
      break;
    case "artifact.collected":
      tag = "artifact";
      body = (
        <>
          collected <span className="em">{s("name")}</span>{" "}
          <span className="mut">
            ({s("bytes")} bytes{d.truncated ? ", truncated" : ""})
          </span>
        </>
      );
      break;
    case "artifact.missing":
      cls = "danger";
      tag = "artifact";
      body = (
        <>
          {s("kind")} not collected <span className="mut">· {s("reason")}</span>
        </>
      );
      break;
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
