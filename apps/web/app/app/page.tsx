"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { apiGet, apiPost, Approval, isTerminal, Session } from "../lib/api";
import { splitTask } from "../lib/activity";
import { ApprovalActions } from "../components/ApprovalActions";
import { AddServerWizard } from "./capabilities/AddServerWizard";
import {
  MintedAutomation,
  RunComposer,
  RunMode,
  ShowAutomationSecrets,
} from "../components/RunComposer";
import { InlineMarkdown, Pill, short, timeAgo } from "../components/bits";
import { useSmartPolling } from "../lib/useSmartPolling";

// The home page — a SUMMARY, not a second workbench.
//
// Until 2026-08-17 this page embedded three other surfaces wholesale: the run
// list (Activity's), the automations panel (Activity's), and the resource
// cards (the Resources page's). It even shipped a worse copy of the run list —
// unpaginated and unfiltered. Everything here now either cannot be seen
// elsewhere (pending approvals) or is a number that LINKS to where the real
// work happens. Nothing is rendered in two places.
export default function Runs() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [composerMode, setComposerMode] = useState<RunMode | null>(null);
  const [agentComposer, setAgentComposer] = useState(false);
  const [showCapabilityWizard, setShowCapabilityWizard] = useState(false);
  const [minted, setMinted] = useState<MintedAutomation | null>(null);
  const [loading, setLoading] = useState(true);
  const [hasSnapshot, setHasSnapshot] = useState(false);
  const [offline, setOffline] = useState(false);
  const [actionErr, setActionErr] = useState("");
  const router = useRouter();

  const load = useCallback(async () => {
    try {
      const [sessionResponse, approvalResponse] = await Promise.all([
        apiGet<{ sessions: Session[] }>("/sessions?limit=50"),
        apiGet<{ approvals: Approval[] }>("/approvals"),
      ]);
      setSessions(sessionResponse.sessions);
      setApprovals(approvalResponse.approvals);
      setHasSnapshot(true);
      setOffline(false);
    } catch {
      // Keep the last good snapshot, but never present a failed first read as
      // real zero activity.
      setOffline(true);
    } finally {
      setLoading(false);
    }
  }, []);

  useSmartPolling(load, 2500);

  const decide = async (id: string, decision: string) => {
    setActionErr("");
    try {
      await apiPost(`/approvals/${id}/decision`, { decision });
      void load();
    } catch (error) {
      setActionErr(`The decision could not be saved. ${String(error)}`);
    }
  };

  const active = sessions.filter((session) => !isTerminal(session.status)).length;
  const done = sessions.filter((session) => session.status === "completed").length;
  const terminal = sessions.filter((session) => isTerminal(session.status)).length;
  const completionRate = terminal > 0 ? `${Math.round((done / terminal) * 100)}%` : "—";
  // The list is newest-first, so the head is the last thing that happened.
  const lastRun = sessions[0];

  return (
    <>
      <Suspense fallback={null}>
        <QueryActions
          setComposerMode={setComposerMode}
          setAgentComposer={setAgentComposer}
          setShowCapabilityWizard={setShowCapabilityWizard}
        />
      </Suspense>
      <header className="dashboard-header">
        <div>
          <h1>Overview</h1>
          <p>Configure, automate, and monitor governed agent runs.</p>
        </div>
        <button className="btn primary" type="button" onClick={() => setComposerMode("once")}>
          New Run
        </button>
      </header>

      <section className="overview-panel panel" aria-labelledby="operations-summary-heading">
        <div className="overview-panel-head">
          <div>
            <h2 id="operations-summary-heading">Operations</h2>
            <p>Current activity across manual runs and automations.</p>
          </div>
          {/* Control-plane status lives ONCE, in the navigation rail's foot —
              a second "Operational" chip here just duplicated it. */}
        </div>
        {/* Each metric is a link into the workbench with its filter applied:
            a summary page earns its place by handing off, not by restating. */}
        <div className="ops-strip" aria-label="Run summary">
          <Metric
            label="Active"
            value={hasSnapshot ? String(active) : "—"}
            href="/app/activity?filter=live"
            note={
              hasSnapshot
                ? active === 1
                  ? "sandbox running"
                  : "sandboxes running"
                : offline
                  ? "control plane unavailable"
                  : "checking…"
            }
          />
          <Metric
            label="Needs Review"
            value={hasSnapshot ? String(approvals.length) : "—"}
            href="/app/activity?filter=attention"
            attention={approvals.length > 0}
            note={
              hasSnapshot
                ? approvals.length
                  ? "decision required"
                  : "no pending decisions"
                : offline
                  ? "status unavailable"
                  : "checking…"
            }
          />
          <Metric
            label="Completed"
            value={hasSnapshot ? String(done) : "—"}
            href="/app/activity?filter=completed"
            note={hasSnapshot ? "recent runs" : offline ? "history unavailable" : "checking…"}
          />
          <Metric
            label="Success Rate"
            value={hasSnapshot ? completionRate : "—"}
            href="/app/activity"
            note={hasSnapshot ? "terminal runs" : offline ? "history unavailable" : "checking…"}
          />
        </div>
      </section>

      {actionErr && <div className="err">{actionErr}</div>}

      {/* The attention band renders in BOTH states on purpose. A home whose
          only content is conditional is blank on a quiet day — which is most
          days — so when nothing is waiting it still says what happened last. */}
      <section className="attention-section" aria-labelledby="attention-heading">
        <div className="section-heading">
          <div>
            {/* "All clear" is a CLAIM, and we can only make it from a read
                that succeeded. Without a snapshot the honest answer is that
                we do not know yet. */}
            <span className="section-kicker">
              {approvals.length > 0
                ? "Action required"
                : hasSnapshot
                  ? "Nothing is waiting on you"
                  : "Waiting on the control plane"}
            </span>
            <h2 id="attention-heading">
              {approvals.length > 0
                ? "Needs your attention"
                : hasSnapshot
                  ? "All clear"
                  : "Approvals unknown"}
            </h2>
          </div>
          {approvals.length > 0 && (
            <span className="section-note">Policy paused these runs before acting.</span>
          )}
        </div>

        {approvals.length > 0 ? (
          <div className="attention-list">
            {approvals.map((approval) => (
              <div className="approval" key={approval.id}>
                <span className="approval-label">Review</span>
                <div className="txt">
                  <div className="h">
                    Waiting for you{approval.risk ? ` · ${approval.risk}` : ""} · expires{" "}
                    {new Date(approval.expires_at).toLocaleTimeString()}
                  </div>
                  <div className="d">
                    <b className="mono">{approval.tool}</b>{" "}
                    <span className="mono mut">{approval.summary}</span>{" "}
                    <Link
                      href={`/app/sessions/${approval.session_id}`}
                      className="link mono approval-session-link"
                    >
                      {short(approval.session_id)}
                    </Link>
                  </div>
                </div>
                <ApprovalActions
                  tool={approval.tool}
                  onDecide={(decision) => decide(approval.id, decision)}
                />
              </div>
            ))}
          </div>
        ) : (
          <LastRun session={lastRun} loading={loading} offline={offline && !hasSnapshot} />
        )}
      </section>

      {/* Where the work actually lives. These are hand-offs, not previews. */}
      <nav className="home-handoff" aria-label="Go to">
        <Link className="handoff-card" href="/app/activity">
          <strong>Activity</strong>
          <small>Every run, filtered and paged</small>
        </Link>
        <Link className="handoff-card" href="/app/activity#automations-heading">
          <strong>Automations</strong>
          <small>Schedules, API endpoints, repository events</small>
        </Link>
        <Link className="handoff-card" href="/app/resources">
          <strong>Resources</strong>
          <small>Agents, MCP servers, integrations</small>
        </Link>
      </nav>

      {composerMode && (
        <RunComposer
          initialMode={composerMode}
          onClose={() => setComposerMode(null)}
          onRunCreated={() => {
            setComposerMode(null);
            void load();
            // The run you just started lives on the workbench, not here.
            router.push("/app/activity");
          }}
          onAutomationCreated={(automation) => {
            setComposerMode(null);
            setMinted(automation);
          }}
        />
      )}

      {agentComposer && (
        <RunComposer
          agentOnly
          onClose={() => setAgentComposer(false)}
          onRunCreated={() => {}}
          onAutomationCreated={() => {}}
          onAgentCreated={() => {
            setAgentComposer(false);
            router.push("/app/resources");
          }}
        />
      )}

      {showCapabilityWizard && (
        <AddServerWizard onClose={() => setShowCapabilityWizard(false)} />
      )}

      {minted && (
        <ShowAutomationSecrets
          minted={minted}
          onClose={() => {
            setMinted(null);
            router.push("/app/activity#automations-heading");
          }}
        />
      )}
    </>
  );
}

/** One at-a-glance number, and the door it opens. */
function Metric({
  label,
  value,
  note,
  href,
  attention = false,
}: {
  label: string;
  value: string;
  note: string;
  href: string;
  attention?: boolean;
}) {
  return (
    <Link className={`ops-metric${attention ? " attention" : ""}`} href={href}>
      <span className="metric-label">{label}</span>
      <strong>{value}</strong>
      <small>{note}</small>
    </Link>
  );
}

/**
 * The quiet state's content: what happened last. One line, never a list — the
 * point of this page's rewrite was to stop duplicating the run list, and
 * `result_summary` already rides the /sessions payload, so this costs no extra
 * read.
 */
function LastRun({
  session,
  loading,
  offline,
}: {
  session: Session | undefined;
  loading: boolean;
  offline: boolean;
}) {
  if (loading) return null;
  if (offline) {
    // A failed read is never rendered as "no runs" — the standing rule.
    return (
      <div className="panel pad last-run">
        <p className="faint">Run history is unavailable right now. Retrying in the background.</p>
      </div>
    );
  }
  if (!session) {
    return (
      <div className="panel pad last-run">
        <p className="faint">No runs yet. Start one and it will appear here.</p>
      </div>
    );
  }

  const { headline } = splitTask(session.task);
  return (
    <Link className="panel pad last-run" href={`/app/sessions/${session.id}`}>
      <div className="last-run-head">
        <span className="metric-label">Last run</span>
        <Pill status={session.status} />
        <span className="faint">{timeAgo(session.created_at)}</span>
      </div>
      <strong>{headline}</strong>
      {session.result_summary && (
        <p>
          <InlineMarkdown text={session.result_summary} />
        </p>
      )}
    </Link>
  );
}

function QueryActions({
  setComposerMode,
  setAgentComposer,
  setShowCapabilityWizard,
}: {
  setComposerMode: React.Dispatch<React.SetStateAction<RunMode | null>>;
  setAgentComposer: React.Dispatch<React.SetStateAction<boolean>>;
  setShowCapabilityWizard: React.Dispatch<React.SetStateAction<boolean>>;
}) {
  const params = useSearchParams();
  const query = params.toString();
  const router = useRouter();

  useEffect(() => {
    // Automations moved to the Activity workbench; keep old bookmarks working
    // rather than silently landing them on a page that no longer lists them.
    if (params.get("view") === "automations") {
      router.replace("/app/activity#automations-heading");
      return;
    }

    // `compose=` is the composer's own URL state (lib/composer-url.ts), so a
    // shared link reopens it with the same selections; `action=` remains the
    // one-shot entry point other pages link to.
    const compose = params.get("compose");
    if (compose === "run") {
      setComposerMode(params.get("mode") === "automation" ? "automation" : "once");
    }
    if (compose === "agent") setAgentComposer(true);

    const action = params.get("action");
    if (action === "new-agent") setAgentComposer(true);
    if (action === "add-capability") setShowCapabilityWizard(true);
    if (action === "new-run") setComposerMode("once");

    if (action) {
      const consumed = new URLSearchParams(query);
      consumed.delete("action");
      // Consuming the ?action= param must leave the browser on /app, not on
      // the marketing home — "/" is the public site since the 2026-07-30 split.
      window.history.replaceState({}, "", consumed.size > 0 ? `/app?${consumed}` : "/app");
    }
  }, [params, query, router, setAgentComposer, setComposerMode, setShowCapabilityWizard]);

  return null;
}
