"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";
import { apiPost, Session, workspaceLabel } from "../lib/api";
import { groupByDay, runGroup, splitTask } from "../lib/activity";
import { Pill, short, timeAgo } from "./bits";

/**
 * The activity workbench's run table: one row per run with real columns
 * (run · agent · trigger · status · age · re-run) under a sticky mono
 * header, grouped by day. The grid template lives in globals.css only —
 * skins retype it but never re-cut the tracks. GitHub-event boilerplate is folded out of the headline by
 * splitTask so the column reads as WHAT each run did, not the same suffix
 * twenty-eight times. This is the only run list in the app: Overview used to
 * ship a second, compact one, which is exactly the duplication that made the
 * two surfaces drift.
 */
export function RunTable({
  sessions,
  agents,
}: {
  sessions: Session[];
  agents?: ReadonlyMap<string, string>;
}) {
  return (
    <div className="run-table" role="table" aria-label="Run history">
      <div className="run-thead" role="row">
        <span role="columnheader">run</span>
        <span role="columnheader" className="run-th-agent">
          agent
        </span>
        <span role="columnheader" className="run-th-trigger">
          trigger
        </span>
        <span role="columnheader">status</span>
        <span role="columnheader" className="run-th-age">
          age
        </span>
        <span aria-hidden />
        <span aria-hidden />
      </div>
      {groupByDay(sessions).map((group) => (
        <div key={group.label} className="run-day" role="rowgroup">
          <div className="run-day-label" role="presentation" aria-hidden>
            {group.label}
          </div>
          {group.sessions.map((session) => (
            <RunTableRow key={session.id} session={session} agents={agents} />
          ))}
        </div>
      ))}
    </div>
  );
}

/**
 * Re-trigger a run from its history row: a NEW governed run with the same
 * agent, the same task, and the same autonomy — through the ordinary
 * POST /v1/sessions path, so it freezes a fresh RunSpec (current revision,
 * current policy) rather than replaying the old one. Workspace falls back to
 * the agent's default, which is the honest choice: an event run's PR checkout
 * belongs to its trigger, not to a manual re-run. Sits inside the row <Link>,
 * so it must stop the navigation it would otherwise cause.
 */
function RerunButton({ session }: { session: Session }) {
  const router = useRouter();
  const [state, setState] = useState<"idle" | "busy" | "failed">("idle");

  const rerun = async (event: React.MouseEvent) => {
    event.preventDefault();
    event.stopPropagation();
    if (state === "busy") return;
    setState("busy");
    try {
      const response = await apiPost<{ session?: { id?: string }; id?: string }>("/sessions", {
        agent: session.agent_id,
        task: session.task,
        autonomous: session.autonomy === "autonomous",
      });
      const id = response.session?.id ?? response.id;
      if (id) {
        router.push(`/app/sessions/${id}`);
      } else {
        setState("failed");
      }
    } catch {
      setState("failed");
    }
  };

  return (
    <button
      className="btn ghost sm run-rerun"
      type="button"
      onClick={(event) => void rerun(event)}
      disabled={state === "busy"}
      title={
        state === "failed"
          ? "The run could not be started — open the row for details"
          : "Start a new run with this agent and task"
      }
    >
      {state === "busy" ? "Starting…" : state === "failed" ? "Retry" : "Re-run"}
    </button>
  );
}

function RunTableRow({
  session,
  agents,
}: {
  session: Session;
  agents?: ReadonlyMap<string, string>;
}) {
  const { headline, context } = splitTask(session.task);
  const workspace = session.repo_source ? workspaceLabel(session.repo_source) : context;
  const agentName = agents?.get(session.agent_id);

  return (
    <Link
      href={`/app/sessions/${session.id}`}
      className={`run-tr rail-${runGroup(session.status)}`}
      role="row"
    >
      <span className="run-td-task" role="cell">
        <strong>{headline}</strong>
        <small>
          {workspace && (
            <>
              <span className="mono">{workspace}</span>
              <span>·</span>
            </>
          )}
          <span className="mono">{short(session.id)}</span>
        </small>
      </span>
      <span className="run-td-agent" role="cell">
        {agentName ?? <span className="faint">—</span>}
      </span>
      <span className="run-td-trigger" role="cell">
        <span className="run-kind">{session.trigger?.kind || "manual"}</span>
      </span>
      <span className="run-td-status" role="cell">
        <Pill status={session.status} />
        {session.autonomy === "autonomous" && (
          <span className="badge warn" title="autonomous">
            auto
          </span>
        )}
      </span>
      <span className="run-td-age" role="cell">
        {timeAgo(session.created_at)}
      </span>
      <span className="run-td-rerun" role="cell">
        <RerunButton session={session} />
      </span>
      <svg
        className="run-arrow"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
        aria-hidden
      >
        <path d="M9 18l6-6-6-6" />
      </svg>
    </Link>
  );
}
