"use client";

import Link from "next/link";
import { Session, workspaceLabel } from "../lib/api";
import { groupByDay, runGroup, splitTask } from "../lib/activity";
import { Pill, short, timeAgo } from "./bits";

/**
 * The activity workbench's run table: one row per run with real columns
 * (run · agent · trigger · status · age) under a sticky mono header, grouped
 * by day. GitHub-event boilerplate is folded out of the headline by
 * splitTask so the column reads as WHAT each run did, not the same suffix
 * twenty-eight times. Overview keeps the compact RunHistory rows — this
 * table is the workbench view of the same Session list.
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
        <span role="columnheader">agent</span>
        <span role="columnheader">trigger</span>
        <span role="columnheader">status</span>
        <span role="columnheader" className="run-th-age">
          age
        </span>
        <span aria-hidden />
      </div>
      {groupByDay(sessions).map((group) => (
        <div key={group.label} role="rowgroup">
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
