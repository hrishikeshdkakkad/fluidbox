"use client";

import Link from "next/link";
import { Session, workspaceLabel } from "../lib/api";
import { groupByDay, runGroup } from "../lib/activity";
import { AutoPill, Pill, short, timeAgo } from "./bits";

/**
 * The run-history rows, shared by Overview and /app/activity so the two
 * surfaces cannot drift. Data stays with the page — each has its own polling
 * cadence and its own loading/empty states — this is only the populated list.
 *
 * `agents` (optional) turns agent ids into names on the meta line; `grouped`
 * (optional, used by /app/activity) adds lowercase day dividers.
 */
export function RunHistory({
  sessions,
  agents,
  grouped = false,
}: {
  sessions: Session[];
  agents?: ReadonlyMap<string, string>;
  grouped?: boolean;
}) {
  if (!grouped) {
    return (
      <div className="run-rows">
        {sessions.map((session) => (
          <RunRow key={session.id} session={session} agents={agents} />
        ))}
      </div>
    );
  }

  return (
    <div className="run-rows">
      {groupByDay(sessions).map((group) => (
        <div key={group.label} className="run-day">
          <div className="run-day-label" aria-hidden>
            {group.label}
          </div>
          {group.sessions.map((session) => (
            <RunRow key={session.id} session={session} agents={agents} />
          ))}
        </div>
      ))}
    </div>
  );
}

function RunRow({
  session,
  agents,
}: {
  session: Session;
  agents?: ReadonlyMap<string, string>;
}) {
  const agentName = agents?.get(session.agent_id);
  return (
    <Link
      href={`/app/sessions/${session.id}`}
      className={`run-row rail-${runGroup(session.status)}`}
    >
      <span className="run-copy">
        <strong>{session.task}</strong>
        <small>
          {agentName && (
            <>
              <span className="run-agent">{agentName}</span>
              <span>·</span>
            </>
          )}
          <span>{session.trigger?.kind || "manual"}</span>
          {session.repo_source && (
            <><span>·</span><span>{workspaceLabel(session.repo_source)}</span></>
          )}
          <span>·</span>
          <span className="mono">{short(session.id)}</span>
        </small>
      </span>
      <span className="run-status">
        <Pill status={session.status} />
        {session.autonomy === "autonomous" && <AutoPill autonomy={session.autonomy} />}
      </span>
      <span className="run-time">{timeAgo(session.created_at)}</span>
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
