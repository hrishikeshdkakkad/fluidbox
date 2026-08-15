"use client";

import Link from "next/link";
import { Session, workspaceLabel } from "../lib/api";
import { AutoPill, Pill, short, timeAgo } from "./bits";

/**
 * The run-history rows, shared by Overview and /app/activity so the two
 * surfaces cannot drift. Data stays with the page — each has its own polling
 * cadence and its own loading/empty states — this is only the populated list.
 */
export function RunHistory({ sessions }: { sessions: Session[] }) {
  return (
    <div className="run-rows">
      {sessions.map((session) => (
        <Link key={session.id} href={`/app/sessions/${session.id}`} className="run-row">
          <span className="run-copy">
            <strong>{session.task}</strong>
            <small>
              <span className="mono">{short(session.id)}</span>
              <span>·</span>
              <span>{session.trigger?.kind || "manual"}</span>
              {session.repo_source && (
                <><span>·</span><span>{workspaceLabel(session.repo_source)}</span></>
              )}
            </small>
          </span>
          <span className="run-status">
            <Pill status={session.status} />
            {session.autonomy === "autonomous" && <AutoPill autonomy={session.autonomy} />}
          </span>
          <span className="run-time">{timeAgo(session.created_at)}</span>
        </Link>
      ))}
    </div>
  );
}
