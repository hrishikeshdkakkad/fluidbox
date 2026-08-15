"use client";

import { useMemo } from "react";
import { Session } from "../lib/api";
import { groupCounts, pulseHours } from "../lib/activity";

const BAR_MIN_PCT = 12;

function hourLabel(start: Date): string {
  return `${String(start.getHours()).padStart(2, "0")}:00`;
}

/**
 * The pulse: 24 hour-aligned bars, height = run volume, colour = the worst
 * outcome in that hour (failed > waiting > live > clean). One glance answers
 * "when was the fleet busy, and did any hour go wrong?" — the readout line
 * below repeats the same numbers in words for screen readers and skimmers.
 */
export function ActivityPulse({ sessions }: { sessions: Session[] }) {
  const hours = useMemo(() => pulseHours(sessions), [sessions]);
  const windowSessions = useMemo(() => {
    const first = hours[0].start.getTime();
    return sessions.filter((session) => new Date(session.created_at).getTime() >= first);
  }, [sessions, hours]);
  const counts = useMemo(() => groupCounts(windowSessions), [windowSessions]);

  const total = windowSessions.length;
  const max = Math.max(...hours.map((hour) => hour.total), 1);

  return (
    <section className="activity-pulse" aria-label="Activity in the last 24 hours">
      <div className="pulse-bars" aria-hidden>
        {hours.map((hour) => {
          const pct =
            hour.total === 0
              ? 0
              : BAR_MIN_PCT + Math.round(Math.sqrt(hour.total / max) * (100 - BAR_MIN_PCT));
          const detail = hour.total === 0 ? "no runs" : `${hour.total} run${hour.total === 1 ? "" : "s"}`;
          const failed = hour.counts.failed > 0 ? ` · ${hour.counts.failed} failed` : "";
          return (
            <span
              key={hour.start.getTime()}
              className={`pulse-bar ${hour.worst ?? "idle"}`}
              style={{ "--pulse-h": `${pct}%` } as React.CSSProperties}
              title={`${hourLabel(hour.start)} · ${detail}${failed}`}
            />
          );
        })}
      </div>
      <div className="pulse-readout">
        <span className="pulse-count">
          <b>{total}</b> run{total === 1 ? "" : "s"} · 24h
        </span>
        {counts.live > 0 && <span className="pulse-live">{counts.live} live</span>}
        {counts.attention > 0 && <span className="pulse-attention">{counts.attention} waiting</span>}
        {counts.failed > 0 && <span className="pulse-failed">{counts.failed} failed</span>}
        {counts.completed > 0 && <span className="pulse-completed">{counts.completed} clean</span>}
        {total === 0 && <span className="pulse-quiet">a quiet day so far</span>}
      </div>
    </section>
  );
}
