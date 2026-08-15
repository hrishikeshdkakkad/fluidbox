// Pure derivations for the activity workbench: status triage groups, the
// 24-hour pulse buckets, and day grouping. No I/O — everything here is a
// function of the sessions list the page already polls, so it stays
// presentation-only (the control plane remains the source of truth).

import { Session } from "./api";

/** Triage groups, in the order an operator cares about them. */
export type RunGroup = "live" | "attention" | "failed" | "completed" | "cancelled";

/** Chip filters: the triage groups an operator actually reaches for. */
export type ActivityFilter = "all" | "live" | "attention" | "failed" | "completed";

const ATTENTION_STATUSES = new Set(["awaiting_approval", "awaiting_authorization"]);
const FAILED_STATUSES = new Set(["failed", "budget_exceeded"]);

/**
 * Map a raw session status onto a triage group. Unknown statuses read as
 * "live" on purpose: a status this UI has never heard of is an in-flight
 * shape from a newer server, and hiding it would be the one wrong answer.
 */
export function runGroup(status: string): RunGroup {
  if (ATTENTION_STATUSES.has(status)) return "attention";
  if (FAILED_STATUSES.has(status)) return "failed";
  if (status === "completed") return "completed";
  if (status === "cancelled") return "cancelled";
  return "live";
}

/** Severity precedence for the pulse: a bar shows the WORST outcome of its
 *  hour, because "does this hour need me?" is the question the strip answers. */
const SEVERITY: readonly RunGroup[] = ["failed", "attention", "live", "completed", "cancelled"];

export const PULSE_HOURS = 24;
const HOUR_MS = 3_600_000;

export interface PulseHour {
  /** Start of the hour bucket (local time). */
  start: Date;
  total: number;
  /** Worst triage group present in this hour, or null when empty. */
  worst: RunGroup | null;
  counts: Readonly<Record<RunGroup, number>>;
}

/**
 * Bucket sessions into the trailing 24 hour-aligned windows, oldest first,
 * ending with the hour containing `now`. Sessions older than the window are
 * ignored; sessions timestamped after `now` land in the current hour.
 */
export function pulseHours(sessions: readonly Session[], now: Date = new Date()): PulseHour[] {
  const currentHour = new Date(now);
  currentHour.setMinutes(0, 0, 0);
  const firstHourMs = currentHour.getTime() - (PULSE_HOURS - 1) * HOUR_MS;

  const tallies = Array.from({ length: PULSE_HOURS }, () => ({
    live: 0,
    attention: 0,
    failed: 0,
    completed: 0,
    cancelled: 0,
  }));

  for (const session of sessions) {
    const createdMs = new Date(session.created_at).getTime();
    if (Number.isNaN(createdMs) || createdMs < firstHourMs) continue;
    const index = Math.min(Math.floor((createdMs - firstHourMs) / HOUR_MS), PULSE_HOURS - 1);
    tallies[index][runGroup(session.status)] += 1;
  }

  return tallies.map((counts, index) => {
    const total = SEVERITY.reduce((sum, group) => sum + counts[group], 0);
    const worst = SEVERITY.find((group) => counts[group] > 0) ?? null;
    return {
      start: new Date(firstHourMs + index * HOUR_MS),
      total,
      worst,
      counts,
    };
  });
}

/** Group tallies for a set of sessions (chip counts, pulse readout). */
export function groupCounts(sessions: readonly Session[]): Record<RunGroup, number> {
  const counts: Record<RunGroup, number> = {
    live: 0,
    attention: 0,
    failed: 0,
    completed: 0,
    cancelled: 0,
  };
  for (const session of sessions) counts[runGroup(session.status)] += 1;
  return counts;
}

export function filterSessions(
  sessions: readonly Session[],
  filter: ActivityFilter
): Session[] {
  if (filter === "all") return [...sessions];
  return sessions.filter((session) => runGroup(session.status) === filter);
}

function startOfDayMs(date: Date): number {
  const day = new Date(date);
  day.setHours(0, 0, 0, 0);
  return day.getTime();
}

const DAY_MS = 86_400_000;

/** "today" / "yesterday" / "aug 12" — the chrome voice is lowercase. */
export function dayLabel(iso: string, now: Date = new Date()): string {
  const created = new Date(iso);
  if (Number.isNaN(created.getTime())) return "earlier";
  const daysAgo = Math.round((startOfDayMs(now) - startOfDayMs(created)) / DAY_MS);
  if (daysAgo <= 0) return "today";
  if (daysAgo === 1) return "yesterday";
  return created
    .toLocaleDateString(undefined, { month: "short", day: "numeric" })
    .toLowerCase();
}

export interface TaskParts {
  /** What the run is doing — the task with boilerplate context stripped. */
  headline: string;
  /** "owner/repo@sha1234" recovered from the boilerplate, when present. */
  context: string | null;
}

// GitHub-event tasks are templated: "<what> of <owner>/<repo> at head <sha>."
// followed by checkout/compare instructions. The suffix repeats on every row
// of a busy timeline, so the table shows the <what> as the headline and
// demotes repo@sha to the meta line (the full task lives on the run page).
// The lookahead requires punctuation or end-of-string right after the sha, so
// ordinary prose that merely contains "of … at head …" passes through whole.
const GITHUB_TASK_TEMPLATE =
  /^(.+?)\s+of\s+(\S+\/\S+)\s+at head\s+([0-9a-f]{7,40})(?=[.,;]|\s*$)/i;

export function splitTask(task: string): TaskParts {
  const match = GITHUB_TASK_TEMPLATE.exec(task);
  if (!match) return { headline: task, context: null };
  return { headline: match[1], context: `${match[2]}@${match[3].slice(0, 7)}` };
}

export interface DayGroup {
  label: string;
  sessions: Session[];
}

/** Partition an already-newest-first list into contiguous day groups. */
export function groupByDay(sessions: readonly Session[], now: Date = new Date()): DayGroup[] {
  const groups: DayGroup[] = [];
  for (const session of sessions) {
    const label = dayLabel(session.created_at, now);
    const last = groups[groups.length - 1];
    if (last && last.label === label) {
      groups[groups.length - 1] = { label, sessions: [...last.sessions, session] };
    } else {
      groups.push({ label, sessions: [session] });
    }
  }
  return groups;
}
