import { describe, expect, test } from "vitest";
import {
  dayLabel,
  filterSessions,
  groupByDay,
  groupCounts,
  PULSE_HOURS,
  pulseHours,
  runGroup,
  splitTask,
} from "./activity";
import { Session } from "./api";

function session(overrides: Partial<Session>): Session {
  return {
    id: "01a00000",
    status: "completed",
    autonomy: "supervised",
    task: "test task",
    agent_id: "agent-1",
    result_summary: null,
    created_at: "2026-08-14T12:00:00Z",
    base_commit: null,
    repo_source: null,
    trigger: null,
    ...overrides,
  };
}

describe("runGroup", () => {
  test("maps every terminal status to its triage group", () => {
    expect(runGroup("completed")).toBe("completed");
    expect(runGroup("failed")).toBe("failed");
    expect(runGroup("budget_exceeded")).toBe("failed");
    expect(runGroup("cancelled")).toBe("cancelled");
  });

  test("maps pauses to attention and in-flight states to live", () => {
    expect(runGroup("awaiting_approval")).toBe("attention");
    expect(runGroup("awaiting_authorization")).toBe("attention");
    expect(runGroup("running")).toBe("live");
    expect(runGroup("provisioning")).toBe("live");
    expect(runGroup("finalizing")).toBe("live");
  });

  test("the capacity park is a neutral wait, not an attention state", () => {
    // `queued` is non-terminal and needs no human, so it shares the live
    // group with `created`. It must NOT join the attention chip: unlike
    // `awaiting_authorization` there is no decision outstanding, and a busy
    // deployment would fill that chip with runs nobody can act on — which
    // trains operators to ignore the one chip that should always mean
    // "someone is blocked on you".
    expect(runGroup("queued")).toBe("live");
    expect(runGroup("created")).toBe("live");
    expect(runGroup("queued")).not.toBe("attention");
  });

  test("treats an unknown status as live so it stays visible", () => {
    expect(runGroup("some_future_status")).toBe("live");
  });
});

describe("pulseHours", () => {
  const now = new Date("2026-08-14T21:30:00Z");

  test("returns 24 hour-aligned buckets ending at the current hour", () => {
    const hours = pulseHours([], now);
    expect(hours).toHaveLength(PULSE_HOURS);
    expect(hours[PULSE_HOURS - 1].start.getTime()).toBe(
      new Date("2026-08-14T21:30:00Z").setMinutes(0, 0, 0)
    );
    expect(hours[0].start.getTime()).toBe(
      new Date("2026-08-14T21:30:00Z").setMinutes(0, 0, 0) - 23 * 3_600_000
    );
    expect(hours.every((hour) => hour.total === 0 && hour.worst === null)).toBe(true);
  });

  // Timestamps are derived from the empty run's own bucket starts so the
  // assertions hold in every timezone (buckets align to LOCAL clock hours).
  const bucketStarts = pulseHours([], now).map((hour) => hour.start.getTime());
  const at = (bucket: number, minutes: number) =>
    new Date(bucketStarts[bucket] + minutes * 60_000).toISOString();

  test("buckets sessions by hour and reports the worst outcome", () => {
    const hours = pulseHours(
      [
        session({ status: "completed", created_at: at(PULSE_HOURS - 1, 5) }),
        session({ status: "failed", created_at: at(PULSE_HOURS - 1, 10) }),
        session({ status: "running", created_at: at(PULSE_HOURS - 2, 5) }),
      ],
      now
    );
    const last = hours[PULSE_HOURS - 1];
    expect(last.total).toBe(2);
    expect(last.worst).toBe("failed");
    expect(hours[PULSE_HOURS - 2].worst).toBe("live");
  });

  test("drops sessions older than the window and tolerates bad timestamps", () => {
    const hours = pulseHours(
      [
        session({ created_at: at(0, -90) }),
        session({ created_at: "not a date" }),
      ],
      now
    );
    expect(hours.every((hour) => hour.total === 0)).toBe(true);
  });
});

describe("groupCounts / filterSessions", () => {
  const sessions = [
    session({ id: "a", status: "running" }),
    session({ id: "b", status: "awaiting_approval" }),
    session({ id: "c", status: "failed" }),
    session({ id: "d", status: "completed" }),
    session({ id: "e", status: "completed" }),
  ];

  test("counts each triage group", () => {
    expect(groupCounts(sessions)).toEqual({
      live: 1,
      attention: 1,
      failed: 1,
      completed: 2,
      cancelled: 0,
    });
  });

  test("filters by group and passes everything through on all", () => {
    expect(filterSessions(sessions, "completed").map((s) => s.id)).toEqual(["d", "e"]);
    expect(filterSessions(sessions, "all")).toHaveLength(5);
  });
});

describe("splitTask", () => {
  test("strips the GitHub-event boilerplate into context", () => {
    expect(
      splitTask(
        "Review pull request #143 (test: PR review panel smoke test) of hrishikeshdkakkad/fluidbox at head 4a3643d898074a4745bc187deefaf32e6e273ff1"
      )
    ).toEqual({
      headline: "Review pull request #143 (test: PR review panel smoke test)",
      context: "hrishikeshdkakkad/fluidbox@4a3643d",
    });
  });

  test("also strips the checkout/compare instructions after the sha", () => {
    expect(
      splitTask(
        "Security-review pull request #143 (test: PR review panel smoke test) of hrishikeshdkakkad/fluidbox at head 4a3643d898074a4745bc187deefaf32e6e273ff1. The PR is checked out in /workspace. Compare against base bbf27d2636f7c00a384e895622e3e21ed17ce367."
      )
    ).toEqual({
      headline: "Security-review pull request #143 (test: PR review panel smoke test)",
      context: "hrishikeshdkakkad/fluidbox@4a3643d",
    });
  });

  test("passes non-templated tasks through untouched", () => {
    expect(splitTask("Fix the failing unit test in policy.rs")).toEqual({
      headline: "Fix the failing unit test in policy.rs",
      context: null,
    });
  });

  test("does not fire on a mid-sentence 'of … at head' with trailing text", () => {
    const task = "Summarize of a/b at head cafe1234 and then do more work";
    expect(splitTask(task).context).toBeNull();
  });
});

describe("day grouping", () => {
  // Local-time construction keeps these assertions timezone-independent.
  const local = (day: number, hour: number) =>
    new Date(2026, 7, day, hour, 0, 0).toISOString();
  const now = new Date(2026, 7, 14, 21, 30);

  test("labels today and yesterday in the chrome voice", () => {
    expect(dayLabel(local(14, 20), now)).toBe("today");
    expect(dayLabel(local(13, 23), now)).toBe("yesterday");
    expect(dayLabel("garbage", now)).toBe("earlier");
  });

  test("partitions a newest-first list into contiguous day groups", () => {
    const groups = groupByDay(
      [
        session({ id: "a", created_at: local(14, 20) }),
        session({ id: "b", created_at: local(14, 8) }),
        session({ id: "c", created_at: local(13, 22) }),
      ],
      now
    );
    expect(groups.map((group) => group.label)).toEqual(["today", "yesterday"]);
    expect(groups[0].sessions.map((s) => s.id)).toEqual(["a", "b"]);
    expect(groups[1].sessions.map((s) => s.id)).toEqual(["c"]);
  });
});
