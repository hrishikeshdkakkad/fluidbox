"use client";

import { useEffect, useMemo, useState } from "react";

/* A schedule picker that speaks in days and times, not cron fields.
 *
 * The control plane still stores a cron expression — that is the scheduler's
 * contract and it does not change. This component just stops asking a person to
 * author one: it builds the expression from a frequency + time, prints the
 * schedule back as a sentence so intent is confirmable, and keeps a raw-cron
 * escape hatch for the shapes a preset cannot express. */

export type Frequency = "hourly" | "daily" | "weekdays" | "weekly" | "monthly" | "custom";

const DAYS = [
  { value: 1, short: "Mon", long: "Monday" },
  { value: 2, short: "Tue", long: "Tuesday" },
  { value: 3, short: "Wed", long: "Wednesday" },
  { value: 4, short: "Thu", long: "Thursday" },
  { value: 5, short: "Fri", long: "Friday" },
  { value: 6, short: "Sat", long: "Saturday" },
  { value: 0, short: "Sun", long: "Sunday" },
];

const FREQUENCIES: { id: Frequency; label: string }[] = [
  { id: "hourly", label: "Every hour" },
  { id: "daily", label: "Every day" },
  { id: "weekdays", label: "Weekdays" },
  { id: "weekly", label: "Every week" },
  { id: "monthly", label: "Every month" },
  { id: "custom", label: "Custom cron" },
];

interface BuilderState {
  frequency: Frequency;
  time: string; // "HH:MM"
  minute: string; // hourly only, "MM"
  days: number[]; // weekly only
  dayOfMonth: number; // monthly only
  raw: string; // custom only
}

const DEFAULT_STATE: BuilderState = {
  frequency: "daily",
  time: "07:00",
  minute: "00",
  days: [1],
  dayOfMonth: 1,
  raw: "",
};

/** Build the cron expression a given builder state represents. */
export function buildCron(state: BuilderState): string {
  const [hh, mm] = state.time.split(":");
  const hour = String(Number(hh ?? 0));
  const minute = String(Number(mm ?? 0));
  switch (state.frequency) {
    case "hourly":
      return `${Number(state.minute || 0)} * * * *`;
    case "daily":
      return `${minute} ${hour} * * *`;
    case "weekdays":
      return `${minute} ${hour} * * 1-5`;
    case "weekly": {
      const days = state.days.length > 0 ? [...state.days].sort((a, b) => a - b) : [1];
      return `${minute} ${hour} * * ${days.join(",")}`;
    }
    case "monthly":
      return `${minute} ${hour} ${state.dayOfMonth} * *`;
    case "custom":
      return state.raw;
  }
}

/** Recover a builder state from a cron string so an existing schedule opens in
 *  the picker rather than dumping the user into the raw field. Anything this
 *  does not recognise round-trips through `custom`, never silently rewritten. */
export function parseCron(cron: string): BuilderState {
  const trimmed = cron.trim();
  if (!trimmed) return DEFAULT_STATE;
  const parts = trimmed.split(/\s+/);
  if (parts.length !== 5) return { ...DEFAULT_STATE, frequency: "custom", raw: trimmed };
  const [min, hour, dom, month, dow] = parts;
  const numeric = (v: string) => /^\d+$/.test(v);
  const pad = (v: string) => String(Number(v)).padStart(2, "0");

  if (numeric(min) && hour === "*" && dom === "*" && month === "*" && dow === "*") {
    return { ...DEFAULT_STATE, frequency: "hourly", minute: pad(min) };
  }
  if (numeric(min) && numeric(hour) && month === "*") {
    const time = `${pad(hour)}:${pad(min)}`;
    if (dom === "*" && dow === "*") return { ...DEFAULT_STATE, frequency: "daily", time };
    if (dom === "*" && dow === "1-5") return { ...DEFAULT_STATE, frequency: "weekdays", time };
    if (dom === "*" && /^[0-6](,[0-6])*$/.test(dow)) {
      return { ...DEFAULT_STATE, frequency: "weekly", time, days: dow.split(",").map(Number) };
    }
    if (numeric(dom) && dow === "*") {
      return { ...DEFAULT_STATE, frequency: "monthly", time, dayOfMonth: Number(dom) };
    }
  }
  return { ...DEFAULT_STATE, frequency: "custom", raw: trimmed };
}

/** The schedule as a sentence. This is the part a person actually checks. */
export function describeSchedule(state: BuilderState, timezone: string): string {
  const zone = timezone.trim() || "UTC";
  const at = (() => {
    const [hh, mm] = state.time.split(":");
    return `${hh ?? "00"}:${mm ?? "00"}`;
  })();
  switch (state.frequency) {
    case "hourly":
      return `Every hour at :${String(Number(state.minute || 0)).padStart(2, "0")} past, ${zone}`;
    case "daily":
      return `Every day at ${at}, ${zone}`;
    case "weekdays":
      return `Monday to Friday at ${at}, ${zone}`;
    case "weekly": {
      if (state.days.length === 0) return `Pick at least one day`;
      const names = [...state.days]
        .sort((a, b) => (a === 0 ? 7 : a) - (b === 0 ? 7 : b))
        .map((d) => DAYS.find((day) => day.value === d)?.long ?? "")
        .filter(Boolean);
      const list =
        names.length === 1
          ? names[0]
          : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
      return `Every ${list} at ${at}, ${zone}`;
    }
    case "monthly": {
      const n = state.dayOfMonth;
      const suffix = n % 10 === 1 && n !== 11 ? "st" : n % 10 === 2 && n !== 12 ? "nd" : n % 10 === 3 && n !== 13 ? "rd" : "th";
      return `The ${n}${suffix} of every month at ${at}, ${zone}`;
    }
    case "custom":
      return state.raw.trim() ? `Custom cron, ${zone}` : "Enter a cron expression";
  }
}

function timezones(): string[] {
  // Intl.supportedValuesOf is widely available; fall back to a short list so the
  // field is never empty on an older engine.
  const intl = Intl as typeof Intl & { supportedValuesOf?: (key: string) => string[] };
  try {
    const all = intl.supportedValuesOf?.("timeZone");
    if (all && all.length > 0) return all;
  } catch {
    /* fall through */
  }
  return ["UTC", "America/New_York", "America/Chicago", "America/Los_Angeles", "Europe/London", "Europe/Berlin", "Asia/Kolkata", "Asia/Singapore", "Asia/Tokyo", "Australia/Sydney"];
}

export function ScheduleBuilder({
  cron,
  timezone,
  onCron,
  onTimezone,
}: {
  cron: string;
  timezone: string;
  onCron: (cron: string) => void;
  onTimezone: (timezone: string) => void;
}) {
  const [state, setState] = useState<BuilderState>(() => parseCron(cron));
  const zones = useMemo(() => timezones(), []);

  // The builder owns the expression: every state change republishes the cron so
  // the parent never has to know how it was authored.
  useEffect(() => {
    onCron(buildCron(state));
    // `onCron` is a fresh closure each render; depending on it would loop.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state]);

  const patch = (next: Partial<BuilderState>) => setState((current) => ({ ...current, ...next }));
  const toggleDay = (day: number) =>
    setState((current) => ({
      ...current,
      days: current.days.includes(day)
        ? current.days.filter((d) => d !== day)
        : [...current.days, day],
    }));

  const generated = buildCron(state);

  return (
    <div className="sched">
      <div className="field">
        <span className="lab">How often</span>
        <div className="sched-freq" role="group" aria-label="Frequency">
          {FREQUENCIES.map((option) => (
            <button
              key={option.id}
              type="button"
              className={`sched-freq-option ${state.frequency === option.id ? "on" : ""}`}
              aria-pressed={state.frequency === option.id}
              onClick={() => patch({ frequency: option.id })}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      <div className="sched-detail">
        {state.frequency === "hourly" && (
          <label className="field sched-narrow">
            <span className="lab">At minute</span>
            <input
              className="inp mono"
              type="number"
              min={0}
              max={59}
              value={Number(state.minute)}
              onChange={(event) => patch({ minute: event.target.value })}
            />
          </label>
        )}

        {state.frequency !== "hourly" && state.frequency !== "custom" && (
          <label className="field sched-narrow">
            <span className="lab">At</span>
            <input
              className="inp"
              type="time"
              value={state.time}
              onChange={(event) => patch({ time: event.target.value })}
            />
          </label>
        )}

        {state.frequency === "weekly" && (
          <div className="field">
            <span className="lab">On these days</span>
            <div className="sched-days">
              {DAYS.map((day) => (
                <button
                  key={day.value}
                  type="button"
                  className={`sched-day ${state.days.includes(day.value) ? "on" : ""}`}
                  aria-pressed={state.days.includes(day.value)}
                  onClick={() => toggleDay(day.value)}
                >
                  {day.short}
                </button>
              ))}
            </div>
          </div>
        )}

        {state.frequency === "monthly" && (
          <label className="field sched-narrow">
            <span className="lab">Day of month</span>
            <input
              className="inp mono"
              type="number"
              min={1}
              max={28}
              value={state.dayOfMonth}
              onChange={(event) => patch({ dayOfMonth: Number(event.target.value) })}
            />
            <span className="field-hint">1–28, so every month fires.</span>
          </label>
        )}

        {state.frequency === "custom" && (
          <label className="field">
            <span className="lab">Cron expression</span>
            <input
              className="inp mono"
              value={state.raw}
              onChange={(event) => patch({ raw: event.target.value })}
              placeholder="0 7 * * 1-5"
            />
            <span className="field-hint">Standard 5-field cron, or 6 fields with seconds.</span>
          </label>
        )}

        <label className="field sched-zone">
          <span className="lab">Timezone</span>
          <input
            className="inp"
            list="fbx-timezones"
            value={timezone}
            onChange={(event) => onTimezone(event.target.value)}
            placeholder="UTC"
          />
          <datalist id="fbx-timezones">
            {zones.map((zone) => (
              <option key={zone} value={zone} />
            ))}
          </datalist>
        </label>
      </div>

      <p className="sched-summary">
        <span>{describeSchedule(state, timezone)}</span>
        {generated.trim() && <code className="sched-cron">{generated}</code>}
      </p>
    </div>
  );
}

/** The browser's timezone, so the default matches where the person lives
 *  instead of silently meaning UTC. */
export function localTimezone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}
