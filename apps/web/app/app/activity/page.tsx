"use client";

import { useCallback, useMemo, useState } from "react";
import { Agent, apiGet, apiGetCached, Session } from "../../lib/api";
import { ActivityFilter, filterSessions, groupCounts } from "../../lib/activity";
import { ActivityPulse } from "../../components/ActivityPulse";
import { AutomationPanel } from "../../components/AutomationPanel";
import { RunTable } from "../../components/RunTable";
import {
  MintedAutomation,
  RunComposer,
  RunMode,
  ShowAutomationSecrets,
} from "../../components/RunComposer";
import { LoadingRows, PageHead } from "../../components/bits";
import { useSmartPolling } from "../../lib/useSmartPolling";

const FILTERS: { key: ActivityFilter; label: string }[] = [
  { key: "all", label: "all" },
  { key: "live", label: "live" },
  { key: "attention", label: "waiting" },
  { key: "failed", label: "failed" },
  { key: "completed", label: "completed" },
];

// The activity workbench (2026-08-14 navigation-boundary design): run history
// and automations as a real place — what the masthead's `activity` points at
// and what sessions/* and automations/* breadcrumb back to. Overview keeps the
// operations summary; the list itself is the shared RunHistory component, so
// the two surfaces cannot drift. This page adds the triage layer on top: the
// 24h pulse, filter chips, and day grouping — all pure derivations of the
// same polled list (lib/activity.ts), never a second source of truth.
export default function ActivityPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [agentNames, setAgentNames] = useState<ReadonlyMap<string, string>>(new Map());
  const [filter, setFilter] = useState<ActivityFilter>("all");
  const [composerMode, setComposerMode] = useState<RunMode | null>(null);
  const [minted, setMinted] = useState<MintedAutomation | null>(null);
  const [automationRefresh, setAutomationRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [hasSnapshot, setHasSnapshot] = useState(false);
  const [offline, setOffline] = useState(false);

  const load = useCallback(async () => {
    try {
      const response = await apiGet<{ sessions: Session[] }>("/sessions?limit=50");
      setSessions(response.sessions);
      setHasSnapshot(true);
      setOffline(false);
    } catch {
      // Keep the last good snapshot, but never present a failed first read as
      // real zero activity.
      setOffline(true);
    } finally {
      setLoading(false);
    }
    try {
      // Names are chrome, not truth: a failed read just leaves ids meta-less.
      const agentResponse = await apiGetCached<{ agents: Agent[] }>("/agents", {
        maxAgeMs: 15_000,
      });
      setAgentNames(new Map(agentResponse.agents.map((agent) => [agent.id, agent.name])));
    } catch {
      // Rows fall back to trigger/workspace/id — never block the timeline.
    }
  }, []);

  useSmartPolling(load, 2500);

  const counts = useMemo(() => groupCounts(sessions), [sessions]);
  const visible = useMemo(() => filterSessions(sessions, filter), [sessions, filter]);
  const chipCount = (key: ActivityFilter): number =>
    key === "all" ? sessions.length : counts[key];

  return (
    <>
      <PageHead
        title="Activity"
        sub="Manual and automated runs share one timeline."
        right={
          <button className="btn primary" type="button" onClick={() => setComposerMode("once")}>
            New Run
          </button>
        }
      />

      {sessions.length > 0 && <ActivityPulse sessions={sessions} />}

      <section className="operate-view" aria-labelledby="activity-runs-heading">
        <div className="section-heading recent-heading">
          <div>
            <span className="section-kicker">Every invocation</span>
            <h2 id="activity-runs-heading">Run history</h2>
          </div>
          {sessions.length > 0 && (
            <div className="run-filters" role="group" aria-label="Filter runs by status">
              {FILTERS.map(({ key, label }) => {
                const count = chipCount(key);
                if (key !== "all" && count === 0) return null;
                return (
                  <button
                    key={key}
                    type="button"
                    className={`run-filter ${key}${filter === key ? " on" : ""}`}
                    aria-pressed={filter === key}
                    onClick={() => setFilter(key)}
                  >
                    {label}
                    <b>{count}</b>
                  </button>
                );
              })}
            </div>
          )}
        </div>
        <div className="run-list">
          {loading ? (
            <LoadingRows />
          ) : offline && !hasSnapshot ? (
            <div className="launch-empty">
              <div>
                <h3>Control plane unavailable.</h3>
                <p>Run history could not be loaded. Your browser will keep retrying in the background.</p>
              </div>
              <div className="empty-actions">
                <button className="btn" type="button" onClick={() => void load()}>
                  Retry now
                </button>
              </div>
            </div>
          ) : sessions.length === 0 ? (
            <div className="launch-empty">
              <div>
                <h3>No runs yet.</h3>
                <p>Configure a run once, or save it as an automation below.</p>
              </div>
              <div className="empty-actions">
                <button className="btn primary" type="button" onClick={() => setComposerMode("once")}>
                  Configure a run
                </button>
              </div>
            </div>
          ) : visible.length === 0 ? (
            <div className="launch-empty slim">
              <div>
                <h3>Nothing {FILTERS.find((f) => f.key === filter)?.label} right now.</h3>
                <p>Runs matching this filter will appear here as the timeline moves.</p>
              </div>
              <div className="empty-actions">
                <button className="btn" type="button" onClick={() => setFilter("all")}>
                  Show all runs
                </button>
              </div>
            </div>
          ) : (
            <RunTable sessions={visible} agents={agentNames} />
          )}
        </div>
      </section>

      <section className="operate-view" aria-labelledby="automations-heading">
        <AutomationPanel
          onNew={() => setComposerMode("automation")}
          refreshKey={automationRefresh}
        />
      </section>

      {composerMode && (
        <RunComposer
          initialMode={composerMode}
          onClose={() => setComposerMode(null)}
          onRunCreated={() => {
            setComposerMode(null);
            void load();
          }}
          onAutomationCreated={(automation) => {
            setComposerMode(null);
            setMinted(automation);
            setAutomationRefresh((current) => current + 1);
          }}
        />
      )}

      {minted && <ShowAutomationSecrets minted={minted} onClose={() => setMinted(null)} />}
    </>
  );
}
