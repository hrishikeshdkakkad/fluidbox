"use client";

import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "next/navigation";
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
import { clampPage, Pager, PageSize, PAGE_SIZES } from "../../components/Pager";
import { useSmartPolling } from "../../lib/useSmartPolling";

const FILTERS: { key: ActivityFilter; label: string }[] = [
  { key: "all", label: "all" },
  { key: "live", label: "live" },
  { key: "attention", label: "waiting" },
  { key: "failed", label: "failed" },
  { key: "completed", label: "completed" },
];

// The paging window: how deep the board can walk without a second fetch. The
// list endpoint takes a plain `limit` (no offset), so the board fetches one
// deep window and pages it client-side — 200 rows of Session metadata is a
// few tens of KB, cheap against the 2.5s poll it already rides.
const SESSIONS_WINDOW = 200;

// The activity workbench (2026-08-14 navigation-boundary design, board
// composition 2026-08-16): run history and automations as a real place —
// what the masthead's `activity` points at and what sessions/* and
// automations/* breadcrumb back to. Overview keeps the operations summary;
// the run list is RunTable, which lives only here. This page owns the triage
// layer — the 24h pulse,
// filter chips, day grouping, and paging — all pure derivations of the same
// polled list (lib/activity.ts), never a second source of truth. The pulse,
// filters, table, and pager fuse into ONE instrument card (.activity-board):
// the strip reads like a seismograph directly above the log it summarizes.
export default function ActivityPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [agentNames, setAgentNames] = useState<ReadonlyMap<string, string>>(new Map());
  const [filter, setFilter] = useState<ActivityFilter>("all");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState<PageSize>(PAGE_SIZES[0]);
  const [composerMode, setComposerMode] = useState<RunMode | null>(null);
  const [minted, setMinted] = useState<MintedAutomation | null>(null);
  const [automationRefresh, setAutomationRefresh] = useState(0);
  const [loading, setLoading] = useState(true);
  const [hasSnapshot, setHasSnapshot] = useState(false);
  const [offline, setOffline] = useState(false);

  const load = useCallback(async () => {
    try {
      const response = await apiGet<{ sessions: Session[] }>(
        `/sessions?limit=${SESSIONS_WINDOW}`
      );
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

  // Overview's metrics link here with a filter already chosen; seeding the
  // chip from the URL is what makes that hand-off land where it promised.
  const applyQueryFilter = useCallback((next: ActivityFilter) => {
    setFilter(next);
    setPage(1);
  }, []);

  const counts = useMemo(() => groupCounts(sessions), [sessions]);
  const visible = useMemo(() => filterSessions(sessions, filter), [sessions, filter]);
  // The poll can shrink the list under the operator (runs age out of the
  // window, a filter empties): clamp instead of storing a page that no
  // longer exists, so the board never renders a blank page of nothing.
  const currentPage = clampPage(page, visible.length, pageSize);
  const pageSessions = useMemo(
    () => visible.slice((currentPage - 1) * pageSize, currentPage * pageSize),
    [visible, currentPage, pageSize]
  );
  const chipCount = (key: ActivityFilter): number =>
    key === "all" ? sessions.length : counts[key];

  return (
    <>
      <Suspense fallback={null}>
        <QueryState onFilter={applyQueryFilter} onCompose={setComposerMode} />
      </Suspense>
      <PageHead
        title="Activity"
        sub="Manual and automated runs share one timeline."
        right={
          <>
            {/* Stacked widths bury the automations half below the fold — the
                jump link announces it exists. Hidden when the split layout
                puts the rail on screen anyway. */}
            <a className="btn ghost automations-jump" href="#automations-heading">
              Automations ↓
            </a>
            <button className="btn primary" type="button" onClick={() => setComposerMode("once")}>
              New Run
            </button>
          </>
        }
      />

      <div className="activity-workbench">
      <section className="operate-view activity-board" aria-labelledby="activity-runs-heading">
        <div className="section-heading board-head">
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
                    onClick={() => {
                      setFilter(key);
                      setPage(1);
                    }}
                  >
                    {label}
                    <b>{count}</b>
                  </button>
                );
              })}
            </div>
          )}
        </div>
        {sessions.length > 0 && <ActivityPulse sessions={sessions} />}
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
            <RunTable sessions={pageSessions} agents={agentNames} />
          )}
        </div>
        {!loading && visible.length > 0 && (
          <Pager
            page={currentPage}
            total={visible.length}
            pageSize={pageSize}
            onPage={setPage}
            onPageSize={(size) => {
              setPageSize(size);
              setPage(1);
            }}
          />
        )}
      </section>

      <section className="operate-view automation-rail" aria-labelledby="automations-heading">
        <AutomationPanel
          onNew={() => setComposerMode("automation")}
          refreshKey={automationRefresh}
        />
      </section>
      </div>

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

/**
 * Seeds page state from the query: the triage filter (Overview's metric links)
 * and the run composer (`compose=`, so a shared configuration reopens here the
 * same way it does on Overview). Its own component behind Suspense because
 * `useSearchParams` opts the whole subtree out of static rendering otherwise.
 * An unrecognised filter is ignored rather than clearing the chips — a bad URL
 * should not hide runs.
 */
function QueryState({
  onFilter,
  onCompose,
}: {
  onFilter: (filter: ActivityFilter) => void;
  onCompose: (mode: RunMode) => void;
}) {
  const params = useSearchParams();
  const requested = params.get("filter");
  const compose = params.get("compose");
  const composeMode = params.get("mode");

  useEffect(() => {
    if (requested && FILTERS.some((entry) => entry.key === requested)) {
      onFilter(requested as ActivityFilter);
    }
  }, [requested, onFilter]);

  useEffect(() => {
    if (compose === "run") onCompose(composeMode === "automation" ? "automation" : "once");
  }, [compose, composeMode, onCompose]);

  return null;
}
