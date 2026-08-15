"use client";

import { useCallback, useState } from "react";
import { apiGet, Session } from "../../lib/api";
import { AutomationPanel } from "../../components/AutomationPanel";
import { RunHistory } from "../../components/RunHistory";
import {
  MintedAutomation,
  RunComposer,
  RunMode,
  ShowAutomationSecrets,
} from "../../components/RunComposer";
import { LoadingRows, PageHead } from "../../components/bits";
import { useSmartPolling } from "../../lib/useSmartPolling";

// The activity workbench (2026-08-14 navigation-boundary design): run history
// and automations as a real place — what the masthead's `activity` points at
// and what sessions/* and automations/* breadcrumb back to. Overview keeps the
// operations summary; the list itself is the shared RunHistory component, so
// the two surfaces cannot drift.
export default function ActivityPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
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
  }, []);

  useSmartPolling(load, 2500);

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

      <section className="operate-view" aria-labelledby="activity-runs-heading">
        <div className="section-heading recent-heading">
          <div>
            <span className="section-kicker">Every invocation</span>
            <h2 id="activity-runs-heading">Run history</h2>
          </div>
          <span className="section-note">Runs open their live timeline and diff.</span>
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
          ) : (
            <RunHistory sessions={sessions} />
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
