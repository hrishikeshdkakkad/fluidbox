"use client";

// One recipe deployment: provenance (recipe + pinned version + params),
// every stamped object with a deep link into its native editor (the
// "eject to custom" path IS those editors), recent runs live, the integration
// contract, and the full lifecycle — run now, pause/resume, upgrade (dry-run
// diff first), duplicate, delete (consequences stated, soft by design).

import { use, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { apiDelete, apiGet, apiPost, Session } from "../../../../lib/api";
import { LoadingRows, ModalShell, PageHead, Pill, short, timeAgo } from "../../../../components/bits";
import { CopyBlock } from "../../../../components/AutomationContract";
import { useSmartPolling } from "../../../../lib/useSmartPolling";
import {
  stashPrefill,
  type InstanceContract,
  type InstanceObject,
  type RecipeInstance,
  type UpgradePlan,
} from "../../../../lib/recipes";

interface InstanceDetail {
  instance: RecipeInstance;
  objects: InstanceObject[];
  sessions: Session[];
  latest_version: number;
  update_available: boolean;
  contracts: InstanceContract[];
}

function errText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export default function RecipeInstancePage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = use(params);
  const router = useRouter();
  const [detail, setDetail] = useState<InstanceDetail | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const [actionErr, setActionErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [upgrade, setUpgrade] = useState<UpgradePlan | null>(null);

  const load = useCallback(async () => {
    try {
      setDetail(await apiGet<InstanceDetail>(`/recipes/instances/${id}`));
      setLoadErr("");
    } catch (e) {
      if (!detail) setLoadErr(errText(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);
  useSmartPolling(load, 5000);
  useEffect(() => {
    void load();
  }, [load]);

  const act = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setActionErr("");
    try {
      await fn();
      await load();
    } catch (e) {
      setActionErr(errText(e)); // server message verbatim — it names the rule
    } finally {
      setBusy(false);
    }
  };

  // As in recipes/[slug]: the crumb trail and the <h1> come from the route, so
  // a failed load must not take them down with it. A deployment id is not a
  // readable label, so the crumb carries the short form the run pages use.
  if (loadErr && !detail) {
    return (
      <>
        <PageHead title="Deployment" leaf={short(id)} />
        <div className="launch-empty">
          <p>Could not load this deployment.</p>
          <p className="err">{loadErr}</p>
          <Link className="btn" href="/app/recipes?tab=deployments">
            Back to deployments
          </Link>
        </div>
      </>
    );
  }
  if (!detail) return <LoadingRows rows={4} />;
  const { instance, objects, sessions, contracts } = detail;
  const deleted = instance.status === "deleted";
  const paused = instance.status === "paused";

  return (
    <>
      <PageHead
        leaf={instance.name}
        title={instance.name}
        sub={`From ${instance.recipe_slug} · v${instance.recipe_version}`}
        right={<Pill status={instance.status} />}
      />

      {detail.update_available && !deleted && (
        <div className="note recipe-update-banner">
          <span>
            v{detail.latest_version} of this recipe is available (deployed: v
            {instance.recipe_version}).
          </span>
          <button
            className="btn sm"
            disabled={busy}
            onClick={() =>
              void act(async () => {
                const res = await apiPost<{ plan: UpgradePlan }>(
                  `/recipes/instances/${id}/upgrade`,
                  { dry_run: true },
                );
                setUpgrade(res.plan);
              })
            }
          >
            Preview upgrade…
          </button>
        </div>
      )}

      <div className="spread" style={{ margin: "14px 0" }}>
        <div className="chips">
          <button
            className="btn sm primary"
            disabled={busy || deleted}
            onClick={() =>
              void act(async () => {
                const res = await apiPost<{ session_id?: string }>(
                  `/recipes/instances/${id}/run`,
                  {},
                );
                if (res.session_id) router.push(`/app/sessions/${res.session_id}`);
              })
            }
          >
            Run now
          </button>
          {paused ? (
            <button
              className="btn sm"
              disabled={busy || deleted}
              onClick={() => void act(() => apiPost(`/recipes/instances/${id}/resume`, {}))}
            >
              Resume
            </button>
          ) : (
            <button
              className="btn sm"
              disabled={busy || deleted}
              onClick={() => void act(() => apiPost(`/recipes/instances/${id}/pause`, {}))}
            >
              Pause
            </button>
          )}
          <button
            className="btn sm"
            disabled={busy}
            onClick={() => {
              stashPrefill(instance.recipe_slug, `${instance.name} copy`, instance.params);
              router.push(`/app/recipes/${instance.recipe_slug}`);
            }}
          >
            Duplicate
          </button>
          <button
            className="btn sm danger"
            disabled={busy || deleted}
            onClick={() => setConfirmDelete(true)}
          >
            Delete
          </button>
        </div>
        {actionErr && <span className="err">{actionErr}</span>}
      </div>

      <div className="recipe-detail-grid">
        <div>
          <section className="panel pad">
            <h2 className="sectitle">Runs</h2>
            {sessions.length === 0 ? (
              <p className="helper">
                No runs yet — “Run now”, the schedule, or an API/event trigger will
                start one.
              </p>
            ) : (
              <div className="rows">
                {sessions.map((s) => (
                  <Link
                    key={s.id}
                    href={`/app/sessions/${s.id}`}
                    className="row recipe-run-row"
                    prefetch={false}
                  >
                    <span>
                      <Pill status={s.status} />
                    </span>
                    <span className="t recipe-run-task">{s.task}</span>
                    <span className="helper">{timeAgo(s.created_at)}</span>
                  </Link>
                ))}
              </div>
            )}
          </section>

          {contracts.length > 0 && !deleted && (
            <section className="panel pad">
              <h2 className="sectitle">Integration contract</h2>
              <p className="helper">
                Invoke with the trigger token shown once at deploy time (rotate it on
                the automation page).
              </p>
              {contracts.map((c) => (
                <CopyBlock
                  key={c.subscription_id}
                  label={`Invoke · ${c.slot}`}
                  value={c.invoke_url}
                />
              ))}
            </section>
          )}
        </div>

        <div>
          <section className="panel pad">
            <h2 className="sectitle">What this deployment owns</h2>
            <div className="rows">
              {objects
                .filter((o) => o.kind !== "session")
                .map((o) => (
                  <div key={`${o.kind}-${o.object_id}`} className="row recipe-plan-row">
                    <span className={`badge ${o.kind === "policy" ? "brand" : ""}`}>
                      {o.kind}
                    </span>
                    <span className="t">{o.name ?? o.slot}</span>
                    <span>
                      <ObjectLink obj={o} />
                    </span>
                  </div>
                ))}
            </div>
            <p className="helper" style={{ marginTop: 8 }}>
              These are ordinary fluidbox objects — edit them in their own pages to
              take this workflow custom. Runs keep their frozen snapshots either way.
            </p>
          </section>

          <section className="panel pad">
            <h2 className="sectitle">Configuration</h2>
            <div className="rows">
              {Object.entries(instance.params).map(([k, v]) => (
                <div key={k} className="row recipe-plan-row">
                  <span className="helper">{k}</span>
                  <span className="t recipe-param-value">
                    {Array.isArray(v) ? v.join(", ") : String(v)}
                  </span>
                  <span />
                </div>
              ))}
            </div>
            <p className="helper" style={{ marginTop: 8 }}>
              Parameters are frozen into this deployment; change them by duplicating
              (or upgrading when a new version asks for more).
            </p>
          </section>
        </div>
      </div>

      {upgrade && (
        <ModalShell title={`Upgrade to v${upgrade.to_version}`} onClose={() => setUpgrade(null)}>
          <p className="helper">
            In-place, compatible changes only — structural changes are refused and
            need a fresh deployment. Runs in flight keep their frozen snapshots.
          </p>
          <ul className="recipe-list">
            {upgrade.agents_updated.length > 0 && (
              <li>
                Agents updated (new revision appended):{" "}
                {upgrade.agents_updated.join(", ")}
              </li>
            )}
            {upgrade.subscriptions_updated.length > 0 && (
              <li>
                Automations updated:{" "}
                {upgrade.subscriptions_updated.map((s) => s.slot).join(", ")}
              </li>
            )}
            {upgrade.policy_updated && <li>Policy: new version appended</li>}
            {upgrade.agents_updated.length === 0 &&
              upgrade.subscriptions_updated.length === 0 &&
              !upgrade.policy_updated && <li>No object changes — version pointer only.</li>}
          </ul>
          {actionErr && <p className="err">{actionErr}</p>}
          <div className="spread" style={{ marginTop: 16 }}>
            <button className="btn ghost" onClick={() => setUpgrade(null)}>
              Not now
            </button>
            <button
              className="btn primary"
              disabled={busy}
              onClick={() =>
                void act(async () => {
                  await apiPost(`/recipes/instances/${id}/upgrade`, {});
                  setUpgrade(null);
                })
              }
            >
              {busy ? "Upgrading…" : `Apply v${upgrade.to_version}`}
            </button>
          </div>
        </ModalShell>
      )}

      {confirmDelete && (
        <ModalShell title={`Delete ${instance.name}?`} onClose={() => setConfirmDelete(false)}>
          <p>
            This disables every automation this deployment owns, so nothing fires
            again. The stamped agents, policy, and run history <strong>remain</strong>{" "}
            — they are append-only audit records other objects may reference.
          </p>
          <div className="spread" style={{ marginTop: 16 }}>
            <button className="btn ghost" onClick={() => setConfirmDelete(false)}>
              Keep it
            </button>
            <button
              className="btn danger"
              disabled={busy}
              onClick={() =>
                void act(async () => {
                  await apiDelete(`/recipes/instances/${id}`);
                  setConfirmDelete(false);
                })
              }
            >
              {busy ? "Deleting…" : "Delete deployment"}
            </button>
          </div>
        </ModalShell>
      )}
    </>
  );
}

function ObjectLink({ obj }: { obj: InstanceObject }) {
  switch (obj.kind) {
    case "agent":
      return (
        <Link className="helper" href="/app/agents">
          open in Agents →
        </Link>
      );
    case "subscription":
      return (
        <Link className="helper" href={`/app/automations/${obj.object_id}`}>
          open automation →
        </Link>
      );
    case "policy":
      return obj.name ? (
        <Link className="helper" href={`/app/governance/${obj.name}`}>
          open in Governance →
        </Link>
      ) : null;
    default:
      return null;
  }
}
