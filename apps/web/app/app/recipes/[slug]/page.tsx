"use client";

// Recipe detail + deploy wizard. The page answers "what will this create,
// what will it touch, what will it cost" BEFORE anything is committed
// (manifest / integrations / permissions / budgets — all server-derived), and
// the wizard's review step renders the server's dry-run PLAN — the
// Terraform-plan moment. Secrets minted by the real deploy are shown exactly
// once, then the flow lands on the deployment page.

import { use, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  apiGet,
  apiGetCached,
  apiPost,
  Connection,
  ConnectionToolSnapshot,
  fetchConnectionTools,
} from "../../../lib/api";
import { LoadingRows, ModalShell, PageHead } from "../../../components/bits";
import { CopyBlock } from "../../../components/AutomationContract";
import {
  blockingIssue,
  eligibleConnections,
  initialParams,
  listFromText,
  paramsForSubmit,
  takePrefill,
  triggerLabel,
  type DeployPlan,
  type DeployResult,
  type RecipeDetail,
  type RecipeParamSpec,
  type RecipeWidget,
} from "../../../lib/recipes";

function errText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export default function RecipeDetailPage({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const { slug } = use(params);
  const [detail, setDetail] = useState<RecipeDetail | null>(null);
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loadErr, setLoadErr] = useState("");
  const [deploying, setDeploying] = useState(false);

  const load = useCallback(async () => {
    const [d, c] = await Promise.allSettled([
      apiGet<RecipeDetail>(`/recipes/${slug}`),
      apiGetCached<{ connections: Connection[] }>("/connections", { maxAgeMs: 15000 }),
    ]);
    if (d.status === "fulfilled") {
      setDetail(d.value);
      setLoadErr("");
    } else {
      setLoadErr(errText(d.reason));
    }
    if (c.status === "fulfilled") setConnections(c.value.connections ?? []);
  }, [slug]);
  useEffect(() => {
    void load();
  }, [load]);

  if (loadErr && !detail) {
    return (
      <div className="launch-empty">
        <p>Could not load this recipe.</p>
        <p className="err">{loadErr}</p>
        <Link className="btn" href="/app/recipes">
          Back to recipes
        </Link>
      </div>
    );
  }
  if (!detail) return <LoadingRows rows={4} />;

  const r = detail.recipe;
  const f = detail.facets;
  return (
    <>
      <PageHead
        leaf={r.name}
        title={r.name}
        sub={r.tagline}
        right={
          <button className="btn primary" onClick={() => setDeploying(true)}>
            Deploy…
          </button>
        }
      />
      <div className="chips" style={{ marginBottom: 18 }}>
        {r.tier === "official" ? (
          <span className="badge brand">Official</span>
        ) : (
          <span className="badge">Custom</span>
        )}
        <span className="chip">v{detail.version.version}</span>
        {f.trigger_kinds.map((k) => (
          <span key={k} className="chip">
            {triggerLabel(k)}
          </span>
        ))}
        {f.multi_agent && <span className="chip">{f.agent_count} agents</span>}
        <span className="chip">≤ ${f.cost_ceiling_usd.toFixed(2)} / run</span>
      </div>

      <div className="recipe-detail-grid">
        <div>
          <section className="panel pad">
            <h2 className="sectitle">What it does</h2>
            {(detail.summary_md ?? r.description)
              .split(/\n\n+/)
              .filter(Boolean)
              .map((p, i) => (
                <p key={i} className="recipe-prose">
                  {p}
                </p>
              ))}
          </section>

          {f.success_criteria.length > 0 && (
            <section className="panel pad">
              <h2 className="sectitle">What “working” means</h2>
              <ul className="recipe-list">
                {f.success_criteria.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </section>
          )}

          <section className="panel pad">
            <h2 className="sectitle">Permissions</h2>
            <PolicySummary summary={detail.policy_summary} />
          </section>
        </div>

        <div>
          <section className="panel pad">
            <h2 className="sectitle">What gets created</h2>
            <ul className="recipe-list">
              {detail.manifest.policy && <li>1 dedicated policy (tunable afterward in Governance)</li>}
              <li>
                {detail.manifest.agents.length} agent
                {detail.manifest.agents.length === 1 ? "" : "s"} (
                {detail.manifest.agents.map((a) => a.slot).join(", ")})
              </li>
              {detail.manifest.subscriptions.length > 0 && (
                <li>
                  {detail.manifest.subscriptions.length} automation
                  {detail.manifest.subscriptions.length === 1 ? "" : "s"} (
                  {detail.manifest.subscriptions.map((s) => triggerLabel(s.kind)).join(", ")})
                </li>
              )}
              {detail.manifest.first_run && <li>An immediate first run</li>}
            </ul>
            <p className="helper">
              Everything is stamped in one transaction and stays fully editable in
              Agents, Automations, and Governance — that is the path to a custom
              workflow.
            </p>
          </section>

          <section className="panel pad">
            <h2 className="sectitle">Integrations required</h2>
            {f.connectors.length === 0 ? (
              <p className="helper">None — this recipe needs no external connection.</p>
            ) : (
              <ul className="recipe-list">
                {f.connectors.map((c) => {
                  const have = eligibleConnections(
                    { kind: "connection", provider: c.provider, mcp: c.mcp },
                    connections,
                  );
                  return (
                    <li key={c.param}>
                      {c.title}
                      {c.required ? "" : " (optional)"} —{" "}
                      {have.length > 0 ? (
                        <span className="badge ok">connected</span>
                      ) : (
                        <Link href="/app/capabilities?tab=store" className="badge warn">
                          connect first →
                        </Link>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </section>

          <section className="panel pad">
            <h2 className="sectitle">Versions</h2>
            <ul className="recipe-list">
              {detail.versions.map((v) => (
                <li key={v.version}>
                  <strong>v{v.version}</strong>
                  {v.changelog ? ` — ${v.changelog}` : ""}{" "}
                  <span className="helper">({v.author})</span>
                </li>
              ))}
            </ul>
          </section>
        </div>
      </div>

      {deploying && (
        <DeployWizard
          slug={slug}
          detail={detail}
          connections={connections}
          onClose={() => setDeploying(false)}
        />
      )}
    </>
  );
}

function PolicySummary({ summary }: { summary: RecipeDetail["policy_summary"] }) {
  if (!summary.embedded) {
    return <p className="helper">{summary.note}</p>;
  }
  return (
    <>
      <div className="chips" style={{ marginBottom: 10 }}>
        <span className="chip">unmatched tools: {summary.default_action}</span>
        <span className="chip">
          autonomous runs: {summary.autonomy_permitted ? "permitted" : "refused"}
        </span>
        {summary.budgets?.max_cost_usd != null && (
          <span className="chip">≤ ${summary.budgets.max_cost_usd}/run</span>
        )}
        {summary.budgets?.max_wall_clock_secs != null && (
          <span className="chip">
            ≤ {Math.round((summary.budgets.max_wall_clock_secs as number) / 60)} min
          </span>
        )}
      </div>
      <div className="rows">
        {(summary.rules ?? []).map((rule, i) => (
          <div key={i} className="row recipe-rule-row">
            <span className="t" style={{ fontFamily: "var(--font-mono)", fontSize: 12 }}>
              {rule.tools.join(", ")}
            </span>
            <span>
              <span
                className={`badge ${
                  rule.action === "allow" ? "ok" : rule.action === "deny" ? "err" : "warn"
                }`}
              >
                {rule.action}
                {rule.constrained ? " (constrained)" : ""}
              </span>
            </span>
          </div>
        ))}
      </div>
      <p className="helper" style={{ marginTop: 8 }}>
        Verdicts are enforced server-side at the permission gate on every tool call —
        this table is the policy the deploy stamps.
      </p>
    </>
  );
}

// ─── The wizard ───────────────────────────────────────────────────────────

type WizardStage = "configure" | "review" | "done";

function DeployWizard({
  slug,
  detail,
  connections,
  onClose,
}: {
  slug: string;
  detail: RecipeDetail;
  connections: Connection[];
  onClose: () => void;
}) {
  const router = useRouter();
  const specs = detail.params;
  const prefill = useMemo(() => takePrefill(slug), [slug]);
  const [name, setName] = useState(prefill?.name ?? "");
  const [values, setValues] = useState<Record<string, unknown>>(
    () => prefill?.params ?? initialParams(specs),
  );
  const [stage, setStage] = useState<WizardStage>("configure");
  const [plan, setPlan] = useState<DeployPlan | null>(null);
  const [result, setResult] = useState<DeployResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [dirty, setDirty] = useState(Boolean(prefill));

  const setValue = (n: string, v: unknown) => {
    setDirty(true);
    setValues((prev) => ({ ...prev, [n]: v }));
  };

  const blocking = blockingIssue(name, specs, values);

  const review = async () => {
    setBusy(true);
    setErr("");
    try {
      const res = await apiPost<{ plan: DeployPlan }>(`/recipes/${slug}/deploy`, {
        name: name.trim(),
        params: paramsForSubmit(specs, values),
        dry_run: true,
      });
      setPlan(res.plan);
      setStage("review");
    } catch (e) {
      setErr(errText(e)); // server 4xx verbatim — it names the exact field
    } finally {
      setBusy(false);
    }
  };

  const deploy = async () => {
    setBusy(true);
    setErr("");
    try {
      const res = await apiPost<DeployResult>(`/recipes/${slug}/deploy`, {
        name: name.trim(),
        params: paramsForSubmit(specs, values),
      });
      setResult(res);
      setStage("done");
      setDirty(false);
    } catch (e) {
      setErr(errText(e));
    } finally {
      setBusy(false);
    }
  };

  const hasSecrets =
    result &&
    (Object.keys(result.secrets.trigger_tokens).length > 0 ||
      Object.keys(result.secrets.callback_secrets).length > 0);

  return (
    <ModalShell
      title={
        stage === "done"
          ? `Deployed: ${result?.instance.name ?? name}`
          : `Deploy ${detail.recipe.name}`
      }
      onClose={onClose}
      dirty={dirty && stage !== "done"}
      wide
    >
      {stage === "configure" && (
        <>
          <label className="field">
            <span className="lab">Deployment name</span>
            <input
              className="inp"
              value={name}
              placeholder={`e.g. ${detail.recipe.name} — main repo`}
              onChange={(e) => {
                setDirty(true);
                setName(e.target.value);
              }}
              autoFocus
            />
            <span className="field-hint">
              Names the stamped agents, automations, and policy.
            </span>
          </label>
          {specs.map((s) => (
            <ParamField
              key={s.name}
              spec={s}
              value={values[s.name]}
              values={values}
              connections={connections}
              onChange={(v) => setValue(s.name, v)}
            />
          ))}
          {err && <p className="err">{err}</p>}
          <div className="spread" style={{ marginTop: 16 }}>
            <span className="helper">{blocking ?? "Review shows the full plan before anything is created."}</span>
            <button
              className="btn primary"
              disabled={Boolean(blocking) || busy}
              onClick={() => void review()}
            >
              {busy ? "Validating…" : "Review plan"}
            </button>
          </div>
        </>
      )}

      {stage === "review" && plan && (
        <>
          <p className="helper">
            Nothing has been created yet. This is the exact set of objects the deploy
            will stamp — atomically, in one transaction.
          </p>
          <PlanView plan={plan} />
          {err && <p className="err">{err}</p>}
          <div className="spread" style={{ marginTop: 16 }}>
            <button className="btn ghost" onClick={() => setStage("configure")} disabled={busy}>
              ← Adjust
            </button>
            <button className="btn primary" disabled={busy} onClick={() => void deploy()}>
              {busy ? "Deploying…" : "Deploy"}
            </button>
          </div>
        </>
      )}

      {stage === "done" && result && (
        <>
          {result.first_run?.session_id ? (
            <p className="note">
              First run started —{" "}
              <Link href={`/app/sessions/${result.first_run.session_id}`}>
                watch it live →
              </Link>
            </p>
          ) : result.first_run?.error ? (
            <p className="err">First run did not start: {result.first_run.error}</p>
          ) : null}
          {hasSecrets && (
            <>
              <p className="note">
                Shown once — store these now. Rotation lives on each automation page.
              </p>
              {Object.entries(result.secrets.trigger_tokens).map(([slot, token]) => (
                <CopyBlock key={slot} label={`Trigger token · ${slot}`} value={token} />
              ))}
              {Object.entries(result.secrets.callback_secrets).map(([slot, secret]) => (
                <CopyBlock key={slot} label={`Webhook secret · ${slot}`} value={secret} />
              ))}
              {result.contracts.map((c) => (
                <CopyBlock key={c.subscription_id} label={`Invoke URL · ${c.slot}`} value={c.invoke_url} />
              ))}
            </>
          )}
          <div className="spread" style={{ marginTop: 16 }}>
            <button className="btn ghost" onClick={onClose}>
              Close
            </button>
            <button
              className="btn primary"
              onClick={() => router.push(`/app/recipes/instances/${result.instance.id}`)}
            >
              Open the deployment →
            </button>
          </div>
        </>
      )}
    </ModalShell>
  );
}

function PlanView({ plan }: { plan: DeployPlan }) {
  return (
    <div className="rows">
      {plan.policy && (
        <div className="row recipe-plan-row">
          <span className="badge brand">policy</span>
          <span className="t">{plan.policy.name}</span>
          <span className="helper">governs every stamped agent</span>
        </div>
      )}
      {plan.agents.map((a) => (
        <div key={a.slot} className="row recipe-plan-row">
          <span className="badge">agent</span>
          <span className="t">{a.name}</span>
          <span className="helper">
            {a.model}
            {a.budgets?.max_cost_usd != null ? ` · ≤ $${a.budgets.max_cost_usd}/run` : ""}
          </span>
        </div>
      ))}
      {plan.subscriptions.map((s) => (
        <div key={s.slot} className="row recipe-plan-row">
          <span className="badge">{triggerLabel(s.kind).toLowerCase()}</span>
          <span className="t">{s.name}</span>
          <span className="helper">
            {s.schedule
              ? `${s.schedule.cron} (${s.schedule.timezone})`
              : s.kind === "event"
                ? "fires on pull requests"
                : "invoked by API callers"}
            {s.autonomous ? " · autonomous" : " · supervised"}
            {s.signed_webhook ? " · signed webhook" : ""}
          </span>
        </div>
      ))}
      {plan.first_run && (
        <div className="row recipe-plan-row">
          <span className="badge ok">run</span>
          <span className="t">first run fires immediately</span>
          <span className="helper">agent: {plan.first_run.agent_slot}</span>
        </div>
      )}
      <div className="row recipe-plan-row">
        <span className="badge warn">cost</span>
        <span className="t">≤ ${plan.cost_ceiling_usd.toFixed(2)} per triggered run</span>
        <span className="helper">hard per-run ceilings, enforced server-side</span>
      </div>
    </div>
  );
}

// ─── Widget rendering ─────────────────────────────────────────────────────

function ParamField({
  spec,
  value,
  values,
  connections,
  onChange,
}: {
  spec: RecipeParamSpec;
  value: unknown;
  values: Record<string, unknown>;
  connections: Connection[];
  onChange: (v: unknown) => void;
}) {
  const label = (
    <span className="lab">
      {spec.title}
      {!spec.required && <span className="optional-label"> · optional</span>}
    </span>
  );
  const hint = spec.description ? (
    <span className="field-hint">{spec.description}</span>
  ) : null;
  const w = spec.widget;

  switch (w.kind) {
    case "connection":
      return (
        <ConnectionField
          label={label}
          hint={hint}
          widget={w}
          value={typeof value === "string" ? value : ""}
          connections={connections}
          onChange={onChange}
        />
      );
    case "connection_tools":
      return (
        <ConnectionToolsField
          spec={spec}
          label={label}
          hint={hint}
          connectionId={String(values[w.connection_param] ?? "")}
          value={Array.isArray(value) ? (value as string[]) : []}
          onChange={onChange}
        />
      );
    case "events": {
      const chosen = Array.isArray(value) ? (value as string[]) : [];
      const options = (spec.choices ?? []).map(String);
      return (
        <div className="field">
          {label}
          <div className="chips">
            {options.map((opt) => (
              <label key={opt} className={`chip recipe-choice ${chosen.includes(opt) ? "on" : ""}`}>
                <input
                  type="checkbox"
                  checked={chosen.includes(opt)}
                  onChange={(e) =>
                    onChange(
                      e.target.checked
                        ? [...chosen, opt]
                        : chosen.filter((x) => x !== opt),
                    )
                  }
                />
                {opt}
                {opt === "synchronize" ? " (every push)" : ""}
              </label>
            ))}
          </div>
          {hint}
        </div>
      );
    }
    case "select":
    case "model": {
      const options = (spec.choices ?? []).map(String);
      return (
        <label className="field">
          {label}
          <select
            className="inp"
            value={typeof value === "string" ? value : ""}
            onChange={(e) => onChange(e.target.value)}
          >
            {!spec.required && <option value="">—</option>}
            {options.map((o) => (
              <option key={o} value={o}>
                {o}
              </option>
            ))}
          </select>
          {hint}
        </label>
      );
    }
    case "repositories":
    case "string_list": {
      const list = Array.isArray(value) ? (value as string[]).join(", ") : "";
      return (
        <label className="field">
          {label}
          <input
            className="inp"
            value={list}
            placeholder={w.kind === "repositories" ? "owner/name, owner/other" : "one, two"}
            onChange={(e) => onChange(listFromText(e.target.value))}
          />
          {hint ?? (
            <span className="field-hint">Comma-separated.</span>
          )}
        </label>
      );
    }
    case "textarea":
      return (
        <label className="field">
          {label}
          <textarea
            className="inp"
            rows={4}
            value={typeof value === "string" ? value : ""}
            onChange={(e) => onChange(e.target.value)}
          />
          {hint}
        </label>
      );
    case "boolean":
      return (
        <label className="field recipe-choice">
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(e) => onChange(e.target.checked)}
          />
          {label}
          {hint}
        </label>
      );
    case "number":
      return (
        <label className="field">
          {label}
          <input
            className="inp"
            type="number"
            value={value === undefined || value === null ? "" : String(value)}
            onChange={(e) => onChange(e.target.value)}
          />
          {hint}
        </label>
      );
    case "cron":
      return (
        <label className="field">
          {label}
          <input
            className="inp"
            value={typeof value === "string" ? value : ""}
            placeholder="0 9 * * 1"
            onChange={(e) => onChange(e.target.value)}
          />
          {hint ?? (
            <span className="field-hint">
              Five-field cron: minute hour day-of-month month day-of-week.
            </span>
          )}
        </label>
      );
    default:
      return (
        <label className="field">
          {label}
          <input
            className="inp"
            value={typeof value === "string" ? value : ""}
            onChange={(e) => onChange(e.target.value)}
          />
          {hint}
        </label>
      );
  }
}

function ConnectionField({
  label,
  hint,
  widget,
  value,
  connections,
  onChange,
}: {
  label: React.ReactNode;
  hint: React.ReactNode;
  widget: Extract<RecipeWidget, { kind: "connection" }>;
  value: string;
  connections: Connection[];
  onChange: (v: string) => void;
}) {
  const eligible = eligibleConnections(widget, connections);
  return (
    <div className="field">
      {label}
      {eligible.length === 0 ? (
        <p className="note">
          No matching active connection.{" "}
          <Link href="/app/capabilities?tab=store">Connect one in Capabilities →</Link>{" "}
          then come back — this form keeps your inputs.
        </p>
      ) : (
        <select className="inp" value={value} onChange={(e) => onChange(e.target.value)}>
          <option value="">Choose a connection…</option>
          {eligible.map((c) => (
            <option key={c.id} value={c.id}>
              {c.display_name} ({c.provider})
            </option>
          ))}
        </select>
      )}
      {hint}
    </div>
  );
}

function ConnectionToolsField({
  spec,
  label,
  hint,
  connectionId,
  value,
  onChange,
}: {
  spec: RecipeParamSpec;
  label: React.ReactNode;
  hint: React.ReactNode;
  connectionId: string;
  value: string[];
  onChange: (v: string[]) => void;
}) {
  const [snapshot, setSnapshot] = useState<ConnectionToolSnapshot | null>(null);
  const [snapErr, setSnapErr] = useState("");
  useEffect(() => {
    setSnapshot(null);
    setSnapErr("");
    if (!connectionId) return;
    fetchConnectionTools(connectionId)
      .then((s) => setSnapshot(s))
      .catch((e) => setSnapErr(errText(e)));
  }, [connectionId]);

  if (!connectionId) {
    return (
      <div className="field">
        {label}
        <p className="helper">Choose the connection above first — its live tool list appears here.</p>
      </div>
    );
  }
  const tools = snapshot?.tools?.map((t) => t.name) ?? [];
  return (
    <div className="field">
      {label}
      {snapErr ? (
        <p className="err">{snapErr}</p>
      ) : snapshot === null ? (
        <p className="helper">Loading the connection’s tool snapshot…</p>
      ) : tools.length === 0 ? (
        <p className="note">
          This connection has no tool snapshot — refresh its tools in Capabilities.
        </p>
      ) : (
        <div className="chips">
          {tools.map((t) => (
            <label key={t} className={`chip recipe-choice ${value.includes(t) ? "on" : ""}`}>
              <input
                type="checkbox"
                checked={value.includes(t)}
                onChange={(e) =>
                  onChange(
                    e.target.checked ? [...value, t] : value.filter((x) => x !== t),
                  )
                }
              />
              {t}
            </label>
          ))}
        </div>
      )}
      {hint ?? (
        <span className="field-hint">
          Only the tools you pick here are callable — this selection is frozen into
          every run. {spec.required ? "" : "Optional."}
        </span>
      )}
    </div>
  );
}
