"use client";

// One policy, fully resolved — and now AUTHORABLE (design §4.4). The page owns
// a client-side DRAFT of the policy content; every editor (matrix, rules,
// limits) mutates the draft, the server's preview endpoint resolves what the
// draft MEANS (matrix verdicts, autonomy summary — the browser never computes
// one), and Publish mints ONE immutable version with a summary, guarded by the
// version this draft loaded from (a moved head is a 409, never a silent
// overwrite). History lists every version; revert publishes an old one
// forward. A lost draft costs a re-edit — drafts are deliberately not
// persisted server-side (a second source of truth would be worse).

import { use, useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  apiGet,
  apiPost,
  MatrixRow,
  PolicyAction,
  PolicyContent,
  PolicyDetail,
  PolicyPreview,
  ToolRule,
} from "../../lib/api";
import { LoadingRows, PageHead } from "../../components/bits";
import { isExactHeadRule, PermissionMatrix } from "../../components/PermissionMatrix";
import { PolicyLimits } from "../../components/PolicyLimits";
import { PolicyRulesEditor } from "../../components/PolicyRulesEditor";
import { PolicyVersionHistory } from "../../components/PolicyVersionHistory";

/** The resolved payload both sources share: the detail (clean) or the preview
 *  (dirty draft). One shape so every section renders from one place. */
interface Resolved {
  matrix: MatrixRow[];
  autonomy_summary: PolicyDetail["autonomy_summary"];
}

export default function PolicyDetailPage({ params }: { params: Promise<{ name: string }> }) {
  const { name } = use(params);
  const encoded = encodeURIComponent(name);
  const [detail, setDetail] = useState<PolicyDetail | null>(null);
  const [draft, setDraft] = useState<PolicyContent | null>(null);
  const [preview, setPreview] = useState<PolicyPreview | null>(null);
  const [previewError, setPreviewError] = useState("");
  const [summary, setSummary] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  const [publishing, setPublishing] = useState(false);
  const previewSeq = useRef(0);

  const load = useCallback(async () => {
    setErr("");
    try {
      const next = await apiGet<PolicyDetail>(`/policies/${encoded}`);
      setDetail(next);
      setDraft(structuredClone(next.content));
      setPreview(null);
      setPreviewError("");
      setSummary("");
    } catch (reason) {
      setErr(`This policy could not be loaded. ${String(reason)}`);
    } finally {
      setLoading(false);
    }
  }, [encoded]);

  useEffect(() => {
    const timer = window.setTimeout(() => void load(), 0);
    return () => window.clearTimeout(timer);
  }, [load]);

  const dirty = useMemo(
    () => !!detail && !!draft && JSON.stringify(draft) !== JSON.stringify(detail.content),
    [detail, draft]
  );

  // The dirty draft's meaning comes from the SERVER: a debounced preview
  // resolves matrix + autonomy for exactly the content that would publish.
  useEffect(() => {
    if (!dirty || !draft) {
      setPreview(null);
      setPreviewError("");
      return;
    }
    const seq = ++previewSeq.current;
    const timer = window.setTimeout(() => {
      apiPost<PolicyPreview>("/policies/preview", { content: draft, name })
        .then((resolved) => {
          if (previewSeq.current !== seq) return;
          setPreview(resolved);
          setPreviewError("");
        })
        .catch((reason) => {
          if (previewSeq.current !== seq) return;
          setPreview(null);
          setPreviewError(String(reason).replace(/^Error:\s*/, ""));
        });
    }, 350);
    return () => window.clearTimeout(timer);
  }, [dirty, draft, name]);

  const resolved: Resolved | null = useMemo(() => {
    if (dirty) return preview;
    return detail ? { matrix: detail.matrix, autonomy_summary: detail.autonomy_summary } : null;
  }, [detail, dirty, preview]);

  // The matrix edits the DRAFT: an exact-name head rule per decided tool. The
  // WINNING rule index comes from the server-resolved row — the page checks
  // only the STRUCTURE of the rule at that index, never a verdict.
  const setTool = (tool: string, action: PolicyAction) => {
    if (!draft || !resolved) return;
    const row = resolved.matrix.find((r) => r.tool === tool);
    setDraft((current) => {
      if (!current) return current;
      const tools = [...current.tools];
      const idx =
        row && row.status.status === "unconditional" && row.status.rule != null
          ? row.status.rule
          : null;
      if (idx != null && isExactHeadRule(tools[idx], tool)) {
        tools[idx] = { ...tools[idx], action };
      } else {
        tools.unshift({ match: [tool], action });
      }
      return { ...current, tools };
    });
  };

  const clearTool = (tool: string) => {
    if (!draft || !resolved) return;
    const row = resolved.matrix.find((r) => r.tool === tool);
    if (!row || row.status.status !== "unconditional" || row.status.rule == null) return;
    const idx = row.status.rule;
    setDraft((current) => {
      if (!current || !isExactHeadRule(current.tools[idx], tool)) return current;
      return { ...current, tools: current.tools.filter((_, i) => i !== idx) };
    });
  };

  const publish = async () => {
    if (!detail || !draft) return;
    setPublishing(true);
    setErr("");
    try {
      await apiPost(`/policies/${encoded}/publish`, {
        content: draft,
        summary: summary.trim(),
        base_version: detail.policy.version,
      });
      await load();
    } catch (reason) {
      setErr(String(reason).replace(/^Error:\s*/, ""));
    } finally {
      setPublishing(false);
    }
  };

  if (!detail || !draft) {
    return (
      <>
        <PageHead title={name} crumbs={[{ href: "/governance", label: "Governance" }]} />
        {err ? (
          <div className="err" role="alert">
            {err}
          </div>
        ) : null}
        <div className="panel">
          {loading ? (
            <LoadingRows />
          ) : (
            <div className="launch-empty">
              <div>
                <h3>Policy detail is unavailable.</h3>
                <p>No policy rules or limits were inferred from the failed response.</p>
              </div>
              <div className="empty-actions">
                <button
                  className="btn"
                  type="button"
                  onClick={() => {
                    setLoading(true);
                    void load();
                  }}
                >
                  Retry now
                </button>
              </div>
            </div>
          )}
        </div>
      </>
    );
  }

  const a = resolved?.autonomy_summary;
  const contrary = a ? (a.default_fallback === "deny" ? a.allow_overrides : a.deny_overrides) : 0;
  const contraryVerb = a?.default_fallback === "deny" ? "allow" : "deny";
  const knownTools = (resolved ?? { matrix: detail.matrix }).matrix.map((r) => r.tool);

  return (
    <>
      <PageHead
        title={detail.policy.name}
        sub={`Version ${detail.policy.version}${dirty ? " · draft in progress" : ""}`}
        crumbs={[{ href: "/governance", label: "Governance" }]}
      />

      {/* Publishing applies to every FUTURE run of every agent on this policy. */}
      <div className="blast-radius">
        Publishing affects future runs of all {detail.agents_using}{" "}
        {detail.agents_using === 1 ? "agent" : "agents"} on this policy. Runs already in flight
        keep the version they started with, and every version stays in the history below.
      </div>

      {err && (
        <div className="err" role="alert">
          {err}
        </div>
      )}

      {dirty && (
        <div className="panel pad" role="region" aria-label="Publish this draft">
          <div className="sectitle" style={{ marginTop: 0 }}>
            Unpublished draft
          </div>
          {previewError ? (
            <p className="err" style={{ marginBottom: 8 }}>
              The draft does not validate: {previewError}
            </p>
          ) : (
            <p className="helper" style={{ marginBottom: 8 }}>
              Nothing is saved yet. Publishing mints v{detail.policy.version + 1} — one immutable
              version carrying your summary.
            </p>
          )}
          <div className="spread" style={{ gap: 10, alignItems: "center" }}>
            <input
              className="inp"
              style={{ flex: 1 }}
              value={summary}
              onChange={(event) => setSummary(event.target.value)}
              placeholder="What changed, and why? (required)"
              maxLength={500}
            />
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn"
                type="button"
                disabled={publishing}
                onClick={() => {
                  setDraft(structuredClone(detail.content));
                  setSummary("");
                }}
              >
                Discard draft
              </button>
              <button
                className="btn primary"
                type="button"
                disabled={publishing || !summary.trim() || !!previewError || (dirty && !preview)}
                onClick={() => void publish()}
              >
                {publishing ? "Publishing…" : `Publish v${detail.policy.version + 1}`}
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          Unattended runs
        </div>
        {!a ? (
          <p className="helper">Resolving the draft…</p>
        ) : a.permitted ? (
          <p className="note">
            Allowed. When an action needs approval, it is{" "}
            <strong>{a.default_fallback === "deny" ? "denied" : "allowed"}</strong> automatically.
            {contrary > 0 &&
              ` ${contrary} rule${contrary === 1 ? "" : "s"} ${contraryVerb} instead.`}
          </p>
        ) : (
          <p className="note">Not permitted by this policy.</p>
        )}
        <p className="helper">Change this under Limits &amp; autonomy below.</p>
      </div>

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          What agents may do
        </div>
        <p className="helper" style={{ marginBottom: 4 }}>
          Clicking an action writes a per-tool rule into the draft. Rules whose verdict depends on
          the path touched or the command run are edited in Rules below.
        </p>
        {!resolved ? (
          <LoadingRows rows={3} />
        ) : (
          <PermissionMatrix
            rows={resolved.matrix}
            tools={draft.tools}
            onSet={setTool}
            onClear={clearTool}
          />
        )}
      </div>

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          Rules
        </div>
        <p className="helper" style={{ marginBottom: 8 }}>
          Ordered — the first rule whose matcher hits the tool decides. Per-tool decisions from the
          matrix appear here as exact-name rules.
        </p>
        <PolicyRulesEditor
          rules={draft.tools}
          knownTools={knownTools}
          onChange={(tools) => setDraft((current) => (current ? { ...current, tools } : current))}
        />
      </div>

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          Limits &amp; autonomy
        </div>
        <PolicyLimits content={draft} onChange={(next) => setDraft(next)} />
      </div>

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          History
        </div>
        <p className="helper" style={{ marginBottom: 8 }}>
          Every version is immutable — who published it, what they said changed, and the exact
          content. Revert publishes an old version forward as a new one.
        </p>
        <PolicyVersionHistory
          name={detail.policy.name}
          versions={detail.versions}
          headVersion={detail.policy.version}
          onReverted={() => void load()}
          onError={(message) => setErr(message)}
        />
      </div>
    </>
  );
}
