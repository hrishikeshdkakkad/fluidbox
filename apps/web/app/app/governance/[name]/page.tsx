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
import { useRouter } from "next/navigation";
import {
  apiDelete,
  apiGet,
  apiPost,
  MatrixRow,
  PolicyAction,
  PolicyContent,
  PolicyDetail,
  PolicyPreview,
} from "../../../lib/api";
import { LoadingRows, PageHead } from "../../../components/bits";
import { isExactHeadRule, PermissionMatrix } from "../../../components/PermissionMatrix";
import { PolicyLimits } from "../../../components/PolicyLimits";
import { PolicyRulesEditor } from "../../../components/PolicyRulesEditor";
import { PolicyVersionHistory } from "../../../components/PolicyVersionHistory";

/** The resolved payload both sources share: the detail (clean) or the preview
 *  (dirty draft). One shape so every section renders from one place.
 *
 *  `stale` means these verdicts belong to an EARLIER draft — a preview is in
 *  flight, or the current draft does not validate. They are still shown: an
 *  editor that blanks its resolved matrix on every keystroke (and reports an
 *  INVALID draft as "loading") is worse than one that shows a slightly-behind
 *  answer and says so. The controls go inert while stale, because the rule
 *  indices in these rows address the draft the server resolved, not the one
 *  being held now.
 *
 *  How far behind is NOT bounded to one edit: it is the last draft that
 *  RESOLVED, which after a run of invalid edits can be several back. The copy
 *  says exactly that rather than promising a number. */
interface Resolved {
  matrix: MatrixRow[];
  autonomy_summary: PolicyDetail["autonomy_summary"];
  stale: boolean;
}

export default function PolicyDetailPage({ params }: { params: Promise<{ name: string }> }) {
  const { name } = use(params);
  const encoded = encodeURIComponent(name);
  const router = useRouter();
  const [detail, setDetail] = useState<PolicyDetail | null>(null);
  const [draft, setDraft] = useState<PolicyContent | null>(null);
  // The preview is stored WITH the fingerprint of the draft it resolved. A
  // MISMATCH no longer discards it — the rows stay on screen marked stale, see
  // `Resolved` — but it is never treated as CURRENT, which is what keeps a
  // lagging response from arming the publish button or letting a click act on
  // rule indices that address a draft the user has since edited.
  const [preview, setPreview] = useState<{ forDraft: string; data: PolicyPreview } | null>(null);
  // The error carries the DRAFT it belongs to. Without that, an error from an
  // earlier draft kept being reported against the current one — so a draft the
  // user had already FIXED still read "does not validate" until the next
  // response landed, and the publish button stayed disabled on a stale reason.
  const [previewError, setPreviewError] = useState<{ forDraft: string; message: string } | null>(
    null
  );
  // Bumped whenever the draft is replaced from OUTSIDE the editors (load,
  // discard, revert). Editors that hold uncommitted local state — a half-typed
  // matcher, a half-typed number — are keyed on it, so such a replacement
  // remounts them instead of silently re-pointing that state at a different
  // rule or field. Length-based heuristics cannot see a same-length swap.
  const [formEpoch, setFormEpoch] = useState(0);
  const [summary, setSummary] = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);
  const [publishing, setPublishing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const previewSeq = useRef(0);

  const load = useCallback(async () => {
    setErr("");
    try {
      const next = await apiGet<PolicyDetail>(`/policies/${encoded}`);
      setDetail(next);
      setDraft(structuredClone(next.content));
      setPreview(null);
      setPreviewError(null);
      setSummary("");
      setFormEpoch((n) => n + 1);
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
      setPreviewError(null);
      return;
    }
    const seq = ++previewSeq.current;
    const forDraft = JSON.stringify(draft);
    const timer = window.setTimeout(() => {
      apiPost<PolicyPreview>("/policies/preview", { content: draft, name })
        .then((resolved) => {
          if (previewSeq.current !== seq) return;
          setPreview({ forDraft, data: resolved });
          setPreviewError(null);
        })
        .catch((reason) => {
          if (previewSeq.current !== seq) return;
          // Deliberately NOT `setPreview(null)`: a refused draft is a reason to
          // say so, not to throw away the verdicts we already resolved. Keeping
          // the last good preview leaves the matrix one edit behind (marked
          // stale) instead of collapsing the page — which matters because the
          // most ordinary way to reach this state is clicking "Add rule",
          // whose empty matcher list is refused until you fill it in.
          setPreviewError({ forDraft, message: String(reason).replace(/^Error:\s*/, "") });
        });
    }, 350);
    return () => window.clearTimeout(timer);
  }, [dirty, draft, name]);

  const fingerprint = useMemo(() => JSON.stringify(draft), [draft]);
  const draftError = previewError?.forDraft === fingerprint ? previewError.message : "";

  const resolved: Resolved | null = useMemo(() => {
    const clean = detail
      ? { matrix: detail.matrix, autonomy_summary: detail.autonomy_summary, stale: false }
      : null;
    if (!dirty) return clean;
    // A preview that resolved EXACTLY this draft is current; anything else —
    // a lagging response, a refused draft, no preview yet — falls back to the
    // last answer we have, marked stale. That fallback is the last draft that
    // RESOLVED, which is not necessarily the previous keystroke: a run of
    // invalid edits leaves it further back. Hence "the last draft that
    // resolved" in the copy, not "one edit behind".
    if (preview) {
      const current = preview.forDraft === fingerprint;
      return {
        matrix: preview.data.matrix,
        autonomy_summary: preview.data.autonomy_summary,
        stale: !current,
      };
    }
    return clean && { ...clean, stale: true };
  }, [detail, dirty, fingerprint, preview]);

  // The matrix edits the DRAFT: an exact-name head rule per decided tool. The
  // WINNING rule index comes from the server-resolved row — the page checks
  // only the STRUCTURE of the rule at that index, never a verdict.
  const setTool = (tool: string, action: PolicyAction) => {
    // `resolved.stale` rows carry rule indices for a draft the user has since
    // edited; the matrix disables its controls then, and this is the guard
    // behind that (never trust the view to be the only gate).
    if (!draft || !resolved || resolved.stale) return;
    const row = resolved.matrix.find((r) => r.tool === tool);
    // …and the SAME guard again inside the updater, against the draft React
    // actually applies it to. `resolved.stale` was read when this handler was
    // created; a `load()` landing between that render and this click would
    // rebase the edit onto a different draft, where the same rule index can
    // name a different — or shadowed — rule. Comparing fingerprints turns that
    // into a no-op instead of an edit to a rule nobody was looking at.
    setDraft((current) => {
      if (!current || JSON.stringify(current) !== fingerprint) return current;
      const tools = [...current.tools];
      const idx = row && row.status.status === "unconditional" ? row.status.rule : null;
      if (idx != null && isExactHeadRule(tools[idx], tool)) {
        tools[idx] = { ...tools[idx], action };
      } else {
        tools.unshift({ match: [tool], action });
      }
      return { ...current, tools };
    });
  };

  const clearTool = (tool: string) => {
    if (!draft || !resolved || resolved.stale) return;
    const row = resolved.matrix.find((r) => r.tool === tool);
    if (!row || row.status.status !== "unconditional") return;
    const idx = row.status.rule;
    setDraft((current) => {
      if (!current || JSON.stringify(current) !== fingerprint) return current;
      if (!isExactHeadRule(current.tools[idx], tool)) return current;
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

  const remove = async () => {
    if (!detail) return;
    if (
      !window.confirm(
        `Delete policy '${detail.policy.name}' and all ${detail.versions.length} of its versions? ` +
          `This cannot be undone. Runs keep the snapshot they froze.`
      )
    ) {
      return;
    }
    setDeleting(true);
    setErr("");
    try {
      await apiDelete(`/policies/${encoded}`);
      router.push("/app/governance");
    } catch (reason) {
      setErr(String(reason).replace(/^Error:\s*/, ""));
      setDeleting(false);
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
          {draftError ? (
            <p className="err" style={{ marginBottom: 8 }}>
              The draft does not validate: {draftError}
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
                  setFormEpoch((n) => n + 1);
                }}
              >
                Discard draft
              </button>
              <button
                className="btn primary"
                type="button"
                disabled={
                  publishing || !summary.trim() || !!draftError || !resolved || resolved.stale
                }
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
        {resolved?.stale && (
          <p className={draftError ? "err" : "helper"} style={{ marginBottom: 8 }} role="status">
            {draftError
              ? "From your last valid draft — the current one does not validate."
              : "Resolving your latest edit…"}
          </p>
        )}
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
        {resolved && resolved.stale && (
          <p className={draftError ? "err" : "helper"} style={{ marginBottom: 8 }} role="status">
            {draftError
              ? `These verdicts are from the last draft that resolved — the current one is not valid, so it could not be: ${draftError}`
              : "Resolving your latest edit — these verdicts are from the last draft that resolved."}
          </p>
        )}
        {!resolved ? (
          <LoadingRows rows={3} />
        ) : (
          <PermissionMatrix
            rows={resolved.matrix}
            tools={draft.tools}
            stale={resolved.stale}
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
          key={formEpoch}
          rules={draft.tools}
          knownTools={knownTools}
          onChange={(tools) => setDraft((current) => (current ? { ...current, tools } : current))}
        />
      </div>

      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          Limits &amp; autonomy
        </div>
        <PolicyLimits key={formEpoch} content={draft} onChange={(next) => setDraft(next)} />
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

      {/* The counterpart to New policy. Deliberately NOT pre-disabled on
          `agents_using`: that counts agents whose LATEST revision uses this
          policy, while the server refuses on ANY revision (revisions are
          immutable and must keep resolving theirs). Guessing the answer here
          would either forbid a legal delete or promise an illegal one — so the
          button asks, and the server's refusal is what gets shown. */}
      <div className="panel pad">
        <div className="sectitle" style={{ marginTop: 0 }}>
          Delete this policy
        </div>
        <p className="helper" style={{ marginBottom: 8 }}>
          Removes the policy and its entire version history. Runs already finished or in flight are
          unaffected — each froze its own copy. Any agent revision still naming this policy blocks
          the delete.
        </p>
        <button
          className="btn danger"
          type="button"
          disabled={deleting}
          onClick={() => void remove()}
        >
          {deleting ? "Deleting…" : `Delete '${detail.policy.name}'`}
        </button>
      </div>
    </>
  );
}
