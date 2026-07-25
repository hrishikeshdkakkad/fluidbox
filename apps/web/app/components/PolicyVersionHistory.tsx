"use client";

// Version history — the audit trail that replaced git review (design §3):
// every publish is an immutable version with an author, a summary, and a
// date. Viewing a version shows its YAML export and a line diff against the
// version BEFORE it; revert publishes the old content FORWARD as a new
// version (history is never rewritten). The diff renders two server-supplied
// exports side by side — presentation of text, never a re-derived verdict.

import { useCallback, useEffect, useState } from "react";
import { apiGet, apiPost, PolicyVersionDetail, PolicyVersionMeta } from "../lib/api";

/** Minimal LCS line diff: ' ' kept · '-' only in a · '+' only in b. */
function diffLines(a: string[], b: string[]): Array<{ kind: " " | "-" | "+"; line: string }> {
  const m = a.length;
  const n = b.length;
  // LCS table — version documents are small (hundreds of lines), so the
  // quadratic table is fine and exact.
  const lcs: number[][] = Array.from({ length: m + 1 }, () => new Array<number>(n + 1).fill(0));
  for (let i = m - 1; i >= 0; i--) {
    for (let j = n - 1; j >= 0; j--) {
      lcs[i][j] = a[i] === b[j] ? lcs[i + 1][j + 1] + 1 : Math.max(lcs[i + 1][j], lcs[i][j + 1]);
    }
  }
  const out: Array<{ kind: " " | "-" | "+"; line: string }> = [];
  let i = 0;
  let j = 0;
  while (i < m && j < n) {
    if (a[i] === b[j]) {
      out.push({ kind: " ", line: a[i] });
      i++;
      j++;
    } else if (lcs[i + 1][j] >= lcs[i][j + 1]) {
      out.push({ kind: "-", line: a[i] });
      i++;
    } else {
      out.push({ kind: "+", line: b[j] });
      j++;
    }
  }
  while (i < m) out.push({ kind: "-", line: a[i++] });
  while (j < n) out.push({ kind: "+", line: b[j++] });
  return out;
}

function authorLabel(v: PolicyVersionMeta): string {
  const channel =
    v.author === "seed"
      ? "boot seed"
      : v.author === "api"
        ? "YAML import"
        : v.author === "import"
          ? "migration"
          : "dashboard";
  return v.author_user_id ? `${channel} · user ${v.author_user_id.slice(0, 8)}…` : channel;
}

export function PolicyVersionHistory({
  name,
  versions,
  headVersion,
  onReverted,
  onError,
}: {
  name: string;
  versions: PolicyVersionMeta[];
  /** The current head — the optimistic base a revert must name. */
  headVersion: number;
  onReverted: () => void;
  onError: (message: string) => void;
}) {
  const [openVersion, setOpenVersion] = useState<number | null>(null);
  const [detail, setDetail] = useState<PolicyVersionDetail | null>(null);
  const [previous, setPrevious] = useState<PolicyVersionDetail | null>(null);
  const [showDiff, setShowDiff] = useState(true);
  const [busy, setBusy] = useState(false);

  const view = useCallback(
    async (version: number) => {
      setOpenVersion(version);
      setDetail(null);
      setPrevious(null);
      try {
        const encoded = encodeURIComponent(name);
        const current = await apiGet<PolicyVersionDetail>(
          `/policies/${encoded}/versions/${version}`
        );
        setDetail(current);
        if (version > 1) {
          setPrevious(
            await apiGet<PolicyVersionDetail>(`/policies/${encoded}/versions/${version - 1}`)
          );
        }
      } catch (reason) {
        onError(`Version ${version} could not be loaded. ${String(reason)}`);
        setOpenVersion(null);
      }
    },
    [name, onError]
  );

  // A publish/revert elsewhere on the page invalidates an open view.
  useEffect(() => {
    setOpenVersion(null);
    setDetail(null);
    setPrevious(null);
  }, [headVersion]);

  const revert = async (version: number) => {
    if (
      !window.confirm(
        `Revert '${name}' to v${version}? The current v${headVersion} stays in history; ` +
          `the old content is published forward as v${headVersion + 1}.`
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      await apiPost(`/policies/${encodeURIComponent(name)}/revert`, {
        version,
        base_version: headVersion,
      });
      onReverted();
    } catch (reason) {
      onError(`Revert failed. ${String(reason)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div className="rows">
        {versions.map((v) => (
          <div key={v.version} className="row" style={{ gridTemplateColumns: "84px 1fr auto" }}>
            <span className="chip">
              v<b>{v.version}</b>
              {v.version === headVersion && (
                <span className="badge ok" style={{ marginLeft: 6 }}>
                  current
                </span>
              )}
            </span>
            <span>
              <span className="task">{v.summary || "—"}</span>
              <span className="faint" style={{ display: "block", fontSize: 11 }}>
                {authorLabel(v)} · {new Date(v.created_at).toLocaleString()}
              </span>
            </span>
            <span style={{ display: "flex", gap: 6 }}>
              <button
                type="button"
                className="btn sm"
                onClick={() => (openVersion === v.version ? setOpenVersion(null) : void view(v.version))}
              >
                {openVersion === v.version ? "Close" : "View"}
              </button>
              {v.version !== headVersion && (
                <button
                  type="button"
                  className="btn sm"
                  disabled={busy}
                  onClick={() => void revert(v.version)}
                >
                  Revert to this
                </button>
              )}
            </span>
          </div>
        ))}
      </div>

      {openVersion !== null && (
        <div className="panel pad" style={{ marginTop: 10 }}>
          {!detail ? (
            <span className="helper">Loading v{openVersion}…</span>
          ) : (
            <>
              <div className="spread" style={{ alignItems: "center" }}>
                <div className="sectitle" style={{ margin: 0 }}>
                  v{openVersion}
                  {previous && showDiff ? ` — changes since v${openVersion - 1}` : " — YAML export"}
                </div>
                {previous && (
                  <button type="button" className="btn sm" onClick={() => setShowDiff((s) => !s)}>
                    {showDiff ? "Show full YAML" : `Diff against v${openVersion - 1}`}
                  </button>
                )}
              </div>
              <pre className="mono" style={{ fontSize: 12, overflowX: "auto", marginTop: 8 }}>
                {previous && showDiff
                  ? diffLines(previous.yaml.split("\n"), detail.yaml.split("\n")).map(
                      (entry, i) => (
                        <span
                          key={i}
                          style={{
                            display: "block",
                            color:
                              entry.kind === "+"
                                ? "var(--green)"
                                : entry.kind === "-"
                                  ? "var(--red)"
                                  : undefined,
                            opacity: entry.kind === " " ? 0.65 : 1,
                          }}
                        >
                          {entry.kind} {entry.line}
                        </span>
                      )
                    )
                  : detail.yaml}
              </pre>
            </>
          )}
        </div>
      )}
    </>
  );
}
