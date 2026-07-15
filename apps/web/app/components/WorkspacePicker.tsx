"use client";

// Workspace selection shared by New Run and the agent revision editor.
// Presentation only: it emits the `workspace` input JSON; all validation,
// clone-URL derivation, and credential handling live in the Rust API.

import { useCallback, useEffect, useRef, useState } from "react";
import {
  apiGet,
  apiPost,
  Connection,
  GithubAppRegistration,
  isGitConnection,
  Repo,
  WorkspaceSpec,
} from "../lib/api";
import {
  GITHUB_ACTION_LABEL,
  nextGithubAction,
  openVia,
  pickNewConnection,
} from "../lib/github-flows";

export interface WorkspaceDraft {
  mode: "default" | "scratch" | "local" | "git";
  path: string;
  connectionId: string; // "" = public clone URL (no credential)
  repository: string; // owner/name from the picker
  cloneUrl: string; // used when no connection is selected
  ref: string;
}

export const emptyDraft = (mode: WorkspaceDraft["mode"]): WorkspaceDraft => ({
  mode,
  path: "",
  connectionId: "",
  repository: "",
  cloneUrl: "",
  ref: "",
});

/** Seed a draft from a stored spec (for editing an agent's default). */
export function specToDraft(ws: WorkspaceSpec | null | undefined): WorkspaceDraft {
  if (!ws || ws.kind === "scratch" || ws.kind === "none") return emptyDraft("scratch");
  if (ws.kind === "local_copy" || ws.kind === "local_path")
    return { ...emptyDraft("local"), path: ws.path || "" };
  return {
    ...emptyDraft("git"),
    connectionId: ws.connection_id || "",
    repository: ws.repository || "",
    cloneUrl: ws.clone_url || "",
    ref: ws.ref || "",
  };
}

/** undefined = omit the field (server resolves the agent default). */
export function draftToInput(d: WorkspaceDraft): unknown | undefined {
  switch (d.mode) {
    case "default":
      return undefined;
    case "scratch":
      return { kind: "scratch" };
    case "local":
      return { kind: "local_copy", path: d.path.trim() };
    case "git": {
      const ws: Record<string, unknown> = { kind: "git_repository" };
      if (d.connectionId) {
        ws.connection_id = d.connectionId;
        ws.repository = d.repository;
      } else {
        ws.clone_url = d.cloneUrl.trim();
      }
      if (d.ref.trim()) ws.ref = d.ref.trim();
      return ws;
    }
  }
}

export function WorkspacePicker({
  draft,
  onChange,
  defaultOptionLabel,
}: {
  draft: WorkspaceDraft;
  onChange: (d: WorkspaceDraft) => void;
  /** When set, offers a "use agent default" mode with this label. */
  defaultOptionLabel?: string;
}) {
  const [connections, setConnections] = useState<Connection[]>([]);
  const [registrations, setRegistrations] = useState<GithubAppRegistration[]>([]);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [repoErr, setRepoErr] = useState("");
  const [repoFilter, setRepoFilter] = useState("");
  const [flowErr, setFlowErr] = useState("");
  const [org, setOrg] = useState("");
  // Ids seen before a GitHub round-trip, so we can spot what it produced.
  const beforeIds = useRef<string[] | null>(null);

  // The refocus handler must see the CURRENT draft without re-subscribing the
  // listener on every keystroke.
  const onChangeRef = useRef(onChange);
  const draftRef = useRef(draft);
  useEffect(() => {
    onChangeRef.current = onChange;
    draftRef.current = draft;
  });

  const load = useCallback(async () => {
    const [c, r] = await Promise.allSettled([
      apiGet<{ connections: Connection[] }>("/connections"),
      apiGet<{ registrations: GithubAppRegistration[] }>("/github/app"),
    ]);
    if (r.status === "fulfilled") setRegistrations(r.value.registrations);
    if (c.status !== "fulfilled") return;
    // isGitConnection, not `!== "mcp_http"`: this list feeds a git checkout,
    // so a provider stays out until it is deliberately classified as git.
    const git = c.value.connections.filter((x) => x.status === "active" && isGitConnection(x));
    setConnections(git);

    // Returning from a GitHub tab: adopt what the dance produced. The modal
    // kept the task text and agent choice in RunComposer state throughout.
    const before = beforeIds.current;
    if (!before) return;
    beforeIds.current = null;
    const picked = pickNewConnection(before, git);
    if (picked && !draftRef.current.connectionId) {
      onChangeRef.current({ ...draftRef.current, connectionId: picked, repository: "" });
    }
  }, []);

  useEffect(() => {
    // Deferred, not called inline: setState synchronously inside an effect
    // cascades renders. Same shape as integrations/page.tsx.
    const first = window.setTimeout(() => void load(), 0);
    // The GitHub dances happen in another tab; refocus is our only signal
    // that they finished.
    window.addEventListener("focus", load);
    return () => {
      clearTimeout(first);
      window.removeEventListener("focus", load);
    };
  }, [load]);

  useEffect(() => {
    const refresh = window.setTimeout(() => {
      setRepos([]);
      setRepoErr("");
      if (draft.mode !== "git" || !draft.connectionId) return;
      apiGet<{ repos: Repo[] }>(`/connections/${draft.connectionId}/repos?per_page=100`)
        .then((r) => setRepos(r.repos))
        .catch((e) => setRepoErr(String(e)));
    }, 0);
    return () => clearTimeout(refresh);
  }, [draft.mode, draft.connectionId]);

  const set = (patch: Partial<WorkspaceDraft>) => onChange({ ...draft, ...patch });

  const action = nextGithubAction(registrations, connections);

  // Open the tab synchronously (popup blockers eat a late window.open), and
  // remember what we had so the refocus handler can spot what appeared.
  const runGithubAction = () => {
    setFlowErr("");
    beforeIds.current = connections.map((c) => c.id);
    void openVia(async () => {
      if (action.kind === "create") {
        const r = await apiPost<{ go_url: string }>("/github/app/manifest/start", {
          organization: org.trim() || null,
        });
        return r.go_url;
      }
      const r = await apiPost<{ go_url: string }>(`/github/app/${action.regId}/install/start`, {});
      return r.go_url;
    }).catch((e) => {
      beforeIds.current = null;
      setFlowErr(String(e));
    });
  };

  const modes: { value: WorkspaceDraft["mode"]; label: string }[] = [
    ...(defaultOptionLabel
      ? [{ value: "default" as const, label: defaultOptionLabel }]
      : []),
    { value: "scratch", label: "Scratch" },
    { value: "local", label: "Local path" },
    { value: "git", label: "Git repository" },
  ];

  return (
    <>
      <div className="field">
        <span className="lab">Workspace</span>
        <div className="seg">
          {modes.map((m) => (
            <button
              key={m.value}
              type="button"
              className={draft.mode === m.value ? "on" : ""}
              onClick={() => set({ mode: m.value })}
            >
              {m.label}
            </button>
          ))}
        </div>
        {draft.mode === "scratch" && (
          <p className="helper" style={{ margin: "6px 0 0" }}>
            An empty sandbox — nothing is mounted.
          </p>
        )}
      </div>

      {draft.mode === "local" && (
        <label className="field">
          <span className="lab">Local path</span>
          <input
            className="inp"
            placeholder="/absolute/path/to/repo"
            value={draft.path}
            onChange={(e) => set({ path: e.target.value })}
          />
        </label>
      )}

      {draft.mode === "git" && (
        <>
          <div className="field">
            <div className="bundle-picker-head">
              <span className="lab">Connection</span>
              <button className="btn ghost sm" type="button" onClick={runGithubAction}>
                + {GITHUB_ACTION_LABEL[action.kind]}
              </button>
            </div>
            {action.kind === "create" && (
              <input
                className="inp"
                style={{ marginBottom: 6 }}
                placeholder="GitHub organization (optional — blank installs on your account)"
                value={org}
                onChange={(e) => setOrg(e.target.value)}
              />
            )}
            {flowErr && <div className="err">{flowErr}</div>}
            <div className="opt-grid">
              {/* "Public repository" is a MODE, not an identity: it is the
                  absence of a connection. connectionId === "" still means
                  exactly that — WorkspaceDraft is unchanged. */}
              <button
                type="button"
                className={`opt ${draft.connectionId === "" ? "on" : ""}`}
                onClick={() => set({ connectionId: "", repository: "" })}
              >
                <span className="t">
                  Public repository
                  {draft.connectionId === "" && <span className="selected-label">Selected</span>}
                </span>
                <span className="id">no credential</span>
                <span className="d">Clone by URL. Public repositories only.</span>
              </button>
              {connections.map((c) => (
                <button
                  key={c.id}
                  type="button"
                  className={`opt ${draft.connectionId === c.id ? "on" : ""}`}
                  onClick={() => set({ connectionId: c.id, repository: "" })}
                >
                  <span className="t">
                    {c.display_name}
                    {draft.connectionId === c.id && <span className="selected-label">Selected</span>}
                  </span>
                  <span className="id">{c.provider}</span>
                  <span className="d">
                    {c.metadata?.account_login ? `→ ${c.metadata.account_login}` : " "}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {draft.connectionId ? (
            <div className="field">
              <span className="lab">Repository</span>
              {repoErr ? (
                <div className="err">{repoErr}</div>
              ) : repos.length === 0 ? (
                <span className="helper">
                  No repositories visible to this connection
                  {action.kind === "add_repos"
                    ? " — use “+ Add repositories” above to install the App somewhere."
                    : /* A legacy connection (registration_id === null) has no
                         registration to install into. Never synthesise one. */
                      " — manage this connection from Integrations."}
                </span>
              ) : (
                <>
                  {repos.length > 8 && (
                    <input
                      className="inp"
                      style={{ marginBottom: 6 }}
                      placeholder="Filter repositories…"
                      value={repoFilter}
                      onChange={(e) => setRepoFilter(e.target.value)}
                    />
                  )}
                  <div className="opt-list">
                    {repos
                      .filter((r) =>
                        r.full_name.toLowerCase().includes(repoFilter.trim().toLowerCase())
                      )
                      .map((r) => (
                        <button
                          key={r.id}
                          type="button"
                          className={`opt ${draft.repository === r.full_name ? "on" : ""}`}
                          onClick={() => set({ repository: r.full_name })}
                        >
                          <span className="t">
                            {r.full_name}
                            {draft.repository === r.full_name && (
                              <span className="selected-label">Selected</span>
                            )}
                          </span>
                          <span className="id">
                            {r.private ? "private" : "public"} · {r.default_branch}
                          </span>
                        </button>
                      ))}
                  </div>
                </>
              )}
            </div>
          ) : (
            <label className="field">
              <span className="lab">Clone URL</span>
              <input
                className="inp"
                placeholder="https://github.com/owner/repo.git"
                value={draft.cloneUrl}
                onChange={(e) => set({ cloneUrl: e.target.value })}
              />
            </label>
          )}

          <label className="field">
            <span className="lab">Ref (optional — branch or tag; blank = default branch)</span>
            <input
              className="inp"
              placeholder="main"
              value={draft.ref}
              onChange={(e) => set({ ref: e.target.value })}
            />
          </label>
          <p className="mut" style={{ fontSize: 12, marginTop: 0 }}>
            The control plane fetches the exact ref with the connection’s credential and mounts a
            copy into the sandbox — the credential never enters the sandbox and the remote is
            never modified by the run.
          </p>
        </>
      )}
    </>
  );
}
