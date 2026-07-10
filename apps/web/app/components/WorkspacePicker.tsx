"use client";

// Workspace selection shared by New Run and the agent revision editor.
// Presentation only: it emits the `workspace` input JSON; all validation,
// clone-URL derivation, and credential handling live in the Rust API.

import { useEffect, useState } from "react";
import { apiGet, Connection, Repo, WorkspaceSpec } from "../lib/api";

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
  const [repos, setRepos] = useState<Repo[]>([]);
  const [repoErr, setRepoErr] = useState("");

  useEffect(() => {
    apiGet<{ connections: Connection[] }>("/connections")
      .then((r) => setConnections(r.connections.filter((c) => c.status === "active")))
      .catch(() => {});
  }, []);

  useEffect(() => {
    setRepos([]);
    setRepoErr("");
    if (draft.mode !== "git" || !draft.connectionId) return;
    apiGet<{ repos: Repo[] }>(`/connections/${draft.connectionId}/repos?per_page=100`)
      .then((r) => setRepos(r.repos))
      .catch((e) => setRepoErr(String(e)));
  }, [draft.mode, draft.connectionId]);

  const set = (patch: Partial<WorkspaceDraft>) => onChange({ ...draft, ...patch });

  return (
    <>
      <label className="field">
        <span className="lab">Workspace</span>
        <select
          className="inp"
          value={draft.mode}
          onChange={(e) => set({ mode: e.target.value as WorkspaceDraft["mode"] })}
        >
          {defaultOptionLabel && <option value="default">{defaultOptionLabel}</option>}
          <option value="scratch">scratch (empty sandbox)</option>
          <option value="local">local path (copied)</option>
          <option value="git">git repository (cloned control-plane-side)</option>
        </select>
      </label>

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
          <label className="field">
            <span className="lab">Connection</span>
            <select
              className="inp"
              value={draft.connectionId}
              onChange={(e) => set({ connectionId: e.target.value, repository: "" })}
            >
              <option value="">public URL (no credential)</option>
              {connections.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.provider} · {c.display_name}
                </option>
              ))}
            </select>
          </label>

          {draft.connectionId ? (
            <label className="field">
              <span className="lab">Repository</span>
              {repoErr ? (
                <div className="err">{repoErr}</div>
              ) : (
                <select
                  className="inp"
                  value={draft.repository}
                  onChange={(e) => set({ repository: e.target.value })}
                >
                  <option value="">— select a repository —</option>
                  {repos.map((r) => (
                    <option key={r.id} value={r.full_name}>
                      {r.full_name}
                      {r.private ? " (private)" : ""}
                    </option>
                  ))}
                </select>
              )}
            </label>
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
