// The GitHub App acquisition dances, as data. Pure functions live here rather
// than inside WorkspacePicker so they are testable without component-test
// infrastructure — the dashboard has none.

import { Connection, GithubAppRegistration, isGitConnection } from "./api";

export type GithubAction =
  | { kind: "create" }
  | { kind: "install"; regId: string }
  | { kind: "add_repos"; regId: string };

/** What the git picker's "+ new" means right now.
 *
 *  Three states wearing one button:
 *    no active registration       → create an App (the manifest dance)
 *    registration, no install     → install it
 *    registration + installation  → install on more repositories
 *
 *  Legacy connections (registration_id === null) custody their own credential
 *  and have NO registration to install into, so they never satisfy the
 *  add_repos branch. Never synthesise a registration id: custody resolution
 *  fails closed by design. */
export function nextGithubAction(
  registrations: GithubAppRegistration[],
  connections: Connection[]
): GithubAction {
  const active = registrations.find((r) => r.status === "active");
  if (!active) return { kind: "create" };
  const installed = connections.some(
    (c) => c.registration_id === active.id && c.status === "active"
  );
  return installed ? { kind: "add_repos", regId: active.id } : { kind: "install", regId: active.id };
}

export const GITHUB_ACTION_LABEL: Record<GithubAction["kind"], string> = {
  create: "New GitHub App",
  install: "Install GitHub App",
  add_repos: "Add repositories",
};

/** After a GitHub round-trip: which connection should we auto-select?
 *
 *  Exactly one new active git connection → select it. Several → select none
 *  and let the user choose: guessing would silently bind the wrong repo host
 *  to a run whose task text is already typed. */
export function pickNewConnection(before: string[], after: Connection[]): string | null {
  const seen = new Set(before);
  const fresh = after.filter((c) => isGitConnection(c) && c.status === "active" && !seen.has(c.id));
  return fresh.length === 1 ? fresh[0].id : null;
}

/** Open a tab for a URL the API has not returned yet.
 *
 *  The tab MUST open synchronously inside the click handler: awaiting first
 *  voids the user gesture and popup blockers eat the late window.open. Lifted
 *  from integrations/page.tsx so both callers share one implementation.
 *  Rejects on failure — callers wrap this in their own error handling. */
export function openVia(getUrl: () => Promise<string>): Promise<void> {
  const tab = window.open("", "_blank");
  return getUrl().then(
    (url) => {
      if (tab) tab.location.href = url;
      else window.location.href = url;
    },
    (e) => {
      tab?.close();
      throw e;
    }
  );
}
