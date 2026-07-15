# Run-composer pickers Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stop the Configure Run workspace step offering MCP tool credentials as git checkout sources, and give its pickers one card vocabulary with a working `+ new`.

**Architecture:** The provider rule moves from copy-pasted comments into a single `Record<ConnectionProvider, "git" | "tool">` in `lib/api.ts` — adding a provider without classifying it becomes a **compile error**. Picker logic (the `+ new` state machine, the post-round-trip diff) is extracted as **pure functions** in `lib/github-flows.ts` so it is unit-testable without component-test infrastructure. Presentation converges on the `.opt` card the model picker already uses.

**Tech Stack:** Next.js 16.2.10, React 19.2.7, TypeScript 6.0.3 (strict), vitest (new), pnpm 10.30.1.

Design doc: `docs/plans/2026-07-15-run-composer-pickers-design.md`.

## Global Constraints

- **`apps/web` is presentation-only.** No Rust, no migrations, no API changes, no `RunSpec`/gate/custody changes. If a task seems to need one, stop and escalate.
- **Read the docs before Next-specific code.** `apps/web/AGENTS.md`: *"This is NOT the Next.js you know… Read the relevant guide in `node_modules/next/dist/docs/` before writing any code."* Applies to Next APIs, not to vitest config or pure functions.
- **`WorkspaceDraft` and `draftToInput` are frozen.** The emitted workspace JSON must stay byte-for-byte identical. `connectionId: ""` still means "public clone URL".
- **Never synthesise a `registration_id`.** Legacy connections (`registration_id === null`) have no registration; custody resolution fails closed by design.
- **Allowlist, never denylist.** No new `provider !== "mcp_http"` checks. Phase 7 (Slack) is why.
- `just check` must pass at every commit: `cargo fmt` + `clippy -D warnings` + `cargo test` + `pnpm test` + `pnpm build`.
- Branch: `claude/run-composer-pickers` (already created, off `origin/main`). Do not commit to `main` — it is PR-only via ruleset.

---

### Task 1: The provider classification, and the test runner it needs

Fixes the rule. Task 2 applies it. `apps/web` has **no test runner today** — this task adds one, because its deliverable needs it.

**Files:**
- Modify: `apps/web/package.json` (add devDep + `test` script)
- Create: `apps/web/vitest.config.ts`
- Modify: `apps/web/app/lib/api.ts:152` (the `provider` comment) and after `:181` (the `Connection` interface)
- Create: `apps/web/app/lib/api.test.ts`
- Modify: `justfile:73-74` (the `check` target)

**Interfaces:**
- Consumes: nothing.
- Produces: `type ConnectionProvider = "github" | "github_app" | "mcp_http"`; `isGitConnection(c: Connection): boolean`; `isToolConnection(c: Connection): boolean`. Tasks 2, 3, 4 and 7 import these from `./api` / `../lib/api`.

- [ ] **Step 1: Install vitest**

```bash
cd apps/web && pnpm add -D vitest
```

Expected: `dependencies` untouched; `devDependencies` gains `vitest`. If this errors with `EACCES` on `~/.npm/_cacache`, run it in a normal shell — a sandbox blocks that write, the directory itself is fine.

- [ ] **Step 2: Add the vitest config**

Create `apps/web/vitest.config.ts`:

```ts
import { defineConfig } from "vitest/config";

// Pure-logic tests only. The dashboard has no component-test infrastructure
// (no @testing-library), which is why picker logic lives in lib/ as pure
// functions rather than inline in components.
export default defineConfig({
  test: {
    environment: "node",
    include: ["app/**/*.test.ts"],
  },
});
```

- [ ] **Step 3: Add the test script**

In `apps/web/package.json`, add to `"scripts"` (after `"lint"`):

```json
    "test": "vitest run"
```

- [ ] **Step 4: Write the failing test**

Create `apps/web/app/lib/api.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { Connection, isGitConnection, isToolConnection } from "./api";

// Only `provider` is read by the predicates; the rest of Connection is noise.
const conn = (provider: string): Connection => ({ provider }) as Connection;

describe("connection provider classification", () => {
  it("routes both github providers to the git surface", () => {
    expect(isGitConnection(conn("github"))).toBe(true);
    expect(isGitConnection(conn("github_app"))).toBe(true);
    expect(isToolConnection(conn("github"))).toBe(false);
    expect(isToolConnection(conn("github_app"))).toBe(false);
  });

  it("routes mcp_http to the tool surface, never the git one", () => {
    expect(isToolConnection(conn("mcp_http"))).toBe(true);
    // The reported bug: `mcp_http · Cloudflare` was offered as a source for a
    // git checkout. The broker calls that server; it has no repositories.
    expect(isGitConnection(conn("mcp_http"))).toBe(false);
  });

  it("keeps an unclassified provider out of BOTH surfaces", () => {
    // Phase 7 lands `slack` on the server before this client knows the word.
    // The old `provider !== "mcp_http"` form would have admitted it straight
    // into the repo picker. An allowlist fails safe instead.
    expect(isGitConnection(conn("slack"))).toBe(false);
    expect(isToolConnection(conn("slack"))).toBe(false);
  });
});
```

- [ ] **Step 5: Run the test to verify it fails**

Run: `cd apps/web && pnpm test`
Expected: FAIL — `No "isGitConnection" export is defined on the "./api" module`.

- [ ] **Step 6: Implement the classification**

In `apps/web/app/lib/api.ts`, change the `provider` field comment (currently line 152, inside `export interface Connection`) from:

```ts
  provider: string; // github (PAT) | github_app | mcp_http
```

to:

```ts
  /** Wire value, server-controlled. See ConnectionProvider for the ones this
   *  client has classified; unknown values fail safe (neither git nor tool). */
  provider: string;
```

Then add immediately **after** the closing `}` of `export interface Connection` (currently line 181):

```ts
/** Every connection provider this dashboard has classified. The server is the
 *  source of truth for what exists; this union states what we have decided
 *  about. Adding a member without adding it to PROVIDER_CLASS is a build
 *  failure — that is the point. */
export type ConnectionProvider = "github" | "github_app" | "mcp_http";

/** Which surface a provider belongs to.
 *
 *    git  — can back a workspace checkout (repositories, refs, commits).
 *    tool — a credential the BROKER calls during a run. It has no repositories.
 *
 *  This Record is the only place the rule lives. It replaces four hand-rolled
 *  predicates that each re-derived it from a prose comment; WorkspacePicker
 *  forgot, which is how mcp_http reached the git picker.
 *
 *  It is an allowlist BY CONSTRUCTION: Record<ConnectionProvider, …> requires
 *  every union member as a key, so adding `slack` (Phase 7) fails the build
 *  until someone classifies it. The old `provider !== "mcp_http"` form would
 *  have silently admitted slack to the repo picker instead. */
const PROVIDER_CLASS: Record<ConnectionProvider, "git" | "tool"> = {
  github: "git",
  github_app: "git",
  mcp_http: "tool",
};

/** Can this connection back a git workspace checkout?
 *
 *  A provider the server knows but this client does not is neither git nor
 *  tool: it stays out of every picker rather than defaulting into one. */
export const isGitConnection = (c: Connection): boolean =>
  PROVIDER_CLASS[c.provider as ConnectionProvider] === "git";

/** Is this a brokered tool-server credential? The mirror of isGitConnection. */
export const isToolConnection = (c: Connection): boolean =>
  PROVIDER_CLASS[c.provider as ConnectionProvider] === "tool";
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd apps/web && pnpm test`
Expected: PASS — 3 passed.

- [ ] **Step 8: Wire the runner into `just check`**

In `justfile`, replace the `check` target (lines 73-74):

```make
check: fmt lint test
    cd apps/web && pnpm build
```

with:

```make
check: fmt lint test
    cd apps/web && pnpm test
    cd apps/web && pnpm build
```

- [ ] **Step 9: Verify the whole bar passes**

Run: `just check`
Expected: PASS throughout, including the new `pnpm test` line.

- [ ] **Step 10: Commit**

```bash
git add apps/web/package.json apps/web/pnpm-lock.yaml apps/web/vitest.config.ts \
        apps/web/app/lib/api.ts apps/web/app/lib/api.test.ts justfile
git commit -m "feat(web): classify connection providers by allowlist, add vitest

The integrations/capabilities rule lived in prose comments re-derived at four
call sites. One Record keyed by ConnectionProvider makes adding a provider
without classifying it a compile error — Phase 7's slack cannot silently
reach the git picker.

First test infrastructure in apps/web; wired into just check."
```

---

### Task 2: Stop the leak

The reported bug. One predicate at one call site. Shippable alone.

**Files:**
- Modify: `apps/web/app/components/WorkspacePicker.tsx:8` (import), `:79-83` (the fetch)

**Interfaces:**
- Consumes: `isGitConnection` from Task 1.
- Produces: nothing new.

- [ ] **Step 1: Import the predicate**

In `apps/web/app/components/WorkspacePicker.tsx`, change line 8 from:

```ts
import { apiGet, Connection, Repo, WorkspaceSpec } from "../lib/api";
```

to:

```ts
import { apiGet, Connection, isGitConnection, Repo, WorkspaceSpec } from "../lib/api";
```

- [ ] **Step 2: Apply it**

Replace the effect at lines 79-83:

```ts
  useEffect(() => {
    apiGet<{ connections: Connection[] }>("/connections")
      .then((r) => setConnections(r.connections.filter((c) => c.status === "active")))
      .catch(() => {});
  }, []);
```

with:

```ts
  useEffect(() => {
    apiGet<{ connections: Connection[] }>("/connections")
      // isGitConnection, not `!== "mcp_http"`: this list feeds a git checkout,
      // so a provider stays out until it is deliberately classified as git.
      .then((r) =>
        setConnections(r.connections.filter((c) => c.status === "active" && isGitConnection(c)))
      )
      .catch(() => {});
  }, []);
```

- [ ] **Step 3: Verify the build**

Run: `just check`
Expected: PASS.

- [ ] **Step 4: Verify the bug is gone, by hand**

Run `just dev`. Open http://localhost:3000 → **New Run** → the **Workspace & tools** tab → **Git repository** → open the **Connection** dropdown.
Expected: `public URL (no credential)` and any `github_app · …` entries. **`mcp_http · Cloudflare` must NOT appear.**

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/components/WorkspacePicker.tsx
git commit -m "fix(web): stop offering MCP tool credentials as git checkout sources

WorkspacePicker filtered on status only, so every active connection reached
the git Connection dropdown — including mcp_http servers the broker calls,
which have no repositories."
```

---

### Task 3: Retire the hand-rolled predicates

Kills the latent Slack bug at the three sites that got it right by luck.

**Files:**
- Modify: `apps/web/app/integrations/page.tsx:111-113`
- Modify: `apps/web/app/capabilities/page.tsx:105-107`
- Modify: `apps/web/app/components/ResourceOverview.tsx:81-86`

**Interfaces:**
- Consumes: `isGitConnection`, `isToolConnection` from Task 1.
- Produces: nothing new.

`RunComposer.tsx:176` is deliberately **left alone**: event triggers need App identity to publish checks, so `provider === "github_app"` is narrower than "git" on purpose.

- [ ] **Step 1: Convert integrations**

In `apps/web/app/integrations/page.tsx`, add `isGitConnection` to the existing `../lib/api` import (line 9-16), then replace lines 109-113:

```ts
  // Git platform connections only — mcp_http tool credentials live on the
  // Capabilities page.
  const gitConnections = connections.filter(
    (c) => c.provider !== "mcp_http" && c.status !== "revoked"
  );
```

with:

```ts
  const gitConnections = connections.filter((c) => isGitConnection(c) && c.status !== "revoked");
```

- [ ] **Step 2: Convert capabilities**

In `apps/web/app/capabilities/page.tsx`, add `isToolConnection` to the existing `../lib/api` import, then replace lines 103-107:

```ts
  // Tool-server credentials only — git platform connections live on the
  // Integrations page.
  const toolConnections = connections.filter(
    (c) => c.provider === "mcp_http" && c.status !== "revoked"
  );
```

with:

```ts
  const toolConnections = connections.filter((c) => isToolConnection(c) && c.status !== "revoked");
```

- [ ] **Step 3: Convert ResourceOverview**

In `apps/web/app/components/ResourceOverview.tsx`, add `isGitConnection, isToolConnection` to the existing `../lib/api` import, then replace lines 81-86:

```ts
  const activeConnections = snapshot.connections.filter(
    (connection) => connection.status === "active" && connection.provider !== "mcp_http"
  );
  const activeToolConnections = snapshot.connections.filter(
    (connection) => connection.status === "active" && connection.provider === "mcp_http"
  );
```

with:

```ts
  const activeConnections = snapshot.connections.filter(
    (connection) => connection.status === "active" && isGitConnection(connection)
  );
  const activeToolConnections = snapshot.connections.filter(
    (connection) => connection.status === "active" && isToolConnection(connection)
  );
```

- [ ] **Step 4: Verify no denylist survives**

Run: `grep -rn 'provider !== "mcp_http"\|provider === "mcp_http"' apps/web/app`
Expected: **no output.** (`RunComposer.tsx:176`'s `provider === "github_app"` is intentional and does not match.)

- [ ] **Step 5: Verify the build**

Run: `just check`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add apps/web/app/integrations/page.tsx apps/web/app/capabilities/page.tsx \
        apps/web/app/components/ResourceOverview.tsx
git commit -m "refactor(web): route every connection list through the shared predicate

These three sites got the rule right by luck: \`!== \"mcp_http\"\` admits
anything that is not MCP, so Phase 7's slack would have landed in the git
picker. The allowlist keeps it out until someone classifies it."
```

---

### Task 4: The `+ new` state machine and the round-trip diff (pure)

Pure functions, so vitest can test them without component-test infrastructure.

**Files:**
- Create: `apps/web/app/lib/github-flows.ts`
- Create: `apps/web/app/lib/github-flows.test.ts`

**Interfaces:**
- Consumes: `Connection`, `GithubAppRegistration`, `isGitConnection` from Task 1 / `./api`.
- Produces: `type GithubAction`; `nextGithubAction(registrations, connections): GithubAction`; `GITHUB_ACTION_LABEL: Record<GithubAction["kind"], string>`; `pickNewConnection(before: string[], after: Connection[]): string | null`. Task 7 imports all four.

- [ ] **Step 1: Write the failing test**

Create `apps/web/app/lib/github-flows.test.ts`:

```ts
import { describe, expect, it } from "vitest";
import { Connection, GithubAppRegistration } from "./api";
import { nextGithubAction, pickNewConnection } from "./github-flows";

const reg = (id: string, status: string): GithubAppRegistration =>
  ({ id, status }) as GithubAppRegistration;

const conn = (
  id: string,
  provider: string,
  status: string,
  registration_id: string | null = null
): Connection => ({ id, provider, status, registration_id }) as Connection;

describe("nextGithubAction", () => {
  it("offers to create an App when no registration is active", () => {
    expect(nextGithubAction([], [])).toEqual({ kind: "create" });
    // A pending registration is not usable custody yet.
    expect(nextGithubAction([reg("r1", "pending")], [])).toEqual({ kind: "create" });
    expect(nextGithubAction([reg("r1", "revoked")], [])).toEqual({ kind: "create" });
  });

  it("offers to install when the App exists but is not installed", () => {
    expect(nextGithubAction([reg("r1", "active")], [])).toEqual({ kind: "install", regId: "r1" });
  });

  it("offers more repositories once an installation is live", () => {
    const conns = [conn("c1", "github_app", "active", "r1")];
    expect(nextGithubAction([reg("r1", "active")], conns)).toEqual({
      kind: "add_repos",
      regId: "r1",
    });
  });

  it("ignores a revoked connection when deciding install vs add_repos", () => {
    const conns = [conn("c1", "github_app", "revoked", "r1")];
    expect(nextGithubAction([reg("r1", "active")], conns)).toEqual({ kind: "install", regId: "r1" });
  });

  it("never attributes a LEGACY connection to a registration", () => {
    // registration_id === null means custody lives on the connection itself.
    // There is no registration to install into; never synthesise one.
    const legacy = [conn("c1", "github_app", "active", null)];
    expect(nextGithubAction([reg("r1", "active")], legacy)).toEqual({
      kind: "install",
      regId: "r1",
    });
  });
});

describe("pickNewConnection", () => {
  it("selects the single git connection that appeared", () => {
    const after = [conn("c1", "github_app", "active"), conn("c2", "github_app", "active")];
    expect(pickNewConnection(["c1"], after)).toBe("c2");
  });

  it("selects nothing when several appeared", () => {
    // Guessing would silently bind the wrong repo host to a run whose task
    // text is already typed. Make the user choose.
    const after = [conn("c1", "github_app", "active"), conn("c2", "github_app", "active")];
    expect(pickNewConnection([], after)).toBeNull();
  });

  it("selects nothing when nothing appeared", () => {
    expect(pickNewConnection(["c1"], [conn("c1", "github_app", "active")])).toBeNull();
  });

  it("ignores a new NON-git connection", () => {
    // Connecting an MCP server mid-flow must not hijack the repo picker.
    const after = [conn("c1", "github_app", "active"), conn("c2", "mcp_http", "active")];
    expect(pickNewConnection(["c1"], after)).toBeNull();
  });

  it("ignores a new git connection that is not yet active", () => {
    const after = [conn("c1", "github_app", "active"), conn("c2", "github_app", "pending")];
    expect(pickNewConnection(["c1"], after)).toBeNull();
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cd apps/web && pnpm test`
Expected: FAIL — `Failed to resolve import "./github-flows"`.

- [ ] **Step 3: Implement the pure logic**

Create `apps/web/app/lib/github-flows.ts`:

```ts
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
  const fresh = after.filter(
    (c) => isGitConnection(c) && c.status === "active" && !seen.has(c.id)
  );
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd apps/web && pnpm test`
Expected: PASS — 3 (api) + 10 (github-flows) = 13 passed.

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/lib/github-flows.ts apps/web/app/lib/github-flows.test.ts
git commit -m "feat(web): model the GitHub App + new flow as pure, tested functions

\"Repo should have a github app, or create and install new\" is three states,
not one button. Extracted as pure functions so they are unit-testable without
component-test infrastructure."
```

---

### Task 5: One `openVia`

`integrations/page.tsx` adopts the shared helper it donated.

**Files:**
- Modify: `apps/web/app/integrations/page.tsx:58-73`

**Interfaces:**
- Consumes: `openVia` from Task 4.
- Produces: nothing new.

- [ ] **Step 1: Import it**

In `apps/web/app/integrations/page.tsx`, add after the existing `../lib/api` import block:

```ts
import { openVia } from "../lib/github-flows";
```

- [ ] **Step 2: Delete the local copy**

Remove lines 58-73 entirely (the local `openVia` const and its comment):

```ts
  // Browsers void the click gesture across an await (popup blockers eat a
  // late window.open) — open the tab synchronously, then point it at the
  // URL the API returns.
  const openVia = (getUrl: () => Promise<string>) => {
    const tab = window.open("", "_blank");
    act(async () => {
      try {
        const url = await getUrl();
        if (tab) tab.location.href = url;
        else window.location.href = url;
      } catch (e) {
        tab?.close();
        throw e;
      }
    });
  };
```

- [ ] **Step 3: Route the two callers through `act`**

Replace `setupApp` and `connectGithub` (lines 75-89) with:

```ts
  // The manifest dance: the server mints a one-time flow; the browser tab we
  // open is what gets bound to it (cookie), then continues to GitHub.
  // act() calls its fn synchronously, so openVia's window.open stays inside
  // the click gesture.
  const setupApp = () =>
    act(() =>
      openVia(async () => {
        const r = await apiPost<{ go_url: string }>("/github/app/manifest/start", {
          organization: org.trim() || null,
        });
        return r.go_url;
      })
    );

  const connectGithub = (regId: string) =>
    act(() =>
      openVia(async () => {
        const r = await apiPost<{ go_url: string }>(`/github/app/${regId}/install/start`, {});
        return r.go_url;
      })
    );
```

- [ ] **Step 4: Verify the build**

Run: `just check`
Expected: PASS.

- [ ] **Step 5: Verify the tab still opens, by hand**

Run `just dev`, open http://localhost:3000/integrations, click **Set up GitHub App**.
Expected: a new tab opens and lands on GitHub's manifest form. **A blocked-popup warning is a regression** — it means `window.open` slipped outside the click gesture.

- [ ] **Step 6: Commit**

```bash
git add apps/web/app/integrations/page.tsx
git commit -m "refactor(web): share one openVia between integrations and the run composer"
```

---

### Task 6: Name the list container, hide un-attachable bundles

**Files:**
- Modify: `apps/web/app/globals.css` (add `.opt-list` after the `.opt-grid` block, ~line 2589)
- Modify: `apps/web/app/components/BundlePicker.tsx:79` (inline style), `:80` (the filter)

**Interfaces:**
- Consumes: nothing.
- Produces: the `.opt-list` CSS class. Task 8 uses it for the repository list.

- [ ] **Step 1: Add the class**

In `apps/web/app/globals.css`, immediately after the `.opt-grid { … }` block:

```css
/* Single-column scrolling container for .opt / .cap-row lists too long for
   .opt-grid's auto-fit columns (repositories: up to 100). Promoted from
   BundlePicker's inline style so the repo list and the bundle list share one
   container. */
.opt-list {
  display: grid;
  gap: 6px;
  max-height: 340px;
  overflow-y: auto;
  padding-right: 2px;
}
```

- [ ] **Step 2: Adopt it in BundlePicker, and hide zero-tool bundles**

In `apps/web/app/components/BundlePicker.tsx`, add after the `pinOf` const (line 39):

```ts
  // A zero-tool bundle contributes nothing to a run, so attaching one is
  // always a mistake. They are almost always test residue: fluidbox-db's
  // tests mint `pmt-bundle-<uuid>` against REAL Neon (see CLAUDE.md), so a
  // dev database accumulates them. The cure is `just db-clean`; this is a
  // guard. A pinned bundle stays visible even at zero tools — hiding
  // something already attached would strand it.
  const attachable = (name: string) =>
    (byName.get(name)![0].tool_count ?? 0) > 0 || !!pinOf(name);
  const shownNames = names.filter(attachable);
  const hiddenCount = names.length - shownNames.length;
```

Replace line 79:

```tsx
      <div style={{ display: "grid", gap: 6, maxHeight: 340, overflowY: "auto", paddingRight: 2 }}>
```

with:

```tsx
      <div className="opt-list">
```

Replace line 80's `{names.map((name) => {` with:

```tsx
        {shownNames.map((name) => {
```

Then, immediately after that list's closing `</div>` (line 121), add:

```tsx
      {hiddenCount > 0 && (
        <p className="helper" style={{ margin: "6px 0 0" }}>
          {hiddenCount} bundle{hiddenCount === 1 ? "" : "s"} hidden — no tools to attach.
        </p>
      )}
```

- [ ] **Step 3: Verify the build**

Run: `just check`
Expected: PASS.

- [ ] **Step 4: Verify by hand**

Run `just dev` → **New Run** → the **Workspace & tools** tab.
Expected: `pmt-bundle-…` rows with `0 tools` are gone, replaced by a `N bundles hidden — no tools to attach.` line. The bundle list still scrolls at ~340px.

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/globals.css apps/web/app/components/BundlePicker.tsx
git commit -m "feat(web): name the .opt-list container, hide un-attachable bundles

A zero-tool bundle can never contribute to a run. They are test residue:
fluidbox-db's tests mint pmt-bundle-<uuid> against real Neon."
```

---

### Task 7: Connection rows — `.opt`, and a `+ new` that knows where it is

The largest task. Replaces the native Connection `<select>` with `.opt` cards, adds the state-machine button, and reconciles after the GitHub round-trip.

**Files:**
- Modify: `apps/web/app/components/WorkspacePicker.tsx` — imports (`:7-8`), state + effects (`:75-95`), the Connection `<label>` (`:145-159`)

**Interfaces:**
- Consumes: `isGitConnection` (Task 1); `nextGithubAction`, `GITHUB_ACTION_LABEL`, `openVia`, `GithubAction` (Task 4); `.opt-grid` (existing), `.bundle-picker-head` (existing).
- Produces: nothing new.

- [ ] **Step 1: Extend the imports**

Replace lines 7-8:

```ts
import { useEffect, useState } from "react";
import { apiGet, Connection, isGitConnection, Repo, WorkspaceSpec } from "../lib/api";
```

with:

```ts
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
```

- [ ] **Step 2: Replace the connections effect with a reconciling loader**

Replace lines 75-83:

```ts
  const [connections, setConnections] = useState<Connection[]>([]);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [repoErr, setRepoErr] = useState("");

  useEffect(() => {
    apiGet<{ connections: Connection[] }>("/connections")
      .then((r) => setConnections(r.connections.filter((c) => c.status === "active")))
      .catch(() => {});
  }, []);
```

with:

```ts
  const [connections, setConnections] = useState<Connection[]>([]);
  const [registrations, setRegistrations] = useState<GithubAppRegistration[]>([]);
  const [repos, setRepos] = useState<Repo[]>([]);
  const [repoErr, setRepoErr] = useState("");
  const [flowErr, setFlowErr] = useState("");
  // Ids seen before a GitHub round-trip, so we can spot what it produced.
  const beforeIds = useRef<string[] | null>(null);

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
    // so a provider stays out until deliberately classified as git.
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
    void load();
    // The GitHub dances happen in another tab; refocus is our only signal
    // that they finished. Same pattern as integrations/page.tsx.
    window.addEventListener("focus", load);
    return () => window.removeEventListener("focus", load);
  }, [load]);
```

- [ ] **Step 3: Add the action handler**

Add immediately after the `set` const (currently line 97):

```ts
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
      const r = await apiPost<{ go_url: string }>(
        `/github/app/${action.regId}/install/start`,
        {}
      );
      return r.go_url;
    }).catch((e) => {
      beforeIds.current = null;
      setFlowErr(String(e));
    });
  };
```

And add the org field's state beside the others:

```ts
  const [org, setOrg] = useState("");
```

- [ ] **Step 4: Replace the Connection `<select>` with `.opt` cards**

Replace lines 145-159 (the whole Connection `<label className="field">` block):

```tsx
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
```

with:

```tsx
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
                    {c.metadata?.account_login ? `→ ${c.metadata.account_login}` : " "}
                  </span>
                </button>
              ))}
            </div>
          </div>
```

- [ ] **Step 5: Verify the build**

Run: `just check`
Expected: PASS.

- [ ] **Step 6: Verify by hand — the whole round-trip**

Run `just dev` → **New Run**. Type a task. Pick an agent. Go to the **Workspace & tools** tab → **Git repository**.

Expected:
1. Connection renders as cards, not a native dropdown. No `mcp_http` card.
2. The button reads `+ Add repositories` (you have an active registration + installation).
3. Click it → a new tab opens to GitHub. **No popup-blocker warning.**
4. Return to the fluidbox tab → the list refreshes.
5. **Your task text and agent choice are still there.**

- [ ] **Step 7: Commit**

```bash
git add apps/web/app/components/WorkspacePicker.tsx
git commit -m "feat(web): connection picker as .opt cards with a stateful + new

The native select is replaced by the same card the model picker uses. + new
resolves to create/install/add_repos from registration state, and the modal
holds its draft across the GitHub tab round-trip, reconciling on refocus."
```

---

### Task 8: Repository rows — `.opt-list` and a filter

**Files:**
- Modify: `apps/web/app/components/WorkspacePicker.tsx` — the Repository `<label>` (originally `:161-192`, shifted by Task 7)

**Interfaces:**
- Consumes: `.opt-list` (Task 6); `action` (Task 7).
- Produces: nothing new.

- [ ] **Step 1: Add filter state**

Beside the other `useState` calls:

```ts
  const [repoFilter, setRepoFilter] = useState("");
```

- [ ] **Step 2: Replace the Repository `<select>`**

Replace the `draft.connectionId ? ( … ) : ( … )` block's **first** branch (the Repository `<label className="field">` containing the `<select>`) with:

```tsx
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
```

- [ ] **Step 3: Verify the build**

Run: `just check`
Expected: PASS.

- [ ] **Step 4: Verify by hand**

Run `just dev` → **New Run** → the **Workspace & tools** tab → **Git repository** → select a `github_app` connection.
Expected: repositories render as a scrolling `.opt-list`; a filter appears above 8 repos and narrows the list as you type; selecting one marks it `Selected`.

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/components/WorkspacePicker.tsx
git commit -m "feat(web): repository picker as a filterable .opt-list

Same .opt card as Connection; .opt-list rather than .opt-grid because 100
repos do not belong in auto-fit columns."
```

---

### Task 9: The agent picker joins its own modal

`RunComposer`'s agent list is a native `<select>` sitting two sections above a model picker that already renders `.opt` cards.

**Files:**
- Modify: `apps/web/app/components/RunComposer.tsx:466-472`

**Interfaces:**
- Consumes: `.opt-grid`, `.opt`, `.field-hint` (all existing).
- Produces: nothing new.

- [ ] **Step 1: Replace the `<select>`, keeping the revision hint**

Replace lines 466-472 — the entire `<label>` through its closing `</label>`:

```tsx
              <label className="field">
                <span className="lab">Agent</span>
                <select className="inp" value={selectedAgentName} onChange={(event) => setSelectedAgentName(event.target.value)}>
                  {agents.map((candidate) => <option key={candidate.id} value={candidate.name}>{candidate.name}</option>)}
                </select>
                <span className="field-hint">Changes below append a new revision; active runs keep their original frozen revision.</span>
              </label>
```

with:

```tsx
              <div className="field">
                <span className="lab">Agent</span>
                <div className="opt-grid">
                  {agents.map((candidate) => (
                    <button
                      key={candidate.id}
                      type="button"
                      className={`opt ${selectedAgentName === candidate.name ? "on" : ""}`}
                      onClick={() => setSelectedAgentName(candidate.name)}
                    >
                      <span className="t">
                        {candidate.name}
                        {selectedAgentName === candidate.name && (
                          <span className="selected-label">Selected</span>
                        )}
                      </span>
                    </button>
                  ))}
                </div>
                <span className="field-hint">Changes below append a new revision; active runs keep their original frozen revision.</span>
              </div>
```

The `<label>` becomes a `<div>` because a `<label>` wrapping many buttons has no
single control to label. **Keep the `field-hint` span**: it is the append-only
revision warning (agents are never mutated), not decoration.

- [ ] **Step 2: Verify the build**

Run: `just check`
Expected: PASS. If TS reports an unbalanced JSX tag, the closing `</label>` was not converted to `</div>`.

- [ ] **Step 3: Verify the revision hint survived**

Run: `grep -c "append a new revision" apps/web/app/components/RunComposer.tsx`
Expected: `1` — unchanged from before this task.

- [ ] **Step 4: Verify by hand**

Run `just dev` → **New Run** → the **Agent** tab → **Use an existing agent**.
Expected: agents render as `.opt` cards matching the Model cards below them. Selecting one marks it `Selected` and the **Workspace & tools** tab still resolves that agent's workspace.

- [ ] **Step 5: Commit**

```bash
git add apps/web/app/components/RunComposer.tsx
git commit -m "feat(web): agent picker as .opt cards, matching its own model picker"
```

---

### Task 10: Close it out

**Files:**
- Modify: `docs/plans/2026-07-15-run-composer-pickers-design.md` (status line)

- [ ] **Step 1: Clear the test residue**

Run: `just db-clean`
Expected: the `pmt-bundle-…` rows are gone from the dev database (they are `fluidbox-db` test residue against real Neon, not a UI defect — Task 6's guard is a safety net, not the cure).

- [ ] **Step 2: Run the full bar**

Run: `just check`
Expected: PASS — fmt, clippy, cargo test, `pnpm test` (13 passed), `pnpm build`.

- [ ] **Step 3: Run the acceptance suite**

Run: `just e2e` (stop `just dev` first — it owns the stack)
Expected: PASS. Nothing here touches the permission gate, so a failure means something outside this plan's scope broke.

- [ ] **Step 4: Confirm no denylist crept back in**

Run: `grep -rn 'provider !== "mcp_http"' apps/web/app`
Expected: no output.

- [ ] **Step 5: Mark the design shipped**

In `docs/plans/2026-07-15-run-composer-pickers-design.md`, change the status line to:

```markdown
Status: SHIPPED 2026-07-15 (branch claude/run-composer-pickers).
```

- [ ] **Step 6: Commit and open the PR**

```bash
git add docs/plans/2026-07-15-run-composer-pickers-design.md
git commit -m "docs(web): mark run-composer picker design shipped"
git push -u origin claude/run-composer-pickers
gh pr create --title "fix(web): unleak connection pickers, one card vocabulary, working + new" --body "$(cat <<'BODY'
The Configure Run workspace step offered \`mcp_http · Cloudflare\` as a source
for a git checkout — a tool credential the broker calls, which has no repos.

**Root cause was not the missing filter.** The integrations/capabilities rule
lived in prose comments re-derived at four call sites; \`WorkspacePicker.tsx:81\`
forgot. Worse, the surviving predicates used exclusion (\`!== "mcp_http"\`) —
Phase 7 is Slack, which would have sailed through into the repo picker.

One \`Record<ConnectionProvider, "git" | "tool">\` now holds the rule. Adding a
provider without classifying it is a **compile error**.

Also settles the vocabulary split the bug exposed: \`.opt\` and \`.cap-row\` are
one design language split by selection semantics (single vs multi), so the
single-select lists take \`.opt\` — the card the model picker in that same modal
already used. And \`+ new\` resolves to create/install/add_repos from
registration state, holding the run draft across the GitHub tab round-trip.

Presentation only: no Rust, no migration, no RunSpec/gate/custody change.
First test infrastructure in \`apps/web\` (vitest, 13 tests), wired into
\`just check\`.

Design: \`docs/plans/2026-07-15-run-composer-pickers-design.md\`

🤖 Generated with [Claude Code](https://claude.com/claude-code)

https://claude.ai/code/session_016vw74YXS3K5NytVaezSS81
BODY
)"
```

---

## Verification matrix

| Spec § | Requirement | Task |
|---|---|---|
| 3.1 | `isGitConnection` / `isToolConnection` allowlist | 1 |
| 3.1 | `WorkspacePicker` leak fixed | 2 |
| 3.1 | Other call sites adopt the predicate | 3 |
| 3.2 | `.opt` for single-select, `.cap-row` for multi | 7, 8, 9 |
| 3.2 | `.opt-list` named, adopted by bundles + repos | 6, 8 |
| 3.3 | "Public repository" is an explicit card | 7 |
| 3.4 | `+ new` create/install/add_repos state machine | 4, 7 |
| 3.4 | Optional organization field on create | 7 |
| 3.4 | Legacy connections offer no add_repos | 4 (test), 8 (empty state) |
| 3.5 | Tab opened inside the click gesture | 4 (`openVia`), 5 |
| 3.5 | Refocus refresh + single-match auto-select | 4 (`pickNewConnection`), 7 |
| 3.5 | Draft survives the round-trip | 7 (manual) |
| 3.5 | `openVia` shared, not duplicated | 4, 5 |
| 3.6 | Zero-tool bundles hidden | 6 |
| 3.6 | `just db-clean` for the residue | 10 |
| 5 | Phase 7 Slack regression guard | 1 (Record + test) |
