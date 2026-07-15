# Run-composer pickers: unleak the connection lists, one row vocabulary, `+ new` in place

Status: design approved 2026-07-15. Not yet planned or built.
Scope: `apps/web` only. No Rust changes, no migrations, no API changes.

## 1. The problem

The Configure Run modal's **Workspace & tools** step offers `mcp_http · Cloudflare`
as a source for a git checkout. Cloudflare is a *tool* credential the broker calls
on the control plane's behalf; it has no repositories. Picking it is nonsense.

Two things are wrong, and only one of them is the one you see:

1. **The leak.** `WorkspacePicker` lists every active connection regardless of
   provider.
2. **The vocabulary split.** The same step renders raw native `<select>`
   (Connection, Repository) immediately beside designed `.cap-row` cards
   (capability bundles). The native macOS dropdown is what renders the
   checkmark list in the bug report — it is not our design system at all.

## 2. Root cause

fluidbox keeps one `connections` table across three providers (`github` PAT,
`github_app`, `mcp_http`). The integrations/capabilities split is real and
intentional — but it is enforced by **hand-rolled predicates copy-pasted at
each call site**, described in prose comments rather than expressed in code:

| Site | Predicate | Correct? |
|---|---|---|
| `capabilities/page.tsx:105` | `provider === "mcp_http"` | yes |
| `integrations/page.tsx:111` | `provider !== "mcp_http"` | yes, by luck |
| `ResourceOverview.tsx:81,84` | both directions | yes |
| `RunComposer.tsx:176` | `provider === "github_app"` | yes |
| `WorkspacePicker.tsx:81` | `status` only — **no provider filter** | **no** |

Four sites duplicate the rule; one forgot. That is not bad luck, it is the
design guaranteeing a leak.

**The exclusion form is a scheduled recurrence.** `provider !== "mcp_http"`
admits anything that is not MCP. Phase 7 is Slack. A `slack` connection would
sail through that predicate and land in the git-repo picker — the same bug,
already on the roadmap.

## 3. Design

### 3.1 One predicate, allowlist form (the load-bearing change)

`lib/api.ts` already hosts connection predicates (`needsManualIngress`, `:289`).
Add the provider rule there and delete the hand-rolled copies:

```ts
/** Providers that can back a git workspace checkout. mcp_http is a tool
 *  credential the broker calls — it has no repos, and neither will slack
 *  (Phase 7). Allowlist, not an mcp_http denylist: a new provider stays out
 *  of git pickers until someone deliberately adds it here. */
export const isGitConnection = (c: Connection) =>
  c.provider === "github" || c.provider === "github_app";

/** Tool-server credentials — brokered MCP. The mirror of isGitConnection. */
export const isToolConnection = (c: Connection) => c.provider === "mcp_http";
```

Call sites converted: `WorkspacePicker.tsx:81` (the fix), plus
`integrations/page.tsx:111` and `capabilities/page.tsx:105` (removing the
latent Slack bug). `ResourceOverview.tsx` and `RunComposer.tsx:176` adopt them
where they express the same intent — `RunComposer:176` stays `github_app`-only
(event triggers need App identity to publish checks; that is narrower than
"git", and deliberately so).

This is the only change that prevents recurrence. Everything below is the
design-system pass.

### 3.2 The vocabulary is already there: selection semantics pick the card,
### cardinality picks the container

`.opt` (`globals.css:2593`) and `.cap-row` (`:2589`) are not two design
languages. They are one — identical `border-strong`, `radius: 8px`, and
`.on → accent-dim + accent-tint`. They differ by **selection semantics**:

- `.cap-row` — **multi**-select (checkbox), compact: name + meta.
- `.opt` — **single**-select (button), rich: `.t` title / `.id` / `.d`
  description, plus an `.off` disabled state.

Connection, Repository, and Agent are all *single*-select, so they take `.opt` —
the same card the model picker already uses (`RunComposer:513`) two sections
above them in this very modal. Bundles are multi-select and correctly keep
`.cap-row`.

The **container** then follows cardinality:

| List | Size | Select | Card | Container |
|---|---|---|---|---|
| Connection | 0–5 | single | `.opt` | `.opt-grid` |
| Agent | 0–20 | single | `.opt` | `.opt-grid` |
| Repository | 0–100 (`per_page=100`) | single | `.opt` | `.opt-list` + filter |
| Bundles | 0–50 | multi | `.cap-row` | `.opt-list` |

`.opt-grid` is `repeat(auto-fit, minmax(150px, 1fr))` — right for 4 models, a
wall for 100 repos. `.opt-list` is the scrolling single-column container that
**already exists** at `BundlePicker.tsx:79`, inlined as an anonymous style prop:

```jsx
<div style={{ display: "grid", gap: 6, maxHeight: 340, overflowY: "auto", paddingRight: 2 }}>
```

Promote it to a named class in `globals.css` and both the repo list and the
bundle list use it. This is the design's only new CSS, and it is a cleanup of
an existing inline style rather than new surface area.

A popover combobox was rejected: `ModalShell` already installs a focus trap
(`bits.tsx:89`), and nesting a second one inside it risks real keyboard-nav
bugs for a cosmetic gain.

### 3.3 "Public repository" stops masquerading as a connection

Today the Connection `<select>` carries `value=""` labelled *"public URL (no
credential)"* — a **mode** rendered as if it were an identity. That is the same
category error as the `mcp_http` leak, just quieter. As an explicit `.opt` card
it states what it is:

```
Connection                                        + New GitHub App
┌───────────────────────────────┐ ┌───────────────────────────────┐
│ Public repository             │ │ fluidbox-test-1      Selected │  ← .opt.on
│ (no credential)               │ │ github_app                    │
│ Clone by URL. Public repos    │ │ → hrishikeshdkakkad           │
│ only.                         │ │                               │
└───────────────────────────────┘ └───────────────────────────────┘
   .opt .t / .d                      .opt .t / .id / .d

   (mcp_http · Cloudflare — gone: isGitConnection)

Repository                                      + Add repositories
┌──────────────────────────────────────────────────────────────┐
│ 🔍 filter…                                                   │
├──────────────────────────────────────────────────────────────┤
│ hrishikeshdkakkad/fluidbox                  private · main   │  ← .opt.on
│ hrishikeshdkakkad/infra                     private · main   │
└──────────────────────────────────────────────────────────────┘
   .opt-list (scrolls)
```

Selecting *Public repository* reveals the Clone URL input, exactly as
`connectionId === ""` does today. The `WorkspaceDraft` shape is unchanged —
`connectionId: ""` still means public. This is presentation only.

### 3.4 `+ new` is a state machine, not a button

"Repo should have a github app, or create and install new" is three states, not
one action. The picker reads `/github/app` (registrations) alongside
`/connections`:

| Registration state | Label | Action |
|---|---|---|
| No active registration | `+ New GitHub App` | manifest dance → `POST /github/app/manifest/start` |
| Active registration, no connection | `+ Install GitHub App` | `POST /github/app/{regId}/install/start` |
| Registration + connections | `+ Add repositories` | `POST /github/app/{regId}/install/start` |

The manifest panel carries the same optional **organization** field the
integrations page has (`:79`). It cannot be dropped: private apps install only
on the account that owns them, so a silent personal-only default would strand
every org user.

**Legacy connections fail closed.** `registration_id === null` means custody
lives on the connection, not a registration — there is no registration to
install into. Those rows show no `+ Add repositories` affordance; the empty
repo state links to `/integrations` instead. Never synthesise a registration id.

### 3.5 Surviving the GitHub round-trip

The manifest and install dances round-trip through github.com in a new tab. The
modal holds its draft and reconciles on return — the pattern
`integrations/page.tsx:40` already uses:

1. Open the tab **synchronously** on click, then point it at the URL the API
   returns. Awaiting first voids the click gesture and popup blockers eat the
   tab — `integrations/page.tsx:61-73` documents this; reuse that `openVia`
   helper rather than re-deriving it.
2. `window.addEventListener("focus", …)` re-fetches `/connections` + `/github/app`.
3. Diff against the previously-seen connection ids. If exactly one new git
   connection appeared, select it. If several did, select none and let the user
   choose — guessing would silently bind the wrong repo host to the run.
4. Task text, agent choice, and pins are React state in `RunComposer` and are
   never unmounted, so they survive with no extra machinery.

`openVia` moves from `integrations/page.tsx` into a shared module so both
callers use one implementation.

### 3.6 Un-attachable bundles

`pmt-bundle-*` rows with `0 tools` are **test residue, not a UI bug**:
`fluidbox-db/src/lib.rs:4414` mints `pmt-bundle-{uuid}`, and per CLAUDE.md the
`fluidbox-db` tests run against **real Neon**. The dev database accumulates them.
The cleanup is `just db-clean`.

Independently, `BundlePicker` hides `tool_count === 0` bundles behind a
`Show N empty bundles` disclosure. A zero-tool bundle contributes nothing to a
run; attaching one is always a mistake. This is a guard, not the fix — the fix
is not polluting the database.

## 4. Non-goals

- Page-level lists (`/agents`, `/capabilities`, `/integrations`, `/automations`,
  `/governance`). They already carry New/Add actions and are out of scope.
- Any Rust, API, migration, or `RunSpec` change. The frozen-spec, custody, and
  gate invariants are untouched — this is presentation only, per the
  dashboard-is-presentation-only constraint.
- Changing `WorkspaceDraft` / `draftToInput`. The emitted workspace JSON is
  byte-for-byte what it is today.
- Repo search server-side. Filtering is client-side over the ≤100 already fetched.

## 5. Testing

- `just check` — fmt, clippy, test, web build.
- **Unit**: `isGitConnection` / `isToolConnection` over all four providers,
  including a `slack` row that must be excluded from both git and tool lists.
  This is the regression test for the Phase 7 recurrence.
- **Manual** (the reported bug): open Configure Run → Workspace & tools → Git
  repository. `mcp_http · Cloudflare` must not appear. `+ New GitHub App` must
  open a tab; returning must refresh and preserve the task text.
- Legacy `github_app` connection (`registration_id === null`) shows no
  `+ Add repositories`.
- No e2e change. `scripts/governance-e2e.sh` covers the permission gate, which
  this does not touch.

## 6. Files

| File | Change |
|---|---|
| `apps/web/app/lib/api.ts` | add `isGitConnection`, `isToolConnection` |
| `apps/web/app/lib/github-flows.ts` | **new** — `openVia` + manifest/install starters |
| `apps/web/app/globals.css` | name `.opt-list` (promoted from `BundlePicker:79`'s inline style) |
| `apps/web/app/components/WorkspacePicker.tsx` | provider fix; connection/repo → `.opt`; `+ new` state machine |
| `apps/web/app/components/BundlePicker.tsx` | zero-tool disclosure; inline style → `.opt-list` |
| `apps/web/app/components/RunComposer.tsx` | agent `<select>` → `.opt` (matches its own model picker) |
| `apps/web/app/integrations/page.tsx` | adopt predicate + shared `openVia` |
| `apps/web/app/capabilities/page.tsx` | adopt predicate |
| `apps/web/app/components/ResourceOverview.tsx` | adopt predicate |
