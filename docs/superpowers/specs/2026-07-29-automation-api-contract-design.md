# Automation API contract & template clarity — design

**Date:** 2026-07-29
**Status:** Approved (design review with owner)
**Scope:** `apps/web` (Configure Run composer, Automations list, new detail page) + `crates/fluidbox-server/src/triggers.rs` + one `fluidbox-db` method. No migrations.

## Problem

1. The API integration contract (invoke URL, curl, variables, responses) is shown exactly once — in the post-save `ShowAutomationSecrets` modal — and is unreachable afterwards without rotating the token. Users have no durable place to inspect a saved configuration or re-copy the API request.
2. `GET /v1/triggers/{id}` does not return the absolute `invoke_url`/`base_url` (only create and rotate do), so the dashboard *cannot* rebuild the contract later even though nothing secret is involved.
3. Saved automations cannot be edited at all (no PATCH endpoint), so "edit → updated API representation" is impossible.
4. The "What should happen each time? — optional template" box under-explains itself: it doesn't say it is a template rendered per firing, "optional" is only true for API-kind triggers, and placeholder behavior is a one-line passive hint.

## Governing rule

**The API contract is always copyable and always rendered live from the current saved subscription. Only the two secrets (trigger token, callback signing secret) are one-time.** The trigger token is sha256-hashed at rest and can never be re-shown; recovery is rotation. This is a kept security invariant, not a UX gap.

## 1. Configure Run composer — template box

- **Label renames, per trigger kind** (replaces "What should happen each time? optional template"):
  - API call: **"Task template — rendered for every API invocation"**
  - Schedule: **"Task template — rendered at every scheduled firing"**
  - Pull request: **"Task template — rendered for every matching PR event"**
  - Run-once mode is unchanged ("What should the agent accomplish?").
- **Placeholder chips** under the textarea, live-parsed with the existing `templateVariables()` regex: caller-supplied vars styled one way ("caller sends in `context`"), system vars (`fire_time`, `repository`, `pr_number`, `pr_title`) another ("filled by fluidbox"). Replaces the passive `templateHint` line.
- **"optional" appears only when it is true**: kind=api with `allow_task_override` on. Schedule/event kinds (and api without override) mark the template required and validate presence inline before save, mirroring the backend rules (`triggers.rs:382,507,325`).

## 2. Copy API button lifecycle

- **Before saving** (automation mode, kind=api, form valid — name present, template-or-override satisfied): the right-hand summary panel shows a compact **"API preview"** card — curl skeleton with `<minted-on-save>` for the token, real URL pattern, detected variables. Button label is **"Copy preview"** so nobody wires an integration to it. Hidden while the form is invalid.
- **On save**: `ShowAutomationSecrets` is trimmed to what is truly one-time — token + callback secret stay front and center; endpoint/variables/curl/responses sections move to the detail page. Footer gains: *"Everything except these secrets is always available at Automations → {name} → API"* with a link to `/automations/{id}`.
- **After saving, forever**: the detail page renders the full contract from `GET /triggers/{id}` with a Copy button on every block. The curl uses `Authorization: Bearer $FLUIDBOX_TRIGGER_TOKEN`. **Rotate token** sits beside it (existing flow → secrets modal).

## 3. New page: `/automations/{id}`

Single scrolling page (no tabs). List rows on the Automations page link to it; "Rotate token" remains in both places.

- **Header**: name, kind badge, enabled toggle, agent link, next-fire time for schedules.
- **API section** (kind=api; events show their ingress URL here): invoke/poll URLs, curl with token placeholder, variables table, response codes (200/400/401/409 concurrency/422 idempotency-key reuse with a different body — 422 matches what the server actually returns), callback signature block — each a `CopyBlock`. Plus Rotate token.
- **Configuration section**: agent, autonomy, concurrency, overrides, schedule facts, with **Edit** on the mutable subset (§4).
- **Template section**: rendered template with placeholder chips; **Edit template** inline (textarea + the same validation as create — must render from the kind's sample context). Saving PATCHes; the API section re-renders immediately. A line under the contract reads *"Reflects the configuration as of {updated_at}"* so edits are visible, not silent.
- **Activity section**: reuse `AutomationActivity` (runs / firings & skips / deliveries). The list-row expander stays but gains an "Open →" link.

## 4. Backend changes

- **URL fields on read**: `GET /v1/triggers/{id}` gains `base_url`, `invoke_url`, `poll_url_template`, `ingress_url` — same derivation as create/rotate (`public_url` + id; no secrets); `GET /v1/triggers` gains `base_url` only (the list UI never renders contracts; the detail page carries the full block). Refactor the duplicated JSON block into one helper used by every response that carries the contract.
- **`PATCH /v1/triggers/{id}`** — mutable surface only:
  - `name`, `task_template`, `allow_task_override`, `allow_workspace_override`, `callback_url` (re-runs the same SSRF admission check as create), `concurrency_policy`; for schedules also `cron`, `timezone`, `missed_policy`.
  - Trigger kind and agent are immutable — attempting to change them is a 400; changing those means a new automation.
  - Template validation identical to create: renders against the kind's sample context; api-kind requires template-or-override.
  - RBAC: `can_manage_subscriptions`, same as the other trigger management endpoints.
- **`fluidbox-db::update_trigger_subscription`** — TenantScope-signed like every tenant-owned method. All columns already exist; **no migration**.
- **Invariant preserved**: RunSpec freezing is untouched. In-flight runs keep their snapshot; future firings use the updated template — exactly the platform's existing immutability model.

## 5. Persistence semantics

| Question | Answer |
|---|---|
| Contract across refresh / navigation / future sessions? | Always rebuildable — rendered from the DB row via `GET /triggers/{id}`; nothing lives only in client state. |
| Unsaved composer state? | Already persisted by `useSessionDraft` (unchanged). |
| Edit → API snippet? | Updates automatically (live render) + visible "as of {updated_at}" stamp. No snippet versioning (YAGNI) — per-run audit truth is the frozen RunSpec. |
| Token after edit? | Unchanged. Rotation is a deliberate, separate act that revokes all live tokens. |

## 6. Testing & verification

- **Rust unit tests** (`triggers.rs`): PATCH validation (immutable-field 400, template re-validation per kind, callback_url admission), URL fields present on get/list.
- **Web**: `pnpm build` must pass; component-level behavior follows existing patterns.
- **Manual lifecycle drill**: configure → save → copy → leave → return via `/automations/{id}` → copy again → edit template → contract reflects the edit with updated stamp.
- DB-backed and e2e suites are owner-triggered only (standing agreement); the implementation plan will call out which ones are worth running.

## Out of scope

- Editing trigger kind or agent in place (duplicate-as-new is the path; not built in this pass).
- SDK snippets beyond curl.
- Snippet/version history.
