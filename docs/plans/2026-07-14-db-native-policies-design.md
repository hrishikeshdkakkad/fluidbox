# fluidbox — DB-native policies: versioned storage, structured authoring, agent attachment

Status: design, 2026-07-14.
Supersedes parts of `docs/plans/2026-07-14-governance-page-design.md` §7 (§17 #10) — see §8.

Related: `PLAN.md` §2 (convergence invariants), `docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md` §17,
`docs/guides/policies.md`.

---

## 1. Problem

The Governance page (PR #36) made the policy model **visible** and tunable per tool. It did
not make it **authorable**. Three gaps remain, and together they mean the product still
cannot answer its own premise without a terminal:

1. **You cannot create a policy in the UI.** The only paths are adding a
   `policies/*.yaml` file or `POST /v1/policies`.
2. **You cannot author rules in the UI.** The matrix edits per-tool overrides of an
   *existing* policy; budgets, approvals, egress, path globs and the shell classifier are
   YAML-only.
3. **You cannot attach a policy to an agent in the UI.** `RunComposer.tsx:262` hardcodes
   `policy: "default"` — the only mention of policy assignment in the entire dashboard.

The consequence is measurable. The live tenant has 18 policies; **every agent created
through the UI is on `default`**, because `default` is the only policy the UI can reach and
the only one it can create. The Governance page is a list you cannot route anything to.

### The finding that reframes this

**Policies are already stored in the DB.** `crates/fluidbox-db/src/seed.rs` reads
`policies/*.yaml` **once, at boot**, through `seed_policy_if_absent`, whose own comment is
explicit:

```rust
// Bootstrap only when absent — never clobber UI edits on reboot.
```

It even synthesises `name: default` when the directory is empty. The DB row is what
`create_run` freezes; the file is a **seed**. Exactly one mechanism still treats the file
as authoritative: **`just policy-sync`**, which force-upserts and would clobber UI-authored
content.

So this is not a storage migration. It is: **make the UI a first-class authoring surface,
and give it the audit trail that git was silently providing.**

### The regression to avoid

Editing `paths.deny: **/.env` today means a commit — a diff, a reviewer, `git blame`. UI
authoring removes all of it, and `policies` is **one mutable row with no history**
(`unique (tenant_id, name)`; `version` is an odometer, not an address — v5 destroys v4, and
there is no history table). Ship authoring on that storage and someone deletes `**/.env`
with a click and **no record exists that it was ever there**. That is a governance
regression inside a governance feature, and it is what §3 exists to prevent.

---

## 2. Approaches considered

**Authoring depth**

1. *Clone + tune only* — create by cloning; differentiate with the matrix and flat knobs;
   never author a rule. Truly easy, but cannot express a new rule shape, so YAML survives
   for the long tail.
2. *Clone + tune + a rule editor behind "Advanced"* — middle ground.
3. **Full structured authoring — CHOSEN.** Every policy field editable: rules with
   ordering, matchers, constraints, plus defaults/budgets/approvals/autonomy/egress. The
   only option that actually retires YAML as an authoring surface. Cost: rule *order*
   becomes a UI concern, and the editor is expert-facing.

**Audit trail**

1. *Mutable row + an edit log* — cheaper, shows who removed what, but cannot revert and the
   old content is still gone.
2. *Export-to-YAML for git* — opt-in and manual, so the reviewed file drifts from the live
   policy. That ambiguity is precisely what this work removes.
3. *Accept no audit* — "who removed `**/.env`?" becomes unanswerable.
4. **Append-only versions — CHOSEN.** Mirrors `agent_revisions` and `capability_bundles`,
   which the codebase already does twice. History, diff, revert, attribution.

**Schema shape for versioning**

1. *One table, `unique(tenant, name, version)`, revisions point at the policy NAME.* The
   `capability_bundles` shape. But `agent_revisions.policy_id` is a `uuid` FK, so this
   rewires every revision plus `run_service`, `api.rs`, and the seed — meaningful surgery
   for the same outcome as (3).
2. *One table, revisions PIN a version.* Fully mirrors bundles — and **inverts the
   semantics**: a policy edit would no longer reach existing agents. Right for bundles
   (a third party publishes them); wrong for policies (you author them, and an edit is
   meant to take effect). Rejected.
3. **Split identity from content — CHOSEN.** `policies` keeps `(id, tenant_id, name)`;
   a new append-only `policy_versions` holds every edit. `agent_revisions.policy_id`
   **never changes** — the FK survives, `run_service` gains one lookup, and the shape
   matches `agents` → `agent_revisions`.

**Overrides**

1. *Keep `managed_overrides`* (PR #36 as shipped) — no rework, no version churn per click,
   but two mechanisms grant permission, so "why is this tool allowed?" has two answers.
2. **Collapse into rules — CHOSEN.** The column exists for exactly one reason: the authored
   YAML was git-owned, so the UI needed somewhere to write that was not the YAML. Once the
   UI owns the rules and every edit is a revertible version, an override **is** a rule — a
   specific one, ahead of the general ones. One mechanism, one explanation.

---

## 3. Trust model (the load-bearing part)

**Version history replaces git review; it does not merely log it.** Every published edit is
an immutable `policy_versions` row carrying `author`, `summary`, and `created_at`. "What
was removed, when, and what did it look like before?" is answerable by reading rows, and
revert is publishing the old content as a *new* version — never mutating or deleting one.
This is the same append-only discipline as agents and capability bundles, and the same
reason: an audit trail nobody can rewrite.

**Be honest about `author`: fluidbox has no user model.** Auth is a single admin token
(`auth.rs`), so `author` records the **provenance** — `seed` | `api` | `ui` | `import` —
not a person. Against git's `blame`, that is a real downgrade: git answers *who*, this
answers *how it got here*. It is still the difference between "someone deleted `**/.env`
through the dashboard on 2026-07-14 and here is the exact diff" and today's silence, and
`summary` lets the publisher say why. The column is deliberately `text` rather than an
enum so that a future identity model can write a principal into it without a migration.
Per-person attribution is out of scope and blocked on multi-user auth, which has its own
EPIC (`docs/plans/2026-07-14-multi-user-mcp-control-plane-design.md`).

**Draft → Publish is the review beat.** Edits accumulate in a draft; `Publish` mints ONE
version with a summary and a diff against the current one. This is not only churn control
(a 5-click matrix session would otherwise mint 5 versions) — it restores the moment of
deliberate review that a PR used to force, at the point where the blast radius is stated.

**`RunSpec` remains the run's law.** `create_run` resolves latest → freezes `content` into
the RunSpec. In-flight runs are immune to publishes; a completed run can always be judged
against the exact rules it ran under, even after the policy moves on. **Unchanged from
today**, and it is why mutable-latest is safe.

**The gate order is untouched.** `decide_tool_call` stays budget → frozen-capability
availability → trust tier → policy → approvals. Authoring moves only what the *policy*
layer says. No edit can defeat a fork PR's `ReadOnly` tier, the budget ceiling, or the
frozen capability set. **This design must not touch `internal.rs`, `run_service.rs`'s gate
path, `workers.rs`, or `orchestrator.rs`.**

**Editing is admin-token authority, and always was.** The token that can publish a policy
version could already `POST /v1/policies` with arbitrary YAML. Authoring adds *reach*, not
*authority* — which is exactly why the audit trail, not a permission check, is the control.

**What we deliberately give up.** Policy changes leave git. There is no PR review of a rule
edit, no CODEOWNERS on `**/.env`. Version history + attribution + diff is the replacement,
and it is weaker in one specific way: it is *detective*, not *preventive*. A future
"require approval to publish" is the natural answer and is out of scope here.

---

## 4. Design

### 4.1 Objects

Migration `0011_policy_versions.sql`:

```sql
-- Identity and content split: `policies` is the stable thing an agent revision
-- points at; `policy_versions` is the append-only history. Mirrors
-- agents -> agent_revisions, so agent_revisions.policy_id NEVER changes.
create table policy_versions (
    id           uuid primary key,
    policy_id    uuid not null references policies(id) on delete cascade,
    version      int  not null,
    content      jsonb not null,          -- the canonical Policy
    yaml_source  text,                    -- nullable: set on YAML-authored versions
    summary      text,                    -- publish note; null for seeds/imports
    author       text not null,           -- 'seed' | 'api' | 'ui' | 'import'
    created_at   timestamptz not null default now(),
    unique (policy_id, version)
);

-- Backfill: today's single row becomes version 1, overrides folded in (§4.7).
-- The fold PREPENDS each override as a head rule, in managed_overrides order —
-- exactly where evaluate_supervised consulted it — so no policy changes meaning:
--   content.tools = [ {match:[o.tool], action:o.action} for o in managed_overrides ]
--                   ++ parsed.tools
insert into policy_versions (id, policy_id, version, content, yaml_source, summary, author)
select
  gen_random_uuid(), p.id, p.version,
  jsonb_set(
    p.parsed, '{tools}',
    coalesce(
      (select jsonb_agg(jsonb_build_object('match', jsonb_build_array(o->>'tool'),
                                           'action', o->'action')
                        order by ord)
         from jsonb_array_elements(p.managed_overrides) with ordinality t(o, ord)),
      '[]'::jsonb
    ) || coalesce(p.parsed->'tools', '[]'::jsonb),
    true
  ),
  p.yaml_source, 'migrated from 0010 managed_overrides', 'import'
from policies p;
```

> The fold is expressed in SQL so the migration is self-contained, but its
> **correctness is pinned in Rust** by the verdict-equivalence property test (§6) — the
> SQL is the mechanism, the test is the guarantee. If the expression proves awkward,
> a one-shot Rust backfill is an acceptable substitute; the behavioural requirement
> is unchanged.

```sql
-- Drop what has moved or been superseded.

alter table policies drop column yaml_source;
alter table policies drop column parsed;
alter table policies drop column managed_overrides;   -- supersedes 0010
alter table policies drop column version;             -- now lives on the version row
```

`policies` retains `(id, tenant_id, name, created_at, updated_at)` and its
`unique (tenant_id, name)`.

**`content` is canonical.** The UI authors structure, so structure is the source of truth.
`yaml_source` becomes a *derived import/export artifact*: populated verbatim when a version
arrives as YAML (so `POST /v1/policies {name, yaml}` and the e2e keep working), generated
on demand otherwise. YAML stops being authoritative and becomes an interchange format.

`fluidbox-core::policy::Policy` **loses `managed_overrides`** (§4.7).

### 4.2 Resolution

```rust
/// The version that governs future runs.
pub async fn latest_policy_version(pool, policy_id) -> sqlx::Result<Option<PolicyVersionRow>>;
```

`run_service::create_run` becomes: `get_policy(rev.policy_id)` → `latest_policy_version` →
deserialize `content` → freeze into RunSpec. One extra lookup; everything downstream is
byte-identical to today.

A policy with **zero** versions is a bug, not a state: `create_run` fails closed with
`ApiError::Internal("policy '{name}' has no versions")`. §4.5's seed and §4.6's create both
mint version 1 in the same transaction as the policy row.

### 4.3 Engine

`evaluate_supervised` **loses its override branch** and returns to a plain first-match-wins
walk over `tools`. `Policy::validate()` keeps the invariants that still apply (a
matrix-authored rule carries no wildcard; no duplicate exact-name head rules) and **drops
the override-vs-conditional check** — a conditional rule is now editable *as a rule*, which
is legitimate, versioned, and revertible.

`Policy::tool_matrix()` and `autonomy_summary()` are **unchanged**, minus the `Overridden`
variant of `ToolStatus`, which no longer has a source. A tool set from the matrix now
resolves as `Unconditional { rule: Some(0) }` — a real rule, at the head.

`can_require_approval`'s three-route mirror of `apply_rule` is **unchanged and still
load-bearing** (design `2026-07-14-governance-page-design.md` §4.3).

### 4.4 The authoring UI

`/governance` gains **New policy** — clone a parent (inherits its rules) or start blank.
`/governance/[name]` gains:

- **Rules** — ordered list, drag to reorder, `match` chips (typeahead over `CANONICAL` ∪
  the policy's `policy_mcp_tools`), action, and per-constraint editors:
  - *paths*: allow-glob list + deny-glob list, with the hardcoded "outside allowed → asks a
    human" stated from `constraints.paths_on_no_match` (never re-derived in TS).
  - *shell*: allow-prefix list, deny-regex list, `on_no_match`.
- **Defaults · Budgets · Approvals · Autonomy · Egress** — flat forms.
- **History** — version list, diff against any version, one-click revert (publishes the old
  content as a new version).
- The **matrix** stays as the fast path: clicking a tool edits/creates a head rule in the
  draft.
- The **blast-radius banner** stays, and now applies at Publish rather than per click.

Draft state lives client-side and is submitted whole to Publish; a draft is not persisted
server-side (YAGNI — a lost draft costs a re-edit, and persisting it invites a second
source of truth).

**The dashboard stays presentation-only.** It never parses YAML and never resolves a
verdict: the server sends `content`, `tool_matrix`, `autonomy_summary`, and constraint
payloads; the browser renders and posts structure back.

### 4.5 Files, seed, and policy-sync

`seed.rs` **keeps reading `policies/*.yaml` at boot**, unchanged in spirit: seed-if-absent,
never clobber. That is how a fresh clone gets a sane `default`, and it now mints
`policy_versions` v1 with `author='seed'`. `policies/default.yaml` survives as the
**bootstrap seed**, not the source of truth.

**`policy-sync.sh` is retired.** Its force-push is the one mechanism that would clobber
UI-authored versions. The justfile recipe is removed; `docs/guides/policies.md` is rewritten
to describe the UI as the authoring surface and YAML as import/export. `POST /v1/policies
{name, yaml}` **survives** as the import path (the e2e depends on it) and now appends a
version with `author='api'`.

### 4.6 API

| Route | Change |
|---|---|
| `GET /v1/policies` | unchanged shape; `version` now = latest version number |
| `GET /v1/policies/{name}` | + `versions: [{version, author, summary, created_at}]` |
| `GET /v1/policies/{name}/versions/{n}` | **new** — one version's content (for diff/revert) |
| `POST /v1/policies` | now **appends a version** (YAML import path; unchanged wire shape) |
| `POST /v1/policies/{name}/publish` | **new** — `{content, summary}` → validates → appends a version |
| `POST /v1/policies/{name}/revert` | **new** — `{version}` → appends a NEW version with that content |
| `POST /v1/policies/{name}/clone` | **new** — `{name, from}` → new policy + version 1 |
| `PUT/DELETE /v1/policies/{name}/overrides/{tool}` | **removed** (§4.7) |

Publish validates the submitted `content` through `Policy::validate()` and refuses on error
— the server enforces what the UI renders, never the UI alone.

### 4.7 Retiring `managed_overrides`

The migration folds every existing override into its policy's rule list as a head rule, in
`managed_overrides` order, ahead of the authored rules — which is exactly where
`evaluate_supervised` consulted them. **No policy changes meaning.** A property test over
the existing policy fixtures asserts verdict-for-verdict equivalence before and after the
fold (§6).

Removed: the column, `set_policy_override`/`clear_policy_override`/`write_policy_overrides`,
the two API routes, the merge+validate wiring in `api::upsert_policy`, `ToolOverride`,
`Policy.managed_overrides`, the override branch of `evaluate_supervised`, and the
override-related e2e assertions.

**This is real rework of PR #36, merged the same day.** What survives is the expensive part:
the canonical vocabulary as data, `tool_matrix`, `autonomy_summary`, `agents_using`,
`policy_mcp_tools`, the conditional/unconditional distinction, and the page itself.

### 4.8 Policy attachment (ships independently — see §7)

`POST /v1/agents` and `POST /v1/agents/{id}/revisions` already accept `policy` (a name;
default `"default"`; unknown names refused). The dashboard needs only a select on the agent
step, fed by `GET /v1/policies`, replacing `RunComposer.tsx:262`'s hardcode — plus the
autonomy card reading `autonomy_summary.permitted` so a policy that forbids autonomy
disables the choice instead of 400-ing at submit.

### 4.9 What does NOT change

`RunSpec` and its frozen policy snapshot; `decide_tool_call`'s order; the trust-tier /
budget / frozen-capability layers above policy; `agent_revisions.policy_id`'s meaning and
FK; `seed.rs`'s seed-if-absent behaviour; the canonical tool vocabulary; the
conditional/unconditional distinction as the *matrix's* affordance rule.

---

## 5. Threat table (delta)

| Threat | Mitigation |
|---|---|
| A click silently weakens a rule (`paths.deny: **/.env`) with no record | Every publish is an immutable version with `author` + diff + revert (§3) |
| An edit reaches an in-flight run | `RunSpec` froze `content` at session creation (unchanged) |
| An edit escapes the gate's upper layers | Authoring touches only the policy layer; trust tier / budgets / frozen capabilities are above it and untouched by this design |
| The override→rule fold changes a verdict | Property test asserts verdict equivalence over the policy fixtures (§6) |
| `policy-sync` clobbers UI-authored versions | The script is retired; the YAML import path appends a version rather than replacing |
| A policy exists with no version | `create_run` fails closed; seed and clone mint v1 in the same transaction as the policy row |
| History is rewritten to hide an edit | `policy_versions` is append-only; revert publishes forward, never mutates |
| The browser forks the meaning of the policy language | The dashboard posts structure and renders server-resolved payloads; it never parses YAML nor computes a verdict |

---

## 6. Testing

`fluidbox-core` (no DB):
- **The fold**: a property test over `policies/*.yaml` + the existing test fixtures —
  for a generated tool-call corpus, `evaluate()` on `{rules, overrides}` (pre-fold) equals
  `evaluate()` on `folded_rules` (post-fold), verdict for verdict, in both autonomy modes.
- `validate()` still refuses wildcard/duplicate head rules; no longer refuses a
  conditional-targeting rule.
- `tool_matrix` reports a folded head rule as `Unconditional { rule: Some(0) }`.
- `ToolStatus::Overridden` is gone; nothing constructs it.

`fluidbox-db` (real Neon; run `-- --test-threads=1`, and with no `just dev` running — its
scheduler breaks `schedule_lifecycle_and_skip_claims`, and parallel db tests `PoolTimedOut`):
- `latest_policy_version` picks the highest version, not the newest `created_at`.
- Publishing appends; no UPDATE touches an existing version row.
- Revert appends a new version whose content equals the target's.
- The 0011 backfill produces exactly one version per existing policy, overrides folded.
- `create_run` on a version-less policy fails closed.

E2E (`scripts/governance-e2e.sh`): publish → new version → the old version still readable →
revert restores → an agent created with `policy: X` runs under X's latest.

`just check` is the bar.

---

## 7. Sequencing

Three specs. Each produces working, shippable software.

**A — Policy attachment** (§4.8). A select + one field; the API already takes it. No design
tension, unblocks the Governance page, ships alone.

**B — Versioned policies** (§4.1–4.3, 4.5–4.7). Schema, resolution, the override fold, the
API. Valuable without any UI: kills "there is no rollback", gives attribution and revert.

**C — Structured authoring UI** (§4.4). The rule editor, clone/create, history/diff/revert.
Depends on B — authoring without history is the regression §1 names.

B before C is not negotiable. A can ship at any time.

---

## 8. Decisions settled at this boundary (§17 addendum)

**#11. How policies are authored and audited once the dashboard owns them.** — SETTLED
2026-07-14. **Partially supersedes §17 #10.**

1. **DB-native, files are a seed.** `policies/*.yaml` remains the bootstrap seed
   (`seed_policy_if_absent`, already never-clobber); `policy-sync.sh` is retired because its
   force-push is the only thing that would overwrite UI-authored content. YAML survives as
   an import/export format, not a source of truth.
2. **Append-only versions, identity split from content.** `policies` keeps the stable
   identity an `agent_revision` points at; `policy_versions` is the append-only history.
   `agent_revisions.policy_id` is unchanged. Latest governs future runs; `RunSpec` still
   freezes. Mirrors `agents`→`agent_revisions`.
3. **Version history is the replacement for git review**, and draft→publish is the
   replacement for the PR beat. It is detective, not preventive; "require approval to
   publish" is the natural successor and is out of scope.
4. **Overrides collapse into rules.** §17 #10's `managed_overrides` column existed solely
   because the authored YAML was git-owned. Once the UI owns the rules and every edit is a
   revertible version, an override *is* a head rule. One mechanism, one explanation. The
   fold must be verdict-preserving.

**Still standing from §17 #10:** the matrix's conditional/unconditional distinction (a flat
three-way control still cannot express a `paths`/`shell` rule, so the *matrix* still refuses
one — the *rule editor* is where such a rule is edited); the canonical vocabulary as data;
the gate order and the layers above policy.
