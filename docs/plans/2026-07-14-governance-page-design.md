# fluidbox — The Governance page (permissions matrix + managed overrides)

Status: design, 2026-07-14.
Scope: make the governance model **visible and controllable** in the dashboard, without
letting the UI flatten the security engineering that lives in the policy.

Related: `PLAN.md` §2 (convergence invariants), `docs/plans/2026-07-10-agent-workspaces-triggers-integrations-design.md` §8/§17,
`docs/guides/policies.md`.

---

## 1. Problem

The whole product premise is "AI coding agents in **governed** sandboxes", and the
governance model is **invisible in the product**. Today:

- No `.tsx` renders a policy. `/settings` is a stub about the admin token.
- Policies exist only as `policies/*.yaml`, reaching the server via `just policy-sync`.
- The only governance control in the UI is the run wizard's autonomy toggle, which is
  itself defective (its label swaps with its state, so the OFF state reads as its own
  opposite, and `aria-pressed` announces "Supervised runs, not pressed" — false).
- The wizard says "Autonomous runs defer to the configured policy" while showing neither
  the policy nor the fallback. `policy.autonomy.permitted` can forbid autonomous runs
  entirely, and today you can select Autonomous, walk to Review, and eat a
  `400 policy does not permit autonomous runs` at submit.

A user cannot answer the three questions they actually have: **can this run unattended,
what is it allowed to do, and what can it spend.**

### Requirement (2026-07-14)

Not a YAML dashboard. The experience must be intuitive, with **minimal user edits** and
**auto-population wherever the system already knows the answer**.

---

## 2. Approaches considered

1. **YAML editor in the browser** (lens + textarea + validate + publish). Rejected: it is
   the same authoring model with a nicer font, and re-serializing `yaml_source` destroys
   the comments in `policies/default.yaml` — which is mostly reasoning ("resolved
   2026-07-10 from live-run ledger data", "caps sit 4–25× above observed").
2. **Presets + knobs** (Strict / Balanced / Permissive + autonomy + budgets). Rejected:
   cannot express "let this one agent use Cloudflare KV" — the actual live use case.
3. **Observed-behaviour-first** (drive the policy from ledger history: "you approved this
   3×, always allow?"). Deferred, not rejected: it auto-populates purely from truth and is
   the most intuitive surface, but it is empty on a fresh install and needs a new
   cross-session aggregate. It layers on top of this design later.
4. **Permissions matrix** — CHOSEN. Every tool an agent could call, auto-populated, each
   with its **real, server-resolved** status; a three-way control only where the policy is
   genuinely three-way.

---

## 3. Trust model (the load-bearing part)

**A matrix override can only move the POLICY verdict.** `internal.rs::decide_tool_call`
evaluates budget → frozen-capability availability → trust tier → policy → approvals. An
override lives at the policy layer, so it **cannot** defeat:

- **Trust tier** — fork-PR `TrustTier::ReadOnly` is enforced by `policy::read_only_denial`
  *above* policy. No override re-arms a fork PR.
- **Frozen-capability availability** — a tool absent from `RunSpec.capabilities` is
  unavailable whatever the policy says (the rug-pull defence).
- **Budgets** — the ceiling is checked first.

**Conditional rules are never editable.** `evaluate()` takes a `ToolCallRequest` *with
input*, not a tool name. In the seed policy:

```yaml
- match: ["Edit", "Write", "MultiEdit"]
  action: allow
  paths: { allow: ["/workspace/**"], deny: ["**/.env", "**/.git/config"] }
- match: ["Bash", "BashOutput", "KillShell"]
  action: allow
  shell: { on_no_match: approve }
```

"Edit → Allow" is **false** (it is allow-in-`/workspace`, deny-for-`.env`, ask-elsewhere);
"Bash → Allow" is **false** (allow for known-safe prefixes, ask otherwise). A three-way
control cannot represent these, and offering one would let a single click delete
`paths.deny: **/.env`. Therefore rows whose matching rule carries `paths` or `shell`
render **read-only, with their constraints stated**. The three-way control appears only
where the rule is unconditional — which is exactly where the need is: `mcp__*` rules carry
no paths/shell, so every MCP tool is individually controllable.

**The authored YAML is never rewritten.** Overrides live in their own column; `yaml_source`
is untouched by the UI forever. Git keeps owning the base rules (history, review,
comments); the UI owns per-tool overrides. The two never contend, so `policy-sync` needs no
change.

**In-flight runs are unaffected.** `RunSpec` freezes a policy snapshot at session creation;
an override changes **future** runs only.

---

## 4. Design

### 4.1 Objects

Migration `0010_policy_managed_overrides.sql` (0010 is free — the reverted catalog-import
trial that briefly held it was fully rolled back on 2026-07-14; latest applied is 0009):

```sql
alter table policies add column managed_overrides jsonb not null default '[]'::jsonb;
```

> `sqlx::migrate!("../../migrations")` bakes the migration files in at **compile** time, so
> adding the file does not trigger a rebuild on its own. `touch crates/fluidbox-db/src/lib.rs`
> (the `migrate!` call site) before rebuilding, or the server runs the old baked set.

```rust
// fluidbox-core::policy
pub struct ToolOverride { pub tool: String, pub action: RuleAction }

pub struct Policy {
    // …existing…
    /// UI-owned, per-tool decisions. Consulted BEFORE `tools`. Never authored in YAML.
    #[serde(default)]
    pub managed_overrides: Vec<ToolOverride>,
}
```

`managed_overrides` is `#[serde(default)]` so every existing stored `parsed` value and
every authored YAML deserialises unchanged.

Uniqueness: at most one override per exact tool name; a write upserts by `tool`.
Overrides match **exact tool names only** — no wildcards. A wildcard override would be an
un-reviewable blanket rule authored by a click.

### 4.2 The canonical vocabulary becomes data

`fluidbox-core::tools`:

```rust
pub struct ToolDef { pub name: &'static str, pub group: ToolGroup }
pub enum ToolGroup { Files, Shell, Web, Search, Meta }
```

The list is exactly the vocabulary the seed policy already governs — enumerated, not
illustrative:

| Group | Tools |
|---|---|
| `Files` | `Read`, `Write`, `Edit`, `MultiEdit`, `NotebookRead`, `NotebookEdit` |
| `Search` | `Glob`, `Grep`, `LS` |
| `Shell` | `Bash`, `BashOutput`, `KillShell` |
| `Web` | `WebFetch`, `WebSearch` |
| `Meta` | `TodoWrite`, `Task` |

Adding a harness that emits a new canonical name means adding it here — and the drift test
(§6) fails until you do, which is the point.

This is not a convenience list. The canonical tool vocabulary is already a **contract**
every harness must implement (CLAUDE.md: names/shapes crossing `/permission` MUST be
`Bash{command}`, `Edit/Write/MultiEdit{file_path|edits[].file_path}`, `Read/Glob/Grep/LS`,
`mcp__<server>__<tool>`). Encoding a contract as data makes it enumerable and testable
instead of a comment. It lives in **core**, not `harness.rs`, because it is
harness-*independent* — `harness.rs` stays the registry of harness *specifics*
(image/model defaults, env extras) per §17 #8.

MCP tools are **not** in the registry: they come from the photographed bundles (§4.4).

### 4.3 `tool_matrix()` — the static analysis

```rust
pub enum ToolStatus {
    Unconditional { action: RuleAction, rule: Option<usize> },
    Conditional   { action: RuleAction, rule: usize, constraints: ConstraintSummary },
    Default       { action: RuleAction },      // no rule matched → defaults.tool_action
    Overridden    { action: RuleAction, underlying: Box<ToolStatus> },
}

impl Policy {
    pub fn tool_matrix(&self, tools: &[String]) -> Vec<(String, ToolStatus)>;
    pub fn autonomy_summary(&self) -> AutonomySummary;
}
```

`tool_matrix` reuses `tool_matches` — the same matcher `evaluate_supervised` uses — so the
page and the gate can never disagree about which rule wins. A rule is `Conditional` iff it
carries `paths` or `shell`; `ConstraintSummary` carries the globs / prefixes / regexes /
`on_no_match` for display only.

```rust
pub struct AutonomySummary {
    pub permitted: bool,
    pub default_fallback: AutonomousFallback,
    pub allow_overrides: usize,
    pub deny_overrides: usize,
}
```

`*_overrides` count only rules that can actually reach `RequireApproval`, mirroring
`apply_rule`:

```rust
rule.action == RuleAction::Approve
  || rule.shell.as_ref().is_some_and(|s| s.on_no_match == RuleAction::Approve)
```

A rule carrying `on_autonomous` under an unconditional `allow`/`deny` action is dead config
and is not counted — counting it would claim an exception that can never fire. The seed
policy's `Bash` rule (`action: allow` + `shell.on_no_match: approve`) is exactly why the
naive `action == Approve` test is wrong: it would miss an `on_autonomous` added there,
undercounting in the dangerous direction.

### 4.4 Which tools the page shows

- Every `CANONICAL` tool, grouped.
- Every `mcp__<server>__<tool>` from the capability bundles pinned on the **latest
  revision** of each agent whose latest revision uses this policy (union, grouped by server).
  This is what makes the Cloudflare tools appear without anyone typing them.
- A trailing "Anything else → `defaults.tool_action`" row, because the policy has a verdict
  for tools nobody enumerated.

### 4.5 Evaluation change

`evaluate_supervised` consults `managed_overrides` before `tools`:

```rust
fn evaluate_supervised(&self, req: &ToolCallRequest) -> (Verdict, Option<usize>) {
    if let Some(o) = self.managed_overrides.iter().find(|o| o.tool == req.tool) {
        return (self.finish(o.action, None, &req.tool, None), None);
    }
    // …existing first-match-wins over self.tools…
}
```

An override is unconditional by construction (exact name, flat action), so it needs no
rule index and cannot carry paths/shell. `matched_rule = None` means an overridden tool's
autonomy fallback resolves to the policy default — correct: the override replaced the rule,
so the rule's `on_autonomous` no longer applies.

### 4.6 API

| Route | Change |
|---|---|
| `GET /v1/policies` | + `autonomy_summary`, + `agents_using` per policy |
| `GET /v1/policies/{name}` | **new** — detail + `tool_matrix` + constraints + budgets/approvals/egress |
| `PUT /v1/policies/{name}/overrides/{tool}` | **new** — `{action}`; upsert one override |
| `DELETE /v1/policies/{name}/overrides/{tool}` | **new** — clear one override |

Writes validate that `tool` is a known tool (CANONICAL or a bundle-photographed `mcp__*`
name for this policy's agents) and that its current status is **not** `Conditional`. Both
are refused with `400` — the server enforces the rule the UI renders, never the UI alone.

Each write recomputes `parsed` (= base ++ overrides) and bumps `version`. Version++ per
click is honest, if noisy.

### 4.7 `upsert_policy` must merge overrides — the one place this bites

`upsert_policy` currently rebuilds `parsed` from YAML alone. It must now read the existing
`managed_overrides` and merge them into `parsed`, or **the next `just policy-sync` silently
drops every override**. This is the single sharp edge of the separate-column design and
gets an explicit regression test (§6).

### 4.8 Dashboard (presentation-only)

`/governance` — policy list: name, version, `agents_using`, autonomy at a glance.
`/governance/[name]` — the page:

- **Autonomy** — permitted, fallback, overrides (from `autonomy_summary`).
- **What agents may do** — the matrix, grouped Files / Shell / Web / Search & meta, then
  one group per MCP server. Row states:
  - `Unconditional` → live three-way control (Allow / Ask / Deny).
  - `Overridden` → the chosen action + a one-click clear; the affordance *is* the undo.
  - `Conditional` → read-only, constraints stated ("Allowed in /workspace · asks elsewhere
    · never .env").
  - `Default` → the trailing catch-all row.
- **Budgets · Approvals · Egress** — read-only display.
- A permanent header: **"Changes affect future runs of all N agents on this policy."**
  Given a click applies immediately and globally, that is not decoration — it is the one
  fact a click-to-apply control owes the user.

The dashboard **never parses YAML** and never resolves policy semantics: the server sends
`parsed` + `tool_matrix` + `autonomy_summary`; the browser renders them. This is what keeps
"everything flows in dynamically" compatible with the presentation-only constraint. A JS
YAML parser or a client-side fallback computation would fork the meaning of the policy
language away from `policy.rs`.

### 4.9 What does NOT change

`RunSpec` and its frozen policy snapshot; `decide_tool_call`'s order; `run_service`;
`policy-sync.sh`; `yaml_source`; the `/policies` upsert + validate contract; the run
wizard (its radio-card fix is a separate spec that will consume `autonomy_summary`).

---

## 5. Threat table (delta)

| Threat | Mitigation |
|---|---|
| A click flattens a conditional rule, deleting `paths.deny: **/.env` | `Conditional` rows are read-only in the UI **and** refused server-side (§4.6) |
| An override re-arms a fork PR | Trust tier is enforced above policy (`read_only_denial`); overrides move only the policy verdict |
| An override resurrects a rug-pulled / unattached tool | Frozen-capability availability is checked above policy |
| An override escapes the budget ceiling | Budget is checked first in `decide_tool_call` |
| A blanket wildcard override authored by a click | Overrides are exact-name only (§4.1) |
| `policy-sync` silently drops overrides | `upsert_policy` merges them; regression test (§6) |
| An override silently changes a running run | `RunSpec` froze the snapshot; overrides affect future runs only |
| UI drifts from the gate about which rule wins | `tool_matrix` reuses `tool_matches`, the gate's own matcher |

---

## 6. Testing

`fluidbox-core` (no DB), against the **real seed policy** — a good fixture because it
exercises every case:

- `Read → Unconditional(allow)`; `WebFetch → Unconditional(deny)`; `mcp__* → Unconditional(approve)`
- `Edit → Conditional(paths)`; `Bash → Conditional(shell on_no_match)`
- unknown tool → `Default(approve)` (`defaults.tool_action`)
- `autonomy_summary(seed) == {permitted: true, default_fallback: deny, 0, 0}`
- the `Bash`-rule shape (`action: allow` + `shell.on_no_match: approve` + `on_autonomous: allow`) → **counted**
- dead config (`action: allow`, no shell, `on_autonomous: allow`) → **not counted**
- an override beats its general rule (`evaluate` returns the override's action)
- an override cannot be `Conditional` (write-path validation)
- **drift test**: every `match` name in `policies/*.yaml` is in `CANONICAL` or is an
  `mcp__*` pattern — this keeps the vocabulary contract honest as harnesses change

`fluidbox-db` (real Neon): `upsert_policy` **preserves `managed_overrides`** (the
policy-sync drop scenario).

`just check` covers the web build.

---

## 7. Decisions settled at this boundary (§17 addendum)

**#10. How the dashboard edits governance without owning the policy language.** — SETTLED
2026-07-14.

1. **Matrix, not YAML.** The dashboard exposes per-tool Allow/Ask/Deny, auto-populated from
   the server-resolved status of every tool the agent could call. Path globs and the shell
   classifier are security engineering, not user config, and are never editable from the UI.
2. **Overrides are a separate column, not YAML.** `policies.managed_overrides` is UI-owned;
   `yaml_source` stays git-owned and is never rewritten. This dissolves the
   repo-vs-DB ownership contention structurally — `policy-sync` keeps force-pushing base
   rules while overrides survive — instead of settling it by decree.
3. **Overrides precede `tools` in first-match-wins, exact-name only.** An explicit per-tool
   decision beats the general rules by construction, with no reordering of authored rules
   and no click-authored wildcards.
4. **The matrix moves only the policy verdict.** Trust tier, budgets, and frozen-capability
   availability all sit above policy in `decide_tool_call` and are unreachable from the UI.

Deferred: ledger enrichment ("seen 12× · you approved 4") — additive, needs a
cross-session aggregate; policy history/rollback — `policies` is one mutable row, so real
versioning is a schema change.
