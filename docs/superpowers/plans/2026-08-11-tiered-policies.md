# Tiered Seed Policies Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship three named seed policies — `open`, `standard`, `governed` — that reach every environment: fresh deployments via the boot seeder, existing databases via a migration, and future orgs via org-creation seeding.

**Architecture:** The YAML files under `policies/` are the single source of truth, parsed by the real `Policy::parse_yaml`. Migration `0029` backfills the same documents into tenants that already exist, using the audited `system_worker` bypass. A drift-guard test asserts the migration's embedded jsonb equals the parsed YAML, so the two can never disagree silently.

**Tech Stack:** Rust (`fluidbox-core` policy engine, `fluidbox-db` seeding), sqlx migrations, PostgreSQL 17 with FORCEd RLS, YAML policy documents.

## Global Constraints

- **Never edit an applied migration.** sqlx checksums them; editing one requires recreating every local database AND rebuilding the server binary. `0029` is a new file.
- **The migration must set `fluidbox.bypass`.** A migration connection carries no tenant GUC, so `insert … select … from tenants` without it touches **zero rows silently**.
- **`policy_versions.author` CHECK permits only** `seed|api|ui|import`. Use `'seed'`.
- **`policy_versions.version` CHECK requires `> 0`.** Use `1`.
- **Do not modify `default`,** `policies/default.yaml`, or the `seed_policy_semantics` test.
- **Uniqueness:** `policies_tenant_id_name_key` on `(tenant_id, name)` — this is the `on conflict` target.
- Run `cargo test -p fluidbox-core` for Task 1; `cargo test -p fluidbox-db` needs `DATABASE_URL` (`set -a; source .env; set +a`) and the local container Postgres.

---

## File Structure

| File | Responsibility |
|---|---|
| `policies/open.yaml` | the unrestricted tier (create) |
| `policies/standard.yaml` | the everyday tier (create) |
| `policies/governed.yaml` | the read-mostly tier (create) |
| `crates/fluidbox-core/src/policy.rs` | add tier tests beside `seed_policy_semantics` (modify, tests module ~line 1413) |
| `migrations/0029_tiered_policies.sql` | backfill existing tenants (create) |
| `crates/fluidbox-db/src/seed.rs` | expose the parsed tier set for reuse (modify) |
| `crates/fluidbox-server/src/admin_orgs.rs` | seed tiers on org creation (modify) |

---

### Task 1: The three policy documents + semantics test

**Files:**
- Create: `policies/open.yaml`, `policies/standard.yaml`, `policies/governed.yaml`
- Modify: `crates/fluidbox-core/src/policy.rs` (tests module)

**Interfaces:**
- Consumes: `Policy::parse_yaml(&str) -> Result<Policy, _>`, `RuleAction::{Allow, Approve, Deny}`, `NetworkGrantMode::{Offline, Approved, Public}`
- Produces: three YAML files at `policies/`, read by later tasks via `concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/<name>.yaml")`

- [ ] **Step 1: Write the failing test**

Add to the `mod tests` block in `crates/fluidbox-core/src/policy.rs`, beside `seed_policy_semantics`:

```rust
/// The three tiers ship as data, so their SEMANTICS are pinned here — not the
/// bytes. A tier that stops differing from its neighbours has stopped being a
/// tier. Paths resolve from this crate to the repo root.
#[test]
fn tiered_seed_policy_semantics() {
    let open = Policy::parse_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../policies/open.yaml"))).unwrap();
    let standard = Policy::parse_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../policies/standard.yaml"))).unwrap();
    let governed = Policy::parse_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../policies/governed.yaml"))).unwrap();

    assert_eq!(open.name, "open");
    assert_eq!(standard.name, "standard");
    assert_eq!(governed.name, "governed");

    // The fallback verdict IS the tier's spine.
    assert_eq!(open.defaults.tool_action, RuleAction::Allow);
    assert_eq!(standard.defaults.tool_action, RuleAction::Approve);
    assert_eq!(governed.defaults.tool_action, RuleAction::Deny);

    // Autonomy narrows as the tier tightens; governed forbids it outright.
    assert!(open.autonomy.permitted);
    assert!(standard.autonomy.permitted);
    assert!(!governed.autonomy.permitted);

    // Network ceiling per tier.
    assert_eq!(open.network.max_mode, crate::network::NetworkGrantMode::Public);
    assert!(open.network.allow_public_with_brokered);
    assert_eq!(standard.network.max_mode, crate::network::NetworkGrantMode::Approved);
    assert!(standard.network.allow.is_empty(),
        "approved mode stays inert until an operator populates the catalog");
    assert_eq!(governed.network.max_mode, crate::network::NetworkGrantMode::Offline);

    // Spend ceilings exist on every tier — `open` is unrestricted in AUTHORITY,
    // not in spend. Measured, not assumed: `open` omits max_tokens and
    // max_tool_calls, and this asserts what serde actually does with that.
    assert_eq!(open.budgets.max_cost_usd, Some(25.0));
    assert_eq!(open.budgets.max_wall_clock_secs, Some(7200));
    assert_eq!(standard.budgets.max_cost_usd, Some(5.0));
    assert_eq!(governed.budgets.max_cost_usd, Some(1.0));
    assert!(governed.budgets.max_cost_usd < standard.budgets.max_cost_usd);
    assert!(standard.budgets.max_cost_usd < open.budgets.max_cost_usd);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p fluidbox-core tiered_seed_policy_semantics`
Expected: FAIL — compile error, the three YAML files do not exist yet (`include_str!` cannot resolve them).

- [ ] **Step 3: Create `policies/open.yaml`**

```yaml
# The UNRESTRICTED tier: trusted internal automation, never untrusted input.
#
# `defaults.tool_action: allow` means there is nothing for a rule to add, which
# is why `tools` is empty rather than omitted-by-oversight.
#
# ACCEPTED RISK, stated because it is a real one: this tier allows
# Agent/Task/Workflow/Skill. `default` denies those as a SECURITY decision, not
# ergonomics — nested tool calls may never surface as top-level tool_use blocks,
# so they may reach neither the gate nor the GateWitness tripwire. One allow
# here authorises an unobserved tool tree. That is this tier's purpose.
#
# Budgets are RETAINED on purpose. They are a runaway stop, not a restriction on
# the agent's authority. Omitting them moves the failure from a clean
# budget_exceeded terminal state to a hard 429 from LiteLLM's per-tenant cap.
name: open
defaults:
  tool_action: allow
egress:
  mode: proxy-only
network:
  max_mode: public
  allow_public_with_brokered: true
budgets:
  max_cost_usd: 25
  max_wall_clock_secs: 7200
approvals:
  default_ttl_secs: 600
  scope: session
  timeout_action: deny
autonomy:
  permitted: true
  on_approval_rule: allow
tools: []
```

- [ ] **Step 4: Create `policies/standard.yaml`**

The `allow_prefixes` and `deny_regex` below are a byte-for-byte copy of the
`Bash` rule in `policies/default.yaml`. That classifier is ledger-derived from
real runs; do not "improve" it here.

```yaml
# The EVERYDAY tier. Mirrors the shipped `default` posture, with two deliberate
# differences: network `approved` mode is available (inert until an operator
# populates the catalog), and budgets are tighter.
name: standard
defaults:
  tool_action: approve
egress:
  mode: proxy-only
network:
  max_mode: approved
  require_approval: true
budgets:
  max_wall_clock_secs: 3600
  max_tokens: 2000000
  max_cost_usd: 5
  max_tool_calls: 200
approvals:
  default_ttl_secs: 600
  scope: once
  timeout_action: deny
autonomy:
  permitted: true
  on_approval_rule: deny
tools:
  - match:
      ["Read", "Glob", "Grep", "LS", "TodoWrite", "NotebookRead", "ToolSearch",
       "EnterPlanMode", "ExitPlanMode", "AskUserQuestion", "ReportFindings",
       "TaskGet", "TaskList", "TaskOutput", "CronList"]
    action: allow

  - match: ["Agent", "Task", "Workflow", "Skill", "TaskCreate"]
    action: deny
    risk: spawns sub-execution whose nested tool calls the gate may never see

  - match: ["Edit", "Write", "MultiEdit", "NotebookEdit"]
    action: allow
    paths:
      allow: ["/workspace/**"]
      deny: ["**/.env", "**/.env.*", "**/.git/config", "**/.git/hooks/**"]

  - match: ["Bash", "BashOutput", "KillShell"]
    action: allow
    shell:
      allow_prefixes:
        - "ls"
        - "cat"
        - "head"
        - "tail"
        - "wc"
        - "grep"
        - "rg"
        - "find"
        - "pwd"
        - "echo"
        - "which"
        - "env | grep"
        - "python"
        - "python3"
        - "pytest"
        - "pip install -r"
        - "node"
        - "npm test"
        - "npm run test"
        - "npx jest"
        - "npx vitest"
        - "cargo test"
        - "cargo build"
        - "cargo check"
        - "go test"
        - "make test"
        - "git status"
        - "git diff"
        - "git log"
        - "git add"
        - "git commit"
        - "git show"
        - "cd"
        - "mkdir"
        - "touch"
        - "mv"
        - "cp"
        - "sed"
        - "awk"
        - "diff"
        - "sort"
        - "uniq"
        - "cut"
        - "tr"
        - "stat"
        - "file"
        - "du"
        - "printf"
        - "basename"
        - "dirname"
        - "date"
      deny_regex:
        - "rm\\s+(-[a-z]+\\s+)*-[a-z]*r[a-z]*(\\s+-[a-z]+)*\\s+/\\*?(\\s|$)"
        - "\\bcurl\\b"
        - "\\bwget\\b"
        - "\\bnc\\b"
        - "\\bssh\\b"
        - "\\bscp\\b"
        - "git\\s+push\\b.*\\s(--force(-with-lease)?|-f)\\b"
        - "\\bsudo\\b"
        - "/etc/passwd"
        - "\\bchmod\\s+777\\b"
      on_no_match: approve

  - match: ["WebFetch", "WebSearch", "DesignSync", "Monitor"]
    action: deny
    risk: network egress from sandbox

  - match:
      ["TaskStop", "TaskUpdate", "SendMessage", "CronCreate", "CronDelete",
       "ScheduleWakeup", "PushNotification", "EnterWorktree", "ExitWorktree"]
    action: approve
    risk: effect outside this run's disposable workspace

  - match: ["mcp__*"]
    action: approve
    risk: unreviewed MCP tool
```

- [ ] **Step 5: Create `policies/governed.yaml`**

```yaml
# The READ-MOSTLY tier. Writes need a human, autonomy is forbidden, the network
# is offline, and the fallback is DENY rather than approve.
#
# KNOWN CONSEQUENCE, by design: `defaults.tool_action: deny` refuses any tool not
# listed below — including tools a future CLI upgrade introduces. That is the
# intended failure direction, but it is a standing maintenance obligation.
name: governed
defaults:
  tool_action: deny
egress:
  mode: proxy-only
network:
  max_mode: offline
budgets:
  max_wall_clock_secs: 900
  max_tokens: 300000
  max_cost_usd: 1.0
  max_tool_calls: 40
approvals:
  default_ttl_secs: 300
  scope: once
  timeout_action: deny
autonomy:
  permitted: false
  on_approval_rule: deny
tools:
  - match:
      ["Read", "Glob", "Grep", "LS", "TodoWrite", "NotebookRead",
       "EnterPlanMode", "ExitPlanMode", "AskUserQuestion"]
    action: allow

  - match: ["Edit", "Write", "MultiEdit", "NotebookEdit"]
    action: approve
    risk: writes require a human under the governed tier
    paths:
      allow: ["/workspace/**"]
      deny: ["**/.env", "**/.env.*", "**/.git/config", "**/.git/hooks/**"]

  - match: ["Bash", "BashOutput", "KillShell"]
    action: allow
    shell:
      allow_prefixes:
        - "ls"
        - "cat"
        - "head"
        - "tail"
        - "wc"
        - "grep"
        - "rg"
        - "find"
        - "pwd"
        - "git status"
        - "git diff"
        - "git log"
      deny_regex:
        - "\\bcurl\\b"
        - "\\bwget\\b"
        - "\\bnc\\b"
        - "\\bssh\\b"
        - "\\bscp\\b"
        - "\\bsudo\\b"
        - "/etc/passwd"
      on_no_match: deny

  - match: ["mcp__*"]
    action: approve
    risk: unreviewed MCP tool
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test -p fluidbox-core tiered_seed_policy_semantics`
Expected: PASS.

If `open.budgets.max_tokens` behaves differently than assumed, the assertions on
`max_cost_usd`/`max_wall_clock_secs` still hold — but **record the observed
value of `max_tokens` in a comment** rather than deleting a check. The spec
flagged this as measured-not-assumed.

- [ ] **Step 7: Write the verdict-divergence test**

The tiers must produce DIFFERENT verdicts, or they are decoration. Add beside
the test from Step 1:

```rust
/// Three tiers that agree on every call are one tier with three names.
#[test]
fn tiers_diverge_on_the_calls_that_matter() {
    let open = Policy::parse_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../policies/open.yaml"))).unwrap();
    let standard = Policy::parse_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../policies/standard.yaml"))).unwrap();
    let governed = Policy::parse_yaml(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../policies/governed.yaml"))).unwrap();

    // An unlisted tool: the fallback, which is the whole point of the ladder.
    assert_eq!(open.defaults.tool_action, RuleAction::Allow);
    assert_eq!(standard.defaults.tool_action, RuleAction::Approve);
    assert_eq!(governed.defaults.tool_action, RuleAction::Deny);

    // `open` carries no rules at all — the default is what allows everything.
    assert!(open.tools.is_empty());

    // Sub-execution and writes: find the governing rule per tier by tool name.
    // NOTE: adjust the match-field accessor to whatever `ToolRule` actually
    // names it (see Step 8) — do NOT change the YAML to fit the accessor.
    let rule_for = |p: &Policy, tool: &str| p.tools.iter()
        .find(|r| r.match_.iter().any(|m| m == tool))
        .map(|r| r.action);

    assert_eq!(rule_for(&standard, "Agent"), Some(RuleAction::Deny));
    assert_eq!(rule_for(&governed, "Agent"), None,
        "governed lists no Agent rule; defaults.tool_action=deny covers it");

    assert_eq!(rule_for(&standard, "Write"), Some(RuleAction::Allow));
    assert_eq!(rule_for(&governed, "Write"), Some(RuleAction::Approve));
    assert_eq!(rule_for(&open, "Write"), None, "open needs no rule; the default allows");
}
```

- [ ] **Step 8: Fix the match-field accessor**

Open `crates/fluidbox-core/src/policy.rs` and find the `ToolRule` struct. The
field holding the tool-name list is written `match:` in YAML, which is a Rust
keyword, so the struct names it something else (commonly `r#match`, or a plain
identifier with `#[serde(rename = "match")]`). Use whatever it actually is in
both closures above. This is the one accessor the plan could not pre-verify.

- [ ] **Step 9: Run both tests**

Run: `cargo test -p fluidbox-core policy::tests::`
Expected: PASS, including the untouched `seed_policy_semantics`.

- [ ] **Step 10: Commit**

```bash
git add policies/open.yaml policies/standard.yaml policies/governed.yaml crates/fluidbox-core/src/policy.rs
git commit -m "feat(policy): add open, standard, and governed seed policy tiers"
```

---

### Task 2: Migration 0029 + drift guard

**Files:**
- Create: `migrations/0029_tiered_policies.sql`
- Modify: `crates/fluidbox-core/src/policy.rs` (drift-guard test)

**Interfaces:**
- Consumes: the three YAML files from Task 1
- Produces: rows in `policies` + `policy_versions` for every pre-existing tenant

- [ ] **Step 1: Generate the exact jsonb from the parser**

Do NOT hand-write the jsonb. Generate it, so it matches the serde shape by
construction. Add a temporary test in `crates/fluidbox-core/src/policy.rs`:

```rust
#[test]
#[ignore] // temporary: run explicitly to emit the migration literals
fn emit_tier_json() {
    for (name, src) in [
        ("open",     include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/open.yaml"))),
        ("standard", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/standard.yaml"))),
        ("governed", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/governed.yaml"))),
    ] {
        let p = Policy::parse_yaml(src).unwrap();
        println!("{name}\t{}", serde_json::to_string(&p).unwrap());
    }
}
```

Run: `cargo test -p fluidbox-core emit_tier_json -- --ignored --nocapture`
Copy the three one-line JSON strings. **Delete this temporary test before committing Task 2.**

- [ ] **Step 2: Write the migration**

Each tier's JSON goes on ONE line — the drift guard in Step 3 scans line-wise.
Single quotes inside JSON must be doubled for SQL (`''`); the tier documents
contain none today, but check the emitted strings.

```sql
-- Tiered seed policies (design docs/superpowers/specs/2026-08-11-tiered-policies-design.md).
--
-- Backfill ONLY. `policies/*.yaml` is the source of truth and the boot seeder
-- covers every FRESH deployment; this file covers databases that already exist
-- and will never re-run a fresh seed. The two must agree, and
-- `migration_0029_jsonb_matches_the_yaml` in fluidbox-core asserts the jsonb
-- below equals the parsed YAML.
--
-- WHY THE BYPASS: a migration connection carries NO tenant GUC, and `policies`
-- is ENABLE+FORCE RLS keyed on current_setting('fluidbox.tenant_id'). Without
-- the audited system-worker bypass the insert below would touch ZERO rows —
-- silently. That is an empty backfill, not an error, which is the failure mode
-- worth the one line. Transaction-local: sqlx runs each migration in one tx.
set local fluidbox.bypass = 'system_worker';

-- Additive: creates rows, drops nothing, alters no column. Unlike 0018/0026
-- this needs NO stop-the-old-binary posture — an older binary sees extra rows
-- in tables it already understands. Normal rolling deploy.
with tiers(name, content) as (
  values
    ('open', '<OPEN JSON FROM STEP 1>'::jsonb),
    ('standard', '<STANDARD JSON FROM STEP 1>'::jsonb),
    ('governed', '<GOVERNED JSON FROM STEP 1>'::jsonb)
),
created as (
  insert into policies (id, tenant_id, name)
  select gen_random_uuid(), t.id, tiers.name
    from tenants t cross join tiers
  on conflict (tenant_id, name) do nothing
  returning id, tenant_id, name
)
insert into policy_versions (id, tenant_id, policy_id, version, content, yaml_source, summary, author)
select gen_random_uuid(), c.tenant_id, c.id, 1, tiers.content, null,
       'seeded tier: ' || c.name, 'seed'
  from created c join tiers on tiers.name = c.name;
```

Only policies this migration CREATED get a version row — `created` returns rows
solely for successful inserts, so a tenant that already had a policy of that
name is left completely alone.

- [ ] **Step 3: Write the drift-guard test**

In `crates/fluidbox-core/src/policy.rs` tests:

```rust
/// The migration embeds jsonb that nothing validates against the serde shape.
/// A mismatch does not fail at migration time — it fails at create_run, AFTER
/// the run is provisioned. So pin them together here.
#[test]
fn migration_0029_jsonb_matches_the_yaml() {
    let sql = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"), "/../../migrations/0029_tiered_policies.sql"));
    for (name, src) in [
        ("open",     include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/open.yaml"))),
        ("standard", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/standard.yaml"))),
        ("governed", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/governed.yaml"))),
    ] {
        let expected = serde_json::to_value(&Policy::parse_yaml(src).unwrap()).unwrap();

        // Each tier is ONE line: ('<name>', '<json>'::jsonb),
        let prefix = format!("('{name}', '");
        let line = sql.lines()
            .map(str::trim)
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("migration 0029 has no single-line VALUES row for {name}"));
        let body = &line[prefix.len()..];
        let end = body.find("'::jsonb")
            .unwrap_or_else(|| panic!("{name} literal must be cast ::jsonb on the same line"));
        let literal = body[..end].replace("''", "'");

        let actual: serde_json::Value = serde_json::from_str(&literal)
            .unwrap_or_else(|e| panic!("{name} jsonb in 0029 is not valid JSON: {e}"));
        assert_eq!(actual, expected,
            "migration 0029's {name} jsonb has drifted from policies/{name}.yaml");
    }
}
```

- [ ] **Step 4: Run the drift guard**

Run: `cargo test -p fluidbox-core migration_0029`
Expected: PASS. If it fails, the JSON in the migration is wrong — regenerate it from Step 1, never hand-edit toward the test.

- [ ] **Step 5: Delete the temporary emitter and run the suite**

Remove `emit_tier_json`, then run: `cargo test -p fluidbox-core policy::tests::`
Expected: PASS.

- [ ] **Step 6: Apply against the local database and verify**

```bash
set -a; source .env; set +a
cargo run -p fluidbox-server > /tmp/mig.log 2>&1 &
sleep 25 && kill %1
psql "$DATABASE_URL" -Atc "
  select t.slug, count(p.id) from tenants t
  join policies p on p.tenant_id = t.id and p.name in ('open','standard','governed')
  where t.slug in ('default','local') group by t.slug order by t.slug"
```

Expected: `default|3` and `local|3`.

- [ ] **Step 7: Verify idempotency and that `default` was untouched**

Boot the server a second time, then:

```bash
psql "$DATABASE_URL" -Atc "select count(*) from policies where name in ('open','standard','governed')"
psql "$DATABASE_URL" -Atc "
  select p.name, count(pv.id) from policies p
  join policy_versions pv on pv.policy_id = p.id
  where p.name = 'default' group by p.name"
```

Expected: the first count is unchanged from Step 6; the second is `default|1`.

- [ ] **Step 8: Commit**

```bash
git add migrations/0029_tiered_policies.sql crates/fluidbox-core/src/policy.rs
git commit -m "feat(db): backfill tiered policies into existing tenants (0029)"
```

---

### Task 3: Seed the tiers on org creation

**Files:**
- Modify: `crates/fluidbox-db/src/seed.rs`
- Modify: `crates/fluidbox-db/src/lib.rs` (tests module)
- Modify: `crates/fluidbox-server/src/admin_orgs.rs`

**Interfaces:**
- Consumes: `fluidbox_db::seed_policy_if_absent(pool: &PgPool, scope: TenantScope, name: &str, yaml_source: &str, parsed: &Value) -> sqlx::Result<(PolicyRow, bool)>`; `fluidbox_db::identity::create_org(pool: &PgPool, slug: &str, display_name: Option<&str>) -> sqlx::Result<OrgRow>`; `TenantScope::assume(Uuid)`
- Produces: `seed::TIER_DOCUMENTS: &[(&str, &str)]` and `seed::seed_tiers_for_tenant(&PgPool, TenantScope) -> anyhow::Result<()>`

- [ ] **Step 1: Expose the tier documents from `seed.rs`**

```rust
/// The tier documents, compiled in. Org creation must NOT read `policies/` from
/// disk: that would couple an API request to a readable directory on whichever
/// replica served it, and fail differently there than at boot.
pub const TIER_DOCUMENTS: &[(&str, &str)] = &[
    ("open",     include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/open.yaml"))),
    ("standard", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/standard.yaml"))),
    ("governed", include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../policies/governed.yaml"))),
];
```

- [ ] **Step 2: Write the failing test**

In `crates/fluidbox-db/src/lib.rs` tests (self-skips without `DATABASE_URL` — follow the existing `test_pool()` convention in that module):

```rust
/// A new org with zero policies fails closed at create_run AFTER provisioning.
/// Every org must be usable the moment it exists.
#[tokio::test]
async fn new_org_gets_the_seed_policies() {
    let pool = match test_pool().await { Some(p) => p, None => return };
    let slug = format!("t-{}", Uuid::now_v7().simple());
    let org = crate::identity::create_org(&pool, &slug, Some("test")).await.unwrap();
    let scope = TenantScope::assume(org.id);

    crate::seed::seed_tiers_for_tenant(&pool, scope).await.unwrap();

    for name in ["default", "open", "standard", "governed"] {
        assert!(get_policy_by_name(&pool, scope, name).await.unwrap().is_some(),
            "new org is missing policy '{name}'");
    }

    // Idempotent: a second call must not error or duplicate.
    crate::seed::seed_tiers_for_tenant(&pool, scope).await.unwrap();
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `set -a; source .env; set +a; cargo test -p fluidbox-db new_org_gets_the_seed_policies`
Expected: FAIL — `seed_tiers_for_tenant` does not exist.

- [ ] **Step 4: Implement `seed_tiers_for_tenant`**

In `crates/fluidbox-db/src/seed.rs`:

```rust
/// Seed `default` plus the three tiers into a tenant. Idempotent by way of
/// `seed_policy_if_absent`, so calling it twice is a no-op and a tenant that
/// already has a same-named policy is never overwritten.
pub async fn seed_tiers_for_tenant(
    pool: &PgPool,
    scope: TenantScope,
) -> anyhow::Result<()> {
    let bare = Policy::parse_yaml("name: default")?;
    seed_policy_if_absent(pool, scope, "default", "name: default",
                          &serde_json::to_value(&bare)?).await?;
    for (name, yaml) in TIER_DOCUMENTS {
        let parsed = Policy::parse_yaml(yaml)
            .map_err(|e| anyhow::anyhow!("compiled-in policy '{name}' does not parse: {e}"))?;
        seed_policy_if_absent(pool, scope, name, yaml,
                              &serde_json::to_value(&parsed)?).await?;
    }
    Ok(())
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `set -a; source .env; set +a; cargo test -p fluidbox-db new_org_gets_the_seed_policies`
Expected: PASS.

- [ ] **Step 6: Wire it into the org-creation handler**

In `crates/fluidbox-server/src/admin_orgs.rs`, after the `create_org` call
succeeds, call `fluidbox_db::seed::seed_tiers_for_tenant(&state.pool, TenantScope::assume(org.id))`.

A seeding failure must **NOT** roll back the org: the org exists and is
addressable, so failing the request would leave an operator with an org they
cannot see and cannot re-create (the slug is taken). Log the error at `warn`
naming the org slug, and return the org. Read the surrounding handler for its
existing error/log convention and match it.

- [ ] **Step 7: Verify end to end against the running stack**

```bash
set -a; source .env; set +a
A="Authorization: Bearer $FLUIDBOX_ADMIN_TOKEN"
curl -sS -X POST -H "$A" -H 'content-type: application/json' \
  -d '{"slug":"tier-check","display_name":"Tier Check"}' \
  http://127.0.0.1:8787/v1/admin/orgs
psql "$DATABASE_URL" -Atc "
  select p.name from policies p join tenants t on t.id = p.tenant_id
  where t.slug = 'tier-check' order by p.name"
```

Expected: `default`, `governed`, `open`, `standard`.

- [ ] **Step 8: Confirm the pre-existing `local` org is covered**

```bash
psql "$DATABASE_URL" -Atc "
  select p.name from policies p join tenants t on t.id = p.tenant_id
  where t.slug = 'local' order by p.name"
```

Expected: `governed`, `open`, `standard` — from migration 0029. `default` will
be absent unless separately seeded; 0029 deliberately does not create it. If you
want it, call `seed_tiers_for_tenant` for that tenant once.

- [ ] **Step 9: Full check**

Run: `cargo fmt && cargo clippy --all-targets -- -D warnings && cargo test -p fluidbox-core`
Expected: clean.

- [ ] **Step 10: Commit**

```bash
git add crates/fluidbox-db/src/seed.rs crates/fluidbox-db/src/lib.rs crates/fluidbox-server/src/admin_orgs.rs
git commit -m "fix(orgs): seed default and tiered policies when an org is created"
```

---

## Self-Review

**Spec coverage:** mechanism — Task 1 (YAML) + Task 2 (migration) + Task 3 (create_org) ✓; three tier documents ✓; drift guard ✓; idempotency ✓ (Task 2 Step 7, Task 3 Step 2); RLS bypass ✓; tier divergence ✓; the measured-not-assumed `budgets` question ✓ (Task 1 Step 6).

**Type consistency:** `seed_tiers_for_tenant` and `TIER_DOCUMENTS` are named identically in Task 3's Interfaces block, Step 1, Step 2, Step 4, and Step 6. `Policy::parse_yaml` and `seed_policy_if_absent` match the signatures read from source during planning.

**Known soft spots, called out rather than hidden:**
- Task 1 Step 7 depends on the `ToolRule` match-field accessor, which was not verified during planning; Step 8 exists solely to resolve it, and forbids changing the YAML to fit.
- Task 2 Step 3 parses SQL as text. It is constrained to a one-line-per-tier format that Step 2 mandates, and handles doubled single quotes. Do not weaken the equality assertion to make it pass.
- Task 3 Step 6 defers to the handler's existing error convention rather than inventing one.

**Out of scope (from the spec):** changing `default`; a tier-picker UI; cleaning the 24 fixture policies in the `default` tenant.
