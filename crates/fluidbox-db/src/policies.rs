//! Policy identities and their append-only versions.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::PgPool;
use uuid::Uuid;

/// A policy IDENTITY — the stable thing an `agent_revision` points at. The
/// content lives on append-only [`PolicyVersionRow`]s (migration 0026); the
/// LATEST version governs future runs, and `updated_at` bumps on every append
/// so it keeps meaning "last changed".
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PolicyRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// One immutable policy version (migration 0026). `content` is the canonical
/// Policy document — structure is the source of truth; `yaml_source` is set
/// only when the version arrived AS yaml (seed / `POST /v1/policies`), and
/// export regenerates yaml from `content` otherwise.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PolicyVersionRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub policy_id: Uuid,
    pub version: i32,
    pub content: Value,
    pub yaml_source: Option<String>,
    pub summary: Option<String>,
    /// Provenance channel: 'seed' | 'api' | 'ui' | 'import' (design §3).
    pub author: String,
    /// The authenticated user behind an api/ui version; None for the operator
    /// token, seeds, and the 0026 import (no FK — history outlives users).
    pub author_user_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// A policy identity joined with its latest version — the list payload.
/// `latest_version = 0` / `latest_content = None` means a version-less policy,
/// which is a BUG state (`create_run` fails closed on it); surfacing the zero
/// beats hiding the row.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct PolicySummaryRow {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub latest_version: i32,
    pub latest_content: Option<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The inputs of one appended policy version.
#[derive(Debug, Clone, Copy)]
pub struct NewPolicyVersion<'a> {
    pub content: &'a Value,
    pub yaml_source: Option<&'a str>,
    pub summary: Option<&'a str>,
    /// Provenance channel: 'seed' | 'api' | 'ui' | 'import'.
    pub author: &'a str,
    pub author_user_id: Option<Uuid>,
}

// ─── Policies ─────────────────────────────────────────────────────────────

/// The outcome of an optimistic version append.
#[derive(Debug, Clone)]
pub enum AppendPolicyVersion {
    Appended(PolicyVersionRow),
    /// The head moved past the caller's `expected_base` — nothing was written.
    /// The caller answers 409 and the editor reloads; a post-commit retry of
    /// its own publish lands here too, which is what makes the write safe to
    /// retry (it can duplicate nothing).
    Stale {
        head: i32,
    },
}

/// Append one version inside `tx`. Locks the parent policy row first, which
/// serializes appends per policy so `head + 1` cannot race itself
/// (`unique (policy_id, version)` is the backstop, not the mechanism), then
/// bumps `policies.updated_at` so it keeps meaning "last changed".
///
/// `expected_base` is the optimistic-concurrency guard: when set, the append
/// refuses (writes NOTHING) unless the current head equals it — two editors
/// publishing from the same loaded version cannot silently overwrite each
/// other's intent. `RowNotFound` when the policy is not this tenant's.
pub async fn append_policy_version_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    policy_id: Uuid,
    expected_base: Option<i32>,
    v: NewPolicyVersion<'_>,
) -> sqlx::Result<AppendPolicyVersion> {
    sqlx::query_as::<_, (Uuid,)>(
        "select id from policies where id = $1 and tenant_id = $2 for update",
    )
    .bind(policy_id)
    .bind(tenant_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or(sqlx::Error::RowNotFound)?;
    // `tenant_id` is redundant here — the locked row above already proved this
    // policy is ours, and `policies.id` is globally unique — but every
    // tenant-owned read in this crate carries the predicate so the property
    // stays MECHANICALLY checkable (grep, not argument). Same below and in
    // `import_policy_yaml` / `seed_policy_if_absent`.
    let (head,): (i32,) = sqlx::query_as(
        "select coalesce(max(version), 0)::int from policy_versions
          where policy_id = $1 and tenant_id = $2",
    )
    .bind(policy_id)
    .bind(tenant_id)
    .fetch_one(&mut **tx)
    .await?;
    if let Some(base) = expected_base {
        if head != base {
            return Ok(AppendPolicyVersion::Stale { head });
        }
    }
    let row: PolicyVersionRow = sqlx::query_as(
        "insert into policy_versions
             (id, tenant_id, policy_id, version, content, yaml_source, summary,
              author, author_user_id)
         values ($1, $2, $3, $4, $5, $6, $7, $8, $9)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(policy_id)
    .bind(head + 1)
    .bind(v.content)
    .bind(v.yaml_source)
    .bind(v.summary)
    .bind(v.author)
    .bind(v.author_user_id)
    .fetch_one(&mut **tx)
    .await?;
    sqlx::query("update policies set updated_at = now() where id = $1 and tenant_id = $2")
        .bind(policy_id)
        .bind(tenant_id)
        .execute(&mut **tx)
        .await?;
    Ok(AppendPolicyVersion::Appended(row))
}

/// Append one immutable version to an existing policy (publish / revert).
pub async fn append_policy_version(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
    expected_base: Option<i32>,
    v: NewPolicyVersion<'_>,
) -> sqlx::Result<AppendPolicyVersion> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out =
        append_policy_version_tx(&mut tx, scope.tenant_id(), policy_id, expected_base, v).await?;
    match &out {
        AppendPolicyVersion::Appended(_) => tx.commit().await?,
        // Nothing was written; roll back rather than commit an empty tx.
        AppendPolicyVersion::Stale { .. } => tx.rollback().await?,
    }
    Ok(out)
}

/// Create a policy identity + its version 1 in ONE transaction (clone / blank
/// creation) — a policy with zero versions is a bug, not a state (design
/// §4.2). A duplicate name bubbles as the 23505 unique violation.
pub async fn create_policy(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    v: NewPolicyVersion<'_>,
) -> sqlx::Result<(PolicyRow, PolicyVersionRow)> {
    let mut tx = scoped_tx(pool, scope).await?;
    let out = create_policy_tx(&mut tx, scope.tenant_id(), name, v).await?;
    tx.commit().await?;
    Ok(out)
}

/// [`create_policy`] inside a caller-owned transaction — the recipes deploy
/// engine stamps a policy alongside agents/subscriptions in ONE atomic tx.
pub async fn create_policy_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Uuid,
    name: &str,
    v: NewPolicyVersion<'_>,
) -> sqlx::Result<(PolicyRow, PolicyVersionRow)> {
    let policy: PolicyRow = sqlx::query_as(
        "insert into policies (id, tenant_id, name) values ($1, $2, $3) returning *",
    )
    .bind(Uuid::now_v7())
    .bind(tenant_id)
    .bind(name)
    .fetch_one(&mut **tx)
    .await?;
    let AppendPolicyVersion::Appended(version) =
        append_policy_version_tx(tx, tenant_id, policy.id, None, v).await?
    else {
        unreachable!("expected_base is None: the append cannot be stale");
    };
    Ok((policy, version))
}

/// The YAML import path — the `POST /v1/policies` wire semantics that
/// `scripts/policy-sync.sh` used to POST: ensure the identity row exists, then
/// APPEND `parsed` as a new version (author 'api'). Never replaces content;
/// the retired sync's force-overwrite is exactly what this no longer does.
///
/// Kept under its historical name and signature: ~30 test fixtures build
/// policies through it, and the operation really is "make this yaml the
/// policy's latest".
pub async fn upsert_policy(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<PolicyRow> {
    import_policy_yaml(pool, scope, name, yaml_source, parsed, None)
        .await
        .map(|(row, _, _)| row)
}

/// [`upsert_policy`] with the acting user attributed and the resulting version
/// returned. IDEMPOTENT on content: an import whose canonical content equals
/// the current head appends nothing and answers `(row, head, false)` — a
/// re-run loadgen/CI setup or a doubly-delivered import cannot inflate the
/// history. (Publish/revert deliberately do NOT share this: a human's revert
/// to identical content is an audit event; see `append_policy_version`.)
pub async fn import_policy_yaml(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
    author_user_id: Option<Uuid>,
) -> sqlx::Result<(PolicyRow, PolicyVersionRow, bool)> {
    let mut tx = scoped_tx(pool, scope).await?;
    let policy: PolicyRow = sqlx::query_as(
        "insert into policies (id, tenant_id, name) values ($1, $2, $3)
         on conflict (tenant_id, name) do update set name = excluded.name
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .fetch_one(&mut *tx)
    .await?;
    // Same lock the append takes — the equality check and the append decide
    // under one serialization point, so a racing import cannot double-append.
    sqlx::query_as::<_, (Uuid,)>(
        "select id from policies where id = $1 and tenant_id = $2 for update",
    )
    .bind(policy.id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    let head: Option<PolicyVersionRow> = sqlx::query_as(
        "select * from policy_versions where policy_id = $1 and tenant_id = $2
          order by version desc limit 1",
    )
    .bind(policy.id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if let Some(h) = head {
        if h.content == *parsed {
            tx.commit().await?;
            return Ok((policy, h, false));
        }
    }
    let AppendPolicyVersion::Appended(version) = append_policy_version_tx(
        &mut tx,
        scope.tenant_id(),
        policy.id,
        None,
        NewPolicyVersion {
            content: parsed,
            yaml_source: Some(yaml_source),
            summary: None,
            author: "api",
            author_user_id,
        },
    )
    .await?
    else {
        unreachable!("expected_base is None: the append cannot be stale");
    };
    // The append bumped `policies.updated_at`; answer with the row as COMMITTED,
    // not the pre-append capture.
    let policy: PolicyRow =
        sqlx::query_as("select * from policies where id = $1 and tenant_id = $2")
            .bind(policy.id)
            .bind(scope.tenant_id())
            .fetch_one(&mut *tx)
            .await?;
    tx.commit().await?;
    Ok((policy, version, true))
}

/// Bootstrap a policy from a seed file only if it does not already exist —
/// never clobber UI-authored versions on reboot. An absent policy gets its
/// identity AND version 1 (author 'seed') in one transaction; the row lock in
/// the version append serializes racing replicas, and the zero-versions check
/// under that lock keeps a lost race from minting a duplicate seed version.
pub async fn seed_policy_if_absent(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
    yaml_source: &str,
    parsed: &Value,
) -> sqlx::Result<(PolicyRow, bool)> {
    if let Some(existing) = get_policy_by_name(pool, scope, name).await? {
        return Ok((existing, false));
    }
    let mut tx = scoped_tx(pool, scope).await?;
    let row: PolicyRow = sqlx::query_as(
        "insert into policies (id, tenant_id, name) values ($1, $2, $3)
         on conflict (tenant_id, name) do update set name = excluded.name
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(scope.tenant_id())
    .bind(name)
    .fetch_one(&mut *tx)
    .await?;
    // Racing replica: it may have committed the identity AND v1 between our
    // absence check and this transaction. Lock the policy row (the same lock
    // the version append takes), then mint v1 only if none exists.
    sqlx::query_as::<_, (Uuid,)>(
        "select id from policies where id = $1 and tenant_id = $2 for update",
    )
    .bind(row.id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    let (existing_versions,): (i64,) = sqlx::query_as(
        "select count(*) from policy_versions where policy_id = $1 and tenant_id = $2",
    )
    .bind(row.id)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    if existing_versions == 0 {
        append_policy_version_tx(
            &mut tx,
            scope.tenant_id(),
            row.id,
            None,
            NewPolicyVersion {
                content: parsed,
                yaml_source: Some(yaml_source),
                summary: None,
                author: "seed",
                author_user_id: None,
            },
        )
        .await?;
    }
    tx.commit().await?;
    Ok((row, existing_versions == 0))
}

/// The version that governs future runs: the HIGHEST version number, never the
/// newest `created_at` — a skewed clock must not reorder history.
pub async fn latest_policy_version(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<Option<PolicyVersionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(
        "select * from policy_versions
          where tenant_id = $1 and policy_id = $2
          order by version desc limit 1",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Full history, newest first.
pub async fn list_policy_versions(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<Vec<PolicyVersionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(
        "select * from policy_versions
          where tenant_id = $1 and policy_id = $2
          order by version desc",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// One version's row (diff / revert / export).
pub async fn get_policy_version(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
    version: i32,
) -> sqlx::Result<Option<PolicyVersionRow>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let __rls_out = sqlx::query_as(
        "select * from policy_versions
          where tenant_id = $1 and policy_id = $2 and version = $3",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .bind(version)
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Policy identities joined with their latest version (number + content).
pub async fn list_policies(
    pool: &PgPool,
    scope: TenantScope,
) -> sqlx::Result<Vec<PolicySummaryRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select p.id, p.tenant_id, p.name, p.created_at, p.updated_at,
                coalesce(v.version, 0) as latest_version,
                v.content as latest_content
           from policies p
           left join lateral (
             select version, content from policy_versions v2
              where v2.policy_id = p.id
              order by v2.version desc limit 1
           ) v on true
          where p.tenant_id = $1
          order by p.name",
    )
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_policy(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<PolicyRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from policies where id = $1 and tenant_id = $2")
        .bind(id)
        .bind(scope.tenant_id())
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_policy_by_name(
    pool: &PgPool,
    scope: TenantScope,
    name: &str,
) -> sqlx::Result<Option<PolicyRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as("select * from policies where tenant_id = $1 and name = $2")
        .bind(scope.tenant_id())
        .bind(name)
        .fetch_optional(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// Agents whose LATEST revision uses this policy — the blast radius an override
/// header must state. An older revision pointing here does not count: only the
/// latest revision governs future runs, so only it is at stake in an edit.
pub async fn policy_agents_using(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<i64> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_scalar(
        "select count(*) from agents a
          where a.tenant_id = $1
            and (
              select r.policy_id from agent_revisions r
               where r.agent_id = a.id
               order by r.rev desc
               limit 1
            ) = $2",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

/// The outcome of a policy delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeletePolicy {
    /// The identity and — through the composite FK's cascade — its whole
    /// version history are gone.
    Deleted,
    NotFound,
    /// At least one `agent_revision` still names it. `agent_revisions.policy_id`
    /// is ON DELETE NO ACTION on purpose and the count spans EVERY revision,
    /// not just the latest: revisions are immutable, so a historical one must
    /// keep resolving its policy identity. Detach by appending a revision on a
    /// different policy — which does NOT free this one, because the old
    /// revision survives — or delete the agent.
    InUse {
        revisions: i64,
    },
}

/// Delete a policy identity and cascade its versions.
///
/// This is the ONE sanctioned erasure path for `policy_versions` (0026 grants
/// the runtime role no DELETE on that table; the cascade runs with the
/// referencing table owner's privileges, which is why append-only survives as
/// a database property while this still works — pinned by
/// `deleting_a_policy_cascades_its_versions_under_the_runtime_role`).
///
/// In-flight and historical RUNS are unaffected: a RunSpec froze the whole
/// policy document, so a run's audit record never needed the row to survive.
pub async fn delete_policy(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<DeletePolicy> {
    let mut tx = scoped_tx(pool, scope).await?;
    let locked = sqlx::query_as::<_, (Uuid,)>(
        "select id from policies where id = $1 and tenant_id = $2 for update",
    )
    .bind(policy_id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    if locked.is_none() {
        tx.rollback().await?;
        return Ok(DeletePolicy::NotFound);
    }
    // Counted for a MESSAGE; the FK is what guarantees the invariant.
    //
    // The count is nonetheless RACE-FREE, and by construction rather than by
    // luck: the `FOR UPDATE` above conflicts with the `FOR KEY SHARE` an
    // `agent_revisions` insert takes on this same parent row to satisfy its FK.
    // So a revision already in flight makes our lock wait and is then counted,
    // and one starting after our lock waits for us and then fails. There is no
    // window in which the count is stale. (`api.rs` still maps the FK's 23503
    // to the same 409 — belt and braces for a future change to that locking.)
    let (revisions,): (i64,) = sqlx::query_as(
        "select count(*) from agent_revisions r
           join agents a on a.id = r.agent_id
          where a.tenant_id = $1 and r.policy_id = $2",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_one(&mut *tx)
    .await?;
    if revisions > 0 {
        tx.rollback().await?;
        return Ok(DeletePolicy::InUse { revisions });
    }
    sqlx::query("delete from policies where id = $1 and tenant_id = $2")
        .bind(policy_id)
        .bind(scope.tenant_id())
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(DeletePolicy::Deleted)
}

/// The union of `mcp__<server>__<tool>` names an agent on this policy can call —
/// from BOTH attachment paths on the LATEST revision of every agent using it:
/// the photographed tools in its pinned (sandbox) capability bundles, AND the
/// `mcp__<slot>__<tool>` names in its brokered `connection_requirements` (Phase
/// C: converted agents carry brokered tools as requirements, not bundle pins, so
/// their governance-matrix rows keep appearing). Sorted and deduplicated: two
/// agents may pin the same bundle or require the same tool.
///
/// Reads the pins' bundle ids rather than resolving `name`/`version` — the pin is
/// exact by construction (§17 #7), so the id IS the photograph the frozen RunSpec
/// will carry; requirement tool names are the frozen contract directly.
pub async fn policy_mcp_tools(
    pool: &PgPool,
    scope: TenantScope,
    policy_id: Uuid,
) -> sqlx::Result<Vec<String>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let revs: Vec<(Value, Value)> = sqlx::query_as(
        "select r.capability_bundles, r.connection_requirements from agents a
           join lateral (
             select * from agent_revisions r2
              where r2.agent_id = a.id order by r2.rev desc limit 1
           ) r on true
          where a.tenant_id = $1 and r.policy_id = $2",
    )
    .bind(scope.tenant_id())
    .bind(policy_id)
    .fetch_all(&mut *tx)
    .await?;

    let mut out: Vec<String> = Vec::new();

    // Brokered requirement tools: `mcp__<slot>__<tool>` straight off the revision
    // — the requirement IS the frozen contract, there is no bundle to resolve.
    for (_, reqs) in &revs {
        let Some(arr) = reqs.as_array() else { continue };
        for req in arr {
            let Some(slot) = req.get("slot").and_then(|v| v.as_str()) else {
                continue;
            };
            let Some(tools) = req.get("required_tools").and_then(|v| v.as_array()) else {
                continue;
            };
            for t in tools {
                if let Some(tool) = t.as_str() {
                    out.push(format!("mcp__{slot}__{tool}"));
                }
            }
        }
    }

    // Sandbox-bundle tools: resolve each pin's bundle id to its photographed
    // `definition.servers[].tools[]`.
    let mut ids: Vec<Uuid> = Vec::new();
    for (pins, _) in &revs {
        let Some(arr) = pins.as_array() else { continue };
        for r in arr {
            if let Some(id) = r
                .get("id")
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse().ok())
            {
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();

    if !ids.is_empty() {
        // Tenant-scoped: a pin can never reach across a tenant boundary.
        let defs: Vec<Value> = sqlx::query_scalar(
            "select definition from capability_bundles where tenant_id = $1 and id = any($2)",
        )
        .bind(scope.tenant_id())
        .bind(&ids)
        .fetch_all(&mut *tx)
        .await?;

        for def in &defs {
            let Some(servers) = def.get("servers").and_then(|v| v.as_array()) else {
                continue;
            };
            for s in servers {
                let Some(server) = s.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(tools) = s.get("tools").and_then(|v| v.as_array()) else {
                    continue;
                };
                for t in tools {
                    if let Some(tool) = t.get("name").and_then(|v| v.as_str()) {
                        out.push(format!("mcp__{server}__{tool}"));
                    }
                }
            }
        }
    }

    tx.commit().await?;
    out.sort_unstable();
    out.dedup();
    Ok(out)
}
