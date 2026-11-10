//! Run artifacts.

use crate::scope::{scoped_tx, TenantScope};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize)]
pub struct ArtifactRow {
    pub id: Uuid,
    pub session_id: Uuid,
    pub kind: String,
    pub name: String,
    pub content: String,
    pub content_type: String,
    pub created_at: DateTime<Utc>,
}

/// The stored diff artifact's content, if any — the finalizer's evidence
/// guard: a re-driven finalization must never overwrite a collected diff
/// with an `artifact_missing` marker (missing → collected upgrades are fine).
pub async fn diff_artifact_content(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Option<String>> {
    let mut tx = scoped_tx(pool, scope).await?;
    let row: Option<(String,)> = sqlx::query_as(
        "select content from artifacts
         where session_id = $1 and kind = 'diff'
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         limit 1",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row.map(|(c,)| c))
}

/// Idempotent artifact write: a crash-retry during finalization must not
/// accumulate duplicate diff rows. Replaces any existing (session, kind, name).
pub async fn upsert_artifact(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    kind: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> sqlx::Result<ArtifactRow> {
    let mut tx = scoped_tx(pool, scope).await?;
    sqlx::query(
        "delete from artifacts
         where session_id = $1 and kind = $2 and name = $3
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $4)",
    )
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(scope.tenant_id())
    .execute(&mut *tx)
    .await?;
    let row: ArtifactRow = sqlx::query_as(
        "insert into artifacts (id, session_id, kind, name, content, content_type)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(content)
    .bind(content_type)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(row)
}

// ─── Artifacts ────────────────────────────────────────────────────────────

pub async fn add_artifact(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
    kind: &str,
    name: &str,
    content: &str,
    content_type: &str,
) -> sqlx::Result<ArtifactRow> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "insert into artifacts (id, session_id, kind, name, content, content_type)
         select $1,$2,$3,$4,$5,$6
         where exists (select 1 from sessions s where s.id = $2 and s.tenant_id = $7)
         returning *",
    )
    .bind(Uuid::now_v7())
    .bind(session)
    .bind(kind)
    .bind(name)
    .bind(content)
    .bind(content_type)
    .bind(scope.tenant_id())
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn list_artifacts(
    pool: &PgPool,
    scope: TenantScope,
    session: Uuid,
) -> sqlx::Result<Vec<ArtifactRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from artifacts
         where session_id = $1
           and exists (select 1 from sessions s where s.id = $1 and s.tenant_id = $2)
         order by created_at",
    )
    .bind(session)
    .bind(scope.tenant_id())
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}

pub async fn get_artifact(
    pool: &PgPool,
    scope: TenantScope,
    id: Uuid,
) -> sqlx::Result<Option<ArtifactRow>> {
    let mut tx = scoped_tx(pool, scope).await?;

    let __rls_out = sqlx::query_as(
        "select * from artifacts a
         where a.id = $1
           and exists (select 1 from sessions s where s.id = a.session_id and s.tenant_id = $2)",
    )
    .bind(id)
    .bind(scope.tenant_id())
    .fetch_optional(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(__rls_out)
}
