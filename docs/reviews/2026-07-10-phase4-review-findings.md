# Phase 4 GitHub PR Fan-Out — Review Findings Ledger

**Date:** 2026-07-10

**Reviewed head:** `5915965` (`docs: phase 5 brief — add MCP-ecosystem research-first step`)

**Scope:** Phase 4 read-only trust enforcement, event fan-out, trigger dispatch, GitHub connection lifecycle, and GitHub result publishing.

**Overall status:** **Blocked for production use.** `just check` passes, but the review identified four P1 and six P2 defects affecting sandbox confidentiality, authorization revocation, event concurrency, retry safety, and result ordering.

**Verification status:** Each finding below was spot-checked against the referenced source on 2026-07-10 and the unsafe control flow is present. Adversarial reproduction and regression tests are still required during remediation.

## 1. Executive summary

The defects group into three failure domains:

1. **Sandbox security boundary:** `ReadOnly` runs can read outside the workspace or execute/write through commands classified only by prefix.
2. **Distributed dispatch correctness:** event runs are missing from subscription queries, stale claims are unfenced, and transient infrastructure failures become permanent lost dispatches.
3. **Connector lifecycle and publishing:** revoked tokens remain usable from cache, malformed responses fail open, dead webhook secrets can be configured, ambiguous creates can duplicate GitHub objects, and older runs can overwrite newer reviews.

### Release gate

Phase 4 should not be considered production-ready until all ten findings are fixed and the remediation passes:

- targeted unit and database tests;
- adversarial read-only sandbox tests;
- concurrent delivery/takeover tests;
- GitHub ambiguous-response/retry simulations;
- stale-result ordering tests;
- full `just check` and Phase 4 E2E.

## 2. Review ratings

| Dimension | Rating | Reason |
|---|---|---|
| Security | Blocked | Read-only runs can escape workspace confidentiality/execution limits; revoked cached credentials remain usable. |
| Correctness | Blocked | Event runs disappear from subscription ownership/concurrency queries; stale publishers can overwrite current results. |
| Reliability | Blocked | Stale claim takeover can create duplicate paid runs; transient dispatch failures can permanently lose work. |
| Performance | Needs follow-up | Duplicate runs and duplicate GitHub objects create unbounded avoidable cost; no primary algorithmic issue was identified. |
| Maintainability | Mixed | The major abstractions exist, but recovery state and authority checks are distributed across code paths without one enforceable contract. |
| Test coverage | Insufficient for adversarial behavior | Happy-path and quality checks pass, but the reviewed boundary, takeover, revocation, and ambiguous-response cases are not covered. |

## 3. Findings index

| ID | Severity | Area | Finding | Status |
|---|---|---|---|---|
| `P4-SEC-001` | P1 | Read-only policy | Bash command prefixes allow execution and writes through dangerous arguments. | Open; source-confirmed |
| `P4-SEC-002` | P1 | Read-only policy | File reads are not confined to the canonical workspace. | Open; source-confirmed |
| `P4-DSP-003` | P1 | Subscription queries | Dispatch-bound event runs are omitted from ownership, activity, and concurrency lookups. | Open; source-confirmed |
| `P4-AUTH-004` | P1 | GitHub credentials | Revoked App connections can reuse cached installation tokens. | Open; source-confirmed |
| `P4-DSP-005` | P2 | Dispatch claims | Stale-claim takeover has no fencing token and can create duplicate runs. | Open; source-confirmed |
| `P4-DSP-006` | P2 | Dispatch retries | Transient infrastructure errors are recorded as terminal dispatch outcomes. | Open; source-confirmed |
| `P4-PUB-007` | P2 | GitHub publishing | Ambiguous comment/check creates are not idempotent across retries. | Open; source-confirmed |
| `P4-PUB-008` | P2 | Result ordering | Older runs can overwrite newer PR review comments. | Open; source-confirmed |
| `P4-INT-009` | P2 | GitHub HTTP | Malformed nonempty 2xx responses are accepted as `null`. | Open; source-confirmed |
| `P4-SEC-010` | P2 | Webhook secrets | Event subscriptions can be created when the current server cannot decrypt the webhook secret. | Open; source-confirmed |

## 4. Detailed findings

### P4-SEC-001 — Parse allowed Bash arguments before granting read-only access

**Severity:** P1

**Source:** `crates/fluidbox-core/src/policy.rs:396-446`, especially `READ_SAFE_PREFIXES` and `read_only_denial`.

**Observed behavior:** The read-only gate rejects a small set of shell metacharacters and then trusts a command-prefix match. It does not validate the arguments or side effects of the matched program.

Examples that cross the intended boundary without screened metacharacters:

```text
rg --pre sh pattern payload.sh
git diff --output=/workspace/repo/leak.patch
git branch attacker-controlled-ref
```

`rg --pre` executes a program supplied by a fork-controlled repository. Several allowed Git subcommands also have write-producing modes or configuration-driven execution paths.

**Impact:** An untrusted fork can execute repository code or mutate the checkout despite `TrustTier::ReadOnly`. This invalidates the documented “review yes; writes, execution, egress, secrets no” boundary.

**Required remediation:**

- Replace prefix-only classification with command-specific argv validation.
- Parse one simple command; reject shell syntax, environment assignment, redirection, and ambiguous quoting.
- Maintain explicit safe flags and positional-argument rules per command.
- Forbid execution/write options such as ripgrep preprocessors and Git output/ref mutation.
- Disable repository-controlled external diff/text-conversion execution for allowed Git reads.
- Fail closed on unrecognized flags or malformed argv.

**Required regression tests:**

- Deny `rg --pre`, `git diff --output`, and mutating `git branch` forms.
- Deny an allowed command with unknown or combined unsafe flags.
- Allow explicitly supported read forms such as `rg pattern .`, `git status --short`, and a constrained `git diff`.
- Prove no accepted read-only command creates a file, process, ref, or network request.

### P4-SEC-002 — Constrain read-only file access to the workspace

**Severity:** P1

**Source:** `crates/fluidbox-core/src/policy.rs:421-423` and the Bash reader allowlist at `398-413`.

**Observed behavior:** `Read`, `Glob`, `Grep`, `LS`, and `NotebookRead` are accepted solely by tool name. Their input paths are not checked. Bash readers such as `cat`, `head`, and `tail` are likewise not confined to the workspace.

Example:

```text
Read /proc/1/environ
cat /proc/1/environ
```

The sandbox environment can contain the session token, fake model API key, task, and system prompt. The agent can then include those values in a review result.

**Impact:** A fork-controlled repository can cause confidential session context to be exfiltrated through the result publisher without requiring network access from the sandbox.

**Required remediation:**

- Validate every read-tool path against the canonical workspace root.
- Resolve symlinks and reject escapes through absolute paths, `..`, procfs, device paths, or symlink chains.
- Apply equivalent confinement to positional file arguments of allowed Bash readers.
- Define safe handling for nonexistent paths without falling back to unchecked lexical matching.
- Prefer a sandbox filesystem boundary that makes non-workspace reads physically unavailable, with policy as an additional layer.

**Required regression tests:**

- Deny absolute `/proc`, `/etc`, `/root`, and sibling-workspace paths.
- Deny `../` traversal and in-workspace symlinks pointing outside.
- Allow ordinary files and directories beneath the canonical workspace.
- Verify secrets from the sandbox environment never appear in events, artifacts, or published results.

### P4-DSP-003 — Include dispatch-bound event runs in subscription lookups

**Severity:** P1

**Sources:**

- Event runs bind through `trigger_dispatches`: `crates/fluidbox-server/src/events.rs:203-233`.
- Subscription lookups join only `trigger_invocations`: `crates/fluidbox-db/src/lib.rs:1292-1350`.
- Consumers include run concurrency and scoped activity/polling: `run_service.rs`, `triggers.rs`.

**Observed behavior:** API/schedule runs are associated through `trigger_invocations`, while event fan-out runs are associated through `trigger_dispatches`. `active_subscription_sessions`, `list_subscription_sessions`, and `subscription_owns_session` inspect only the first association.

**Impact:**

- Event-to-event `skip_if_running` and `replace` do not see active event runs.
- Trigger activity omits GitHub event runs.
- Trigger-scoped polling returns not found for sessions created by event fan-out.
- Concurrency guarantees differ depending on invocation source.

**Required remediation:** Make subscription-to-session lookup a single database contract that includes both association tables, using a `UNION`/`EXISTS` shape that deduplicates sessions and preserves ordering/limits.

**Required regression tests:**

- Create one invocation-bound and one dispatch-bound session for the same subscription; both must appear in activity.
- `subscription_owns_session` must return true for both kinds.
- `skip_if_running` must skip when the active run came from an event.
- `replace` must identify and cancel/replace an active event run.

### P4-AUTH-004 — Check revocation before returning cached App tokens

**Severity:** P1

**Sources:**

- Cache-first return: `crates/fluidbox-server/src/connectors/github.rs:345-360`.
- Database revocation: `crates/fluidbox-server/src/connections.rs` and `crates/fluidbox-db/src/lib.rs:444-475`.

**Observed behavior:** `installation_token` returns a cached token before checking the current connection status or loading the sealed active credential. Revocation updates the database but does not make the cache lookup fail.

**Impact:** A revoked GitHub App installation can continue fetching repositories or publishing results until the cached token approaches expiry. In a multi-process deployment, endpoint-local cache eviction alone would also be insufficient.

**Required remediation:**

- Check `conn.status == active` before cache lookup.
- Evict the local cache immediately in the revoke path.
- Retain the status check on every token use so database revocation remains authoritative across processes.
- Consider a short status-cache TTL only if database load becomes material; revocation must remain fail closed.

**Required regression tests:**

- Mint/cache a token, revoke the connection, then assert fetch and publish fail immediately.
- Revoke from a separate state/process simulation and assert status validation still blocks the cached token.
- Reconnecting a new installation must not reuse a token cached under obsolete identity metadata.

### P4-DSP-005 — Fence stale dispatch-claim takeovers

**Severity:** P2

**Sources:**

- Unfenced 60-second takeover: `crates/fluidbox-db/src/lib.rs:1686-1721`.
- Unconditional dispatch binding inside session creation: `crates/fluidbox-db/src/lib.rs:689-706`.

**Observed behavior:** A `created` dispatch with no session becomes stealable after 60 seconds. The takeover updates only `created_at`; it does not issue an owner generation or lease token. The original handler continues running and can still bind a session because `create_session` updates the dispatch by id without comparing ownership.

**Impact:** A slow original handler and a retrying handler can both create paid sessions for the same `(delivery, subscription)`. The last binding wins in the dispatch row while the other session remains real and running.

**Required remediation:**

- Add a claim generation/lease token returned by `claim_trigger_dispatch`.
- Require compare-and-swap ownership when binding the session.
- Treat zero affected rows as a lost fence and roll back the newly inserted session in the same transaction.
- Renew the lease around legitimately long pre-creation work, or move slow work after the atomic bind.
- Apply the same fencing discipline to any analogous invocation takeover path.

**Required regression tests:**

- Handler A claims; after simulated expiry handler B takes over; A must be unable to commit a session.
- B creates exactly one session and owns the dispatch.
- A slow but actively renewed claim must not be stealable.
- Concurrent takeover attempts must result in one generation winner.

### P4-DSP-006 — Keep infrastructure dispatch failures retryable

**Severity:** P2

**Source:** `crates/fluidbox-server/src/events.rs:123-159`.

**Observed behavior:** Every `dispatch_one` error is recorded as terminal status `error`, and webhook ingress still succeeds. Later delivery retries find the terminal claim and report `already_dispatched`.

**Impact:** A transient database, connection-pool, or internal service failure can permanently lose a matching run even though the external provider redelivers the event.

**Required remediation:**

- Classify deterministic configuration/input errors separately from infrastructure failures.
- Mark deterministic failures terminal and visible.
- Release/reset the claim or enqueue an internal retry for database, transport, timeout, and internal failures.
- If no durable internal retry has been accepted, return a retryable HTTP error so the provider redelivers.
- Preserve per-subscription outcomes so one deterministic bad subscription does not necessarily force duplicate processing of successful siblings.

**Required regression tests:**

- Inject a transient DB failure; redelivery must later create exactly one run.
- A malformed task template remains terminal and does not create a run on retry.
- A mixed fan-out with successful and retryable-failed subscriptions heals only the missing dispatches.

### P4-PUB-007 — Make GitHub creates idempotent across ambiguous retries

**Severity:** P2

**Sources:**

- Comment POST followed by persistence: `crates/fluidbox-server/src/connectors/github.rs:690-715`.
- Check-run POST with no external identity persistence: `crates/fluidbox-server/src/connectors/github.rs:722-768`.

**Observed behavior:** If GitHub accepts a create request but the response is lost, the process dies, or the database update fails, fluidbox retains no authoritative external id. A retry issues another create.

**Impact:** One run can create duplicate PR comments or check runs, violating the stable result identity promised by the Phase 4 design.

**Required remediation:**

- Persist a local publishing intent with a deterministic correlation key before the external POST.
- Put that correlation key into an externally queryable marker when the provider API permits it.
- On ambiguous failure, reconcile/list/search for the existing external object before creating again.
- Persist the external id and delivery state atomically enough that recovery can distinguish “not sent,” “possibly sent,” and “confirmed.”
- Use the same pattern for both comments and checks.

**Required regression tests:**

- Simulate “provider accepted, client lost response”; retry must find/reuse the original object.
- Simulate “provider accepted, DB write failed”; reconciliation must avoid a duplicate.
- Concurrent publisher attempts for the same stable result key must create at most one external object.

### P4-PUB-008 — Prevent older runs from overwriting newer PR comments

**Severity:** P2

**Source:** `crates/fluidbox-server/src/connectors/github.rs:627-688`.

**Observed behavior:** A stable PR comment is updated without comparing the run's source head, event version, or ordering metadata to the version already published.

**Impact:** When `opened` and `synchronize` runs overlap, or an older delivery retries late, the slower result for an obsolete commit can replace the review for the current PR head.

**Required remediation:**

- Persist a monotonic source version with the stable external result.
- Compare-and-swap the publish version before updating the external comment.
- Ignore and mark stale result deliveries without calling GitHub.
- Keep checks bound to their explicit head SHA and ensure comment ordering uses event/run source metadata rather than completion time alone.

**Required regression tests:**

- New-head review publishes first; old-head review finishes later and must not PATCH the comment.
- Old-head review publishes first; new-head review replaces it.
- Retrying an older delivery after a newer version remains a no-op.

### P4-INT-009 — Reject malformed successful GitHub responses

**Severity:** P2

**Source:** `crates/fluidbox-server/src/connectors/github.rs:255-290`.

**Observed behavior:** Any nonempty body that fails JSON parsing is silently converted to `Value::Null`, even for a successful HTTP status.

**Impact:** PAT/App validation can persist a connection with unknown identity, repository listing can silently appear empty, and create/mint flows lose the distinction between valid empty responses and corrupted successful responses.

**Required remediation:**

- Accept an empty response only for endpoints/statuses that explicitly allow it.
- Treat nonempty malformed 2xx bodies as parse errors.
- Preserve status and a safely truncated, secret-free diagnostic for malformed error responses.
- Prefer typed endpoint response parsing where the caller requires mandatory fields.

**Required regression tests:**

- Nonempty malformed 200/201 response fails closed.
- Expected empty 204 remains accepted where applicable.
- Valid JSON error and success bodies retain their status and fields.

### P4-SEC-010 — Refuse event triggers when webhook secrets cannot be decrypted

**Severity:** P2

**Source:** `crates/fluidbox-server/src/triggers.rs:330-372`.

**Observed behavior:** Event-subscription creation verifies that sealed secret bytes exist, but it does not verify that the current `FLUIDBOX_CREDENTIAL_KEY` can open them.

**Impact:** After restart with a missing or wrong key, users can create apparently valid event subscriptions that can never authenticate ingress. The configuration is permanently dead until the key is corrected, but creation does not report the problem.

**Required remediation:**

- Require an available sealer during event-subscription creation.
- Load and decrypt the webhook secret before accepting the subscription.
- Return a clear configuration error without exposing ciphertext or secret material.
- Keep connection status and provider capability validation in the same fail-closed path.

**Required regression tests:**

- Missing credential key rejects event-subscription creation.
- Wrong key or corrupted ciphertext rejects creation.
- Correct key permits creation without retaining plaintext beyond validation.

## 5. Recommended remediation order

### Wave 1 — Immediate P1 security and semantic blockers

1. `P4-SEC-001`: command-specific read-only Bash validation.
2. `P4-SEC-002`: canonical workspace read confinement.
3. `P4-AUTH-004`: revoked-token cache enforcement.
4. `P4-DSP-003`: unify subscription session lookups.

### Wave 2 — Dispatch recovery and exactly-once run creation

5. `P4-DSP-005`: fenced dispatch claims.
6. `P4-DSP-006`: retryable infrastructure failures.

### Wave 3 — External side-effect consistency

7. `P4-PUB-007`: ambiguous-create reconciliation/idempotency.
8. `P4-PUB-008`: stale-result ordering fence.

### Wave 4 — Fail-closed connector configuration

9. `P4-INT-009`: strict successful-response parsing.
10. `P4-SEC-010`: webhook-secret decryptability validation.

## 6. Positive observations worth preserving

- `TrustTier::ReadOnly` is applied as a hard narrowing layer above policy; the problem is incomplete classification, not an approval path that intentionally widens trust.
- Event ingestion already separates delivery deduplication from per-subscription dispatch deduplication.
- Session creation binds a dispatch and session in one database transaction; fencing can strengthen this existing shape rather than replace it.
- GitHub credentials are sealed at rest and App installation tokens are short-lived and cached; revocation authority simply needs to precede cache reuse.
- PR comments already use a stable `(subscription, resource)` external-result concept, which is the right basis for ordering and reconciliation.
- The run/result lifecycle is separate from external result delivery, allowing publisher retries without rerunning the agent.
- The repository passes its existing quality suite, giving remediation a stable baseline.

## 7. Definition of done

For each finding:

- update its status in this ledger from `Open` to `Fixed`;
- link the fixing commit and targeted tests;
- record the exact verification command and outcome;
- add an adversarial regression covering the reviewer example or equivalent failure injection.

For the remediation wave as a whole:

```text
cargo test -p fluidbox-core
cargo test -p fluidbox-db          # with DATABASE_URL
cargo test -p fluidbox-server
just check
Phase 4 GitHub fan-out E2E
adversarial read-only sandbox suite
concurrent dispatch/publisher retry suite
```

The Phase 4 gate is closed only when no P1/P2 item remains open and the exact-head fan-out demo still produces one independent, correctly ordered result per matching agent subscription.
