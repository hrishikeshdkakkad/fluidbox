# Run queue operations — enabling, sizing, and rolling back capacity admission

> Design: `docs/plans/2026-08-23-run-queue-admission-design.md`. Companion code:
> `crates/fluidbox-server/src/{dispatcher,config}.rs`,
> `crates/fluidbox-db/src/system_worker.rs`, migration `0034_run_queue.sql`.

Without this feature, fluidbox has no admission control: every run launches the
moment it is created, and the only quantity gate is the Kubernetes namespace
`ResourceQuota` — which **fails runs terminally** on its 403 rather than holding
them. Enabling capacity admission adds a `queued` session status, a per-replica
dispatcher that admits runs oldest-first under a deployment-wide cap, bounded
queue depth and age, and requeue-with-backoff on the quota 403.

**With `FLUIDBOX_MAX_CONCURRENT_RUNS` unset, none of this is active** and
behaviour is byte-identical to before the feature existed.

---

## 1. Enable it, in this order

The order is not advisory. It is the same discipline migration 0028 needed.

**① Apply the migration.** `0034_run_queue.sql` is additive — four nullable
columns plus a partial index — and safe to apply well before you enable
anything. Migrations run on server boot, so this happens with the first deploy
of the new image.

**② Roll the new image to EVERY replica.** Do not skip this, and do not
overlap it with step ③.

`SessionStatus::parse` maps an unrecognised status to `Failed` at the transition
sites, so **a binary that predates `queued` reads a parked run as terminal**: it
will not drive it, and its API reports the run failed. If one replica has the
new image and sets the env while another is still old, the old replica
misreports every parked run.

The failure mode is bounded — the boot orphan sweep uses a *strict* parse and
logs "unknown status (newer deploy?)" rather than reaping — so a premature
rollback leaves **zombie queued rows, not destroyed state**. That is a
recoverable mistake, not a data-loss one. Still, do the roll first.

**③ Set the cap.** `FLUIDBOX_MAX_CONCURRENT_RUNS` (Helm:
`server.maxConcurrentRuns`). Boot logs the resolved configuration:

```
run admission: ENABLED — cap 60 concurrent, queue depth 240, max wait 3600s, 5 capacity retries.
```

Every replica logs its own line, so `kubectl logs -l app=fluidbox-server | grep
'run admission'` tells you which replicas have picked the feature up — useful
mid-roll. A replica that has not logs `run admission: off`.

---

## 2. The four knobs

| Env / Helm value | Default | What it does |
|---|---|---|
| `FLUIDBOX_MAX_CONCURRENT_RUNS` / `server.maxConcurrentRuns` | unset = **off** | Deployment-wide cap on sandbox-holding runs. |
| `FLUIDBOX_QUEUE_MAX_DEPTH` / `server.queueMaxDepth` | `max(4 × cap, 50)` | Depth before new work is shed. |
| `FLUIDBOX_QUEUE_MAX_WAIT_SECS` / `server.queueMaxWaitSecs` | `3600` | How long a run may wait before failing with an explained reason. |
| `FLUIDBOX_QUEUE_REQUEUE_MAX` / `server.queueRequeueMax` | `5` | Provider capacity refusals tolerated before a terminal failure. |

The last three are **dead config without the cap**, and the server *refuses to
boot* rather than ignore them — a silently-ignored depth bound is a
misconfiguration you would never discover. `just doctor` catches the same thing
before you deploy. Every value must be an integer ≥ 1; `0` would either admit
nothing or shed everything.

`FLUIDBOX_QUEUE_MAX_WAIT_SECS` is measured from **first enqueue**, and the
timestamp is stamped once, so it bounds *total* time in queue across capacity
bounces. A run that sat in `awaiting_authorization` waiting on a human is not
charged for that wait — its clock starts when it becomes dispatchable.

---

## 3. Sizing against the Kubernetes quota

**Set both, and keep `maxConcurrentRuns ≤ sandbox.quota.pods`.**

They answer different questions:

- The **app cap** counts *runs* and can **hold** them. Over the cap, a run waits
  in `queued` and is admitted FIFO.
- The **namespace quota** counts *pods* — including pods fluidbox did not create
  (another workload in the namespace, a pod stuck terminating) — and is enforced
  by the API server for every replica at once. It cannot be bypassed by any code
  path, which is exactly why it stays as the backstop.

A cap *above* the quota means the quota fires first, and every over-cap run
takes the slower bounce-and-retry path instead of simply waiting its turn. It
still works — a quota 403 is now classified as capacity pressure and re-parks
the run with backoff rather than failing it — but each bounce costs a
provisioning round trip and 30–300 s of backoff. `just doctor` warns on this
combination.

Suggested starting point: `maxConcurrentRuns` equal to `quota.pods`, or one
tier below it if the namespace is shared with anything else.

---

## 4. What to watch

| Metric | Read it as |
|---|---|
| `fluidbox_runs_queued_depth` | How deep the queue is right now. Sustained non-zero means the cap is binding. |
| `fluidbox_queue_oldest_wait_seconds` | How long the head has waited. Climbing toward `MAX_WAIT_SECS` means runs are about to be expired. |
| `fluidbox_runs_dispatched_total` | Admissions. A redispatched bounce counts again. |
| `fluidbox_queue_wait_seconds` | Wait distribution, observed at admission. |
| `fluidbox_queue_shed_total{reason}` | `depth` = refused at create; `age` = expired while waiting; `requeue_exhausted` = bounced past the retry cap. |
| `fluidbox_queue_requeues_total{reason="quota"}` | Kubernetes rejected a pod against `ResourceQuota`. Sustained non-zero means the cap is above `quota.pods`, or something outside fluidbox is consuming the namespace. |
| `fluidbox_queue_requeues_total{reason="throttle"}` | The Kubernetes API server returned 429 throttling. This is normally transient; investigate API-server load or client request pressure if it persists. |

Per-run, the answer to "why is my run not running" is on the run itself: the
timeline carries a `StatusChanged` event with the reason (`parked at admission`,
`provider at capacity: <verbatim 403>`), and `GET /v1/sessions/{id}` exposes
`queued_at` plus `queue_position` while the run is queued.

`queue_position` counts older queued runs **in the same organization**. It is a
*lower bound* on the deployment-wide position, which is deliberately not
exposed: a deployment-wide number would let a caller infer another
organization's load by watching it move.

---

## 5. What callers see at the depth bound

| Entry point | Response |
|---|---|
| Manual `POST /v1/sessions`, API invoke | **429** with `Retry-After: 30` |
| Webhook fan-out | **2xx ack** with a recorded skip, reason `capacity` |
| Schedule tick | Recorded skip, reason `capacity`; the next cron fire retries |

Webhook and schedule shedding is deliberately **not** a 5xx. A 5xx asks the
provider to redeliver, turning one shed event into many requests at exactly the
moment the deployment is least able to take them.

The cost is disclosed: **a shed PR event does not self-heal.** The review run
does not happen, and only the skip row records it. If you see
`queue_shed_total{reason="depth"}` climbing, raise the depth bound or the cap —
depth shedding should be rare.

---

## 6. Rolling back

**Drain first, then roll back.** The reverse order leaves parked runs that the
old binary reads as failed.

1. **Unset `FLUIDBOX_MAX_CONCURRENT_RUNS` on all replicas.** New runs revert to
   launching on creation immediately.
2. **Let the queue drain.** The dispatcher stops with the env, so already-queued
   runs will *not* drain on their own — cancel them via the API
   (`POST /v1/sessions/{id}/cancel`), or re-enable the cap briefly and let them
   through before unsetting again.
3. **Verify zero parked runs:**
   ```sql
   select count(*) from sessions where status = 'queued';
   ```
4. **Roll the old image.**

Migration 0034 does not need reverting: with the env unset the four columns are
simply never written, and `stale_nonstarted_sessions`' `coalesce(launched_at,
created_at)` degrades to the pre-0034 behaviour for any row that carries no
stamp.

---

## 7. Known limits (stage 1)

- **No per-tenant fairness.** The queue is a single deployment-wide FIFO, so one
  organization can fill it and others wait behind. Accepted while the pilot is
  single-tenant; per-tenant ceilings plus round-robin ship when a second
  organization onboards (design §11, stage 2).
- **No priorities and no preemption**, ever by design: killing a running agent
  destroys spent model budget and truncates an audit timeline.
- **Docker classifies nothing as capacity.** Local exhaustion has no clean
  signal, so a Docker provisioning failure stays terminal. Only the Kubernetes
  provider maps the quota 403 and apiserver 429.
- **Admission latency is up to ~1 s** (the dispatcher polls; there is no NOTIFY
  wakeup). Invisible next to provisioning latency.
- **FIFO is near-FIFO.** `for update skip locked` may reorder around contended
  rows. Ordering is by `created_at` and is not a guarantee.
