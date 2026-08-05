# Operator-toolkit failure-path smoke test

Run 2026-08-03T18:41:59Z by `scripts/cloud/guardrail-smoke.sh`. Each case removes
one prerequisite and asserts the script stops immediately with an actionable
message — never a hang, never a silent success. Nothing is mutated.

Result: **11 passed, 0 failed**.

| case | expected in output | verdict | first line |
|---|---|---|---|
| teardown refuses root | `root` | PASS |   ✗ refusing to run as the account ROOT identity |
| deploy-app refuses root | `root` | PASS |   ✗ refusing to run as the account ROOT identity |
| replay-on-cluster refuses root | `root` | PASS |   ✗ refusing to run as the account ROOT identity |
| make-secrets refuses root | `root` | PASS |   ✗ refusing to run as the account ROOT identity |
| make-secrets names the missing DATABASE_URL | `FLUIDBOX_CLOUD_DATABASE_URL` | PASS | scripts/cloud/make-secrets.sh: line 25: FLUIDBOX_CLOUD_DATABASE_URL: set FLUIDBOX_CLOUD_DATABASE |
| direct-alb-check without edge outputs | `edge` | PASS |   ✗ edge stack outputs unavailable (apply edge first or set CF_DOMAIN/ALB_DNS) |
| rotate-origin-secret without a distribution | `distribution` | PASS | == resolve edge identifiers == |
| make-secrets rejects a -pooler endpoint | `pooler` | PASS |   ✗ DATABASE_URL looks like a POOLER endpoint |
| kind validation refuses the dev database | `DEV database` | PASS |   ✗ refusing to run against the DEV database |
| onboarding rehearsal refuses the dev database | `DEV database` | PASS |   ✗ refusing to run against the DEV database |
| rehearsal names a missing server binary | `binary` | PASS |   ✗ server binary not found at /nonexistent/fluidbox-server |

The root-refusal cases are the load-bearing ones: this toolkit is meant to
be used AFTER the M1.0 ceremony retires the root key, and a script that
quietly worked under root credentials would undermine the whole guardrail.
