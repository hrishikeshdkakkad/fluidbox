# Authentication

fluidbox has four kinds of credential, and they are not interchangeable. Picking
the wrong one is the single most common integration mistake, so this page is
mostly about *which* rather than *how*.

## Choosing

| You are… | Use | Header |
| --- | --- | --- |
| A script, CI job, or backend service | **Personal access token** | `Authorization: Bearer fbx_pat_…` |
| A single-admin or local deployment | **Admin token** | `Authorization: Bearer …` |
| A webhook or scheduler firing one automation | **Trigger token** | `Authorization: Bearer …` |
| A browser | **Session cookie** | `__Host-fbx_web` + `x-fluidbox-csrf` |
| A sandbox runner | **Session token** | `Authorization: Bearer fbx_sess_…` |

---

## Admin token

The deployment-wide credential. Its reach depends on one setting:

- **Single-user (default)** — reaches the whole `/v1` surface. This is the
  local and single-admin mode.
- **Multi-user (`FLUIDBOX_REQUIRE_SSO=1`)** — confined to `/v1/admin/*` as a
  **break-glass credential**. Everywhere else the principal resolver refuses
  it, in favour of user sessions and personal access tokens.

That confinement is deliberate: in a multi-user deployment, actions need an
attributable human behind them, and a shared deployment token has no identity.

The admin token can never invoke a trigger. That restriction is symmetric — a
trigger token can never reach the admin API.

## Personal access tokens

The right choice for machine access. Prefix `fbx_pat_`.

```bash
curl -sX POST "$FLUIDBOX_URL/v1/auth/tokens" \
  -H 'x-fluidbox-csrf: 1' \
  -H 'content-type: application/json' \
  --cookie "__Host-fbx_web=$SESSION" \
  -d '{"name":"ci-runner","expires_in":2592000}'
```

Three properties worth knowing:

- **Minting requires a browser session.** A PAT can never mint another PAT, so
  a leaked token cannot quietly extend its own lifetime.
- **Stored as a SHA-256 digest.** The value is returned exactly once and cannot
  be read back.
- **Scrubbed from the event ledger.** The redactor removes `fbx_pat_`,
  `fbx_web_`, and `fbx_sess_` values, and there is a test that pins it.

Revoke with `DELETE /v1/auth/tokens/{id}`.

## Browser sessions

Browsers authenticate with a `__Host-fbx_web` cookie. Non-safe methods
additionally require:

- the `x-fluidbox-csrf: 1` header, and
- a same-origin `Origin`.

There is **no CORS layer**, and that is a deliberate design choice rather than
an omission. The dashboard is a same-origin proxy — `/` serves the web app and
`/v1` the API on one origin — so a cross-origin write to `/v1` is never
legitimate, and no `Access-Control-*` grant should exist to make one possible.

Bearer principals are exempt from the CSRF requirement: a cross-site request
cannot attach an `Authorization` header, so there is nothing to forge.

The dashboard proxy's own credential mode is fixed per deployment via
`FLUIDBOX_WEB_MODE`:

- `admin` — injects the admin token server-side (local and single-admin).
- `sso` — carries no admin token at all; forwards only the session cookie and
  the CSRF header.

## Trigger tokens

Subscription-scoped. A trigger token can:

- invoke its **one** subscription, and
- poll that subscription's runs.

It can never reach the admin API.

Polling is scoped to the *subscription*, not to the token. That distinction
matters at rotation time: rotation replaces the **credential**, not the
**authority**, so a replacement token can still poll runs created before it
existed.

```bash
curl -sX POST "$FLUIDBOX_URL/v1/triggers/$SUB/invoke" \
  -H "Authorization: Bearer $TRIGGER_TOKEN" \
  -H 'content-type: application/json' \
  -d '{}'
```

The token is returned exactly once, at creation and at rotation.

## Sandbox session tokens

Not for you — these belong to the runner inside the sandbox. They are described
here because the design constrains what a harness author can do.

A sandbox holds **four audience-scoped tokens**, not one bearer:

| Audience | Routes |
| --- | --- |
| `tool` | `/permission`, `/tools/call` |
| `control` | `/events`, `/heartbeat`, `/result`, `/token/renew` |
| `workspace` | `/workspace` |
| `llm` | `/llm/*` |

Each guarded handler checks the audience as its **first statement** and answers
`403 {"error":"wrong_audience"}`. That body string is load-bearing: runners key
their fatal abort on it, so changing it would silently restore silent denial.

The `llm` token doubles as the sandbox's `ANTHROPIC_API_KEY`. There is no real
provider key inside a sandbox, ever.

### Disclosed limits

Being straight about what this does and does not buy:

- A same-uid child process can still read the runner's *initial* environment
  via `/proc/<pid>/environ`. Both runners delete the token from the environment
  before spawning anything, so the scrub covers spawned processes — true
  process isolation is a follow-up.
- Docker's device host is explicitly not a security boundary.
- An **old pinned runner image on a new server is unsupported.** Current
  runner libraries abort loudly with a diagnostic on the timeline, but that
  behaviour lives *in the image* — a sufficiently old image will instead
  collapse into silent denial while model spend continues.

---

## Confirming who you are

When a request is refused and you are not sure which principal you presented:

```bash
curl -s "$FLUIDBOX_URL/v1/auth/me" -H "Authorization: Bearer $TOKEN"
```

## A note on `404`

Tenant isolation is a **signature requirement**, not a remember-to-filter
convention: every tenant-owned data access carries a verified tenant scope into
its query, and the database enforces a second floor with row-level security.

The practical consequence for you as a caller is that another tenant's resource
is indistinguishable from a missing one. A `404` means "no such resource, or
none visible to you" — do not read it as proof of non-existence.
