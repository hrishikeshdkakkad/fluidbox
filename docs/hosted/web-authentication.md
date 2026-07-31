# Dashboard web-tier authentication (WorkOS AuthKit)

**Scope:** the Next.js app (`apps/web`) — who may *use the dashboard and its
API proxy*. This is deliberately distinct from control-plane identity
(`FLUIDBOX_REQUIRE_SSO`, per-org OIDC — see `docs/guides/authentication.md`).
Design: `docs/plans/2026-07-30-public-site-and-auth-boundary-design.md` §3.

## The two switches

| Variable | Values | Question it answers |
| --- | --- | --- |
| `FLUIDBOX_WEB_MODE` | `admin` (default) \| `sso` | Which credential the server-side proxy presents to the **control plane** |
| `FLUIDBOX_WEB_AUTH` | `none` (default) \| `workos` | Whether the **web tier itself** requires a WorkOS AuthKit session for `/app/*` and `/api/fluidbox/*` |

Valid combinations: `admin+none` (local default, unchanged), `admin+workos`
(hosted single-tenant: WorkOS authenticates the human, the proxy still holds
the operator token server-side), `sso+none` (fluidbox multi-user SSO,
unchanged). **`sso+workos` refuses to boot** — one origin, one session
system; in multi-user deployments WorkOS belongs *behind* fluidbox SSO as an
organization's OIDC identity provider, not in front of it.

## Enabling workos mode

1. In the WorkOS dashboard (per environment): create an **API key**, note the
   **client id**, register the **redirect URI** `<origin>/callback`, and set
   the app **homepage URL** (the post-logout landing) to `<origin>`.
   - dev: `http://localhost:3000/callback` / `http://localhost:3000`
   - preview: `https://<preview-host>/callback` / `https://<preview-host>`
   - production: `https://<prod-host>/callback` / `https://<prod-host>`
2. Set the environment (see `apps/web/.env.example` for the annotated block):
   `FLUIDBOX_WEB_AUTH=workos`, `WORKOS_API_KEY`, `WORKOS_CLIENT_ID`,
   `WORKOS_COOKIE_PASSWORD` (≥32 chars, `openssl rand -base64 24`),
   `NEXT_PUBLIC_WORKOS_REDIRECT_URI`.
3. **Docker images:** `NEXT_PUBLIC_*` values are inlined at build time. A
   `deploy/web.Dockerfile` image destined for workos mode must receive
   `NEXT_PUBLIC_WORKOS_REDIRECT_URI` as a build argument — runtime-only env
   is not enough for the callback's code exchange. Everything else is
   runtime env.
4. Zero-friction alternative for local evaluation:
   `npx workos env provision` mints an unclaimed environment (API key +
   client id), then `npx workos config redirect add http://localhost:3000/callback`
   and `npx workos config homepage-url set http://localhost:3000` complete
   it. Claim it into a team later with `workos env claim` (permanent).

## What enforces what

- **Cold start (fail closed):** `proxy.ts` resolves both switches at module
  scope. workos mode with any of the four variables missing, a short cookie
  password, or the `sso+workos` combination → every request 500s with an
  error naming the missing variable. There is no configuration in which
  `/app` silently serves unprotected.
- **Navigation:** the proxy composes the fluidbox gate (`lib/auth-gate.ts`)
  with AuthKit (`authkit()` / `handleAuthkitProxy`). An unauthenticated
  `/app*` document request 307s to the AuthKit authorization URL carrying
  the requested path — the user returns to the deep link after sign-in.
- **API (the boundary):** `app/api/fluidbox/[...path]/route.ts` validates the
  session with `withAuth()` on **every call**, before any control-plane
  credential is attached. No session → `401 {"error":"unauthorized"}` —
  JSON, never a redirect. Middleware assists UX; this check is the boundary.
- **Defense in depth:** the `/app` layout re-validates per document request
  (`withAuth({ ensureSignedIn: true })`, `force-dynamic` so runtime config
  governs) and feeds the session badge server-side — the client never
  derives auth state.
- **Sign-in / sign-up:** `/sign-in` and `/sign-up` are route handlers
  (`getSignInUrl`/`getSignUpUrl` — the PKCE-cookie-sanctioned surface).
  Marketing CTAs may simply link `/app` and let the gate run the dance.
- **Sign-out:** a POST **server action** (`app/app/actions.ts`) — never a GET
  route (prefetch- and CSRF-safe). Lands on the environment's homepage URL.
- **Secrets:** `WORKOS_API_KEY`/`WORKOS_COOKIE_PASSWORD` are server-only; the
  2026-07-30 verification greps the built client bundles for the key value,
  the variable names, and any `sk_` prefix — all zero.

## Session semantics worth knowing

- AuthKit holds its own session on the AuthKit domain: after a local
  sign-out-less cookie loss (rotation, new browser), visiting `/app` may
  silently re-authenticate via the hosted session. **Sign out revokes both**
  — verified live: post-signout, `/app` presents the sign-in page and the
  API answers 401.
- The pure decisions (mode parsing, env validation, the `/app` gate, the
  incompatibility rule) live in `apps/web/app/lib/web-auth.ts` with unit
  tests; `scripts/verify-routes.mjs` asserts the whole matrix against a real
  server in all three configurations.
