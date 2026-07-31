# Public website, developer docs, and the authenticated application boundary

**Date:** 2026-07-30 · **Branch:** `feat/developer-docs` · **Status:** approved design (implements the 2026-07-30 goal brief)

fluidbox today serves one thing on port 3000: the dashboard, with the in-flight
`/developer` docs as its only public corner. This design splits that origin into
three surfaces with one hard boundary:

1. **Public marketing site** — `/`, `/product`, `/open-source`, `/security`,
   `/changelog`, `/pricing`. Indexable, static, no session of any kind.
2. **Public developer docs** — `/docs/*`. Indexable, statically generated from
   `docs/` at the repo root (single source of truth), no session of any kind.
3. **The application** — everything operational moves under `/app/*`, optionally
   protected by WorkOS AuthKit at the web tier.

Positioning (verbatim, used across the site): *fluidbox is the open-source
control plane for governed AI agents.* Problem statement: *Run AI agents
without giving them God mode.* No invented metrics, customers, certifications,
or guarantees anywhere.

## 1. One app, not three

The marketing site, docs, and dashboard stay in the single Next.js app
(`apps/web`). Reasons, in order:

- The **credential boundary is already server-side here** — the API proxy
  (`app/api/fluidbox/[...path]/route.ts`) is the only place credentials exist.
  A second app would duplicate that seam, the Helm/web.Dockerfile deployment
  surface, and the design system, for zero additional isolation: route groups +
  the proxy gate enforce public/private exactly as well on one origin.
- The Helm ingress is already a `/` catch-all to web:3000 — new public routes
  ship with **zero chart changes**.
- The docs engine (`/developer`, this branch) is already in this app; the goal
  is a relocation and upgrade, not a rebuild.

Route groups keep the chromes apart: `app/(site)/…` renders the public chrome
(header/footer), `app/app/…` renders the dashboard shell, `app/login` renders
bare. The root layout shrinks to html/fonts/theme only.

## 2. Route matrix

| Route | Surface | Auth | Indexed | Notes |
| --- | --- | --- | --- | --- |
| `/` | marketing | none | yes | homepage (hero, governed-run demo, capabilities, architecture, DX, OSS, CTA) |
| `/product` | marketing | none | yes | capability deep-dive, honest feature matrix |
| `/open-source` | marketing | none | yes | MIT, repo, self-hosting, contributing, roadmap; no fabricated stats |
| `/security` | marketing | none | yes | posture from SECURITY.md + threat-model links; no guarantees language |
| `/changelog` | marketing | none | yes | generated from CHANGELOG.md at sync time |
| `/pricing` | marketing | none | yes | "Open source" + "Hosted early access" only — no invented prices |
| `/docs` | docs | none | yes | landing (start-here cards + four-planes panel) |
| `/docs/[slug]` | docs | none | yes | guides, statically generated; slug set below |
| `/docs/api` | docs | none | yes | API overview: auth, curl request/response examples |
| `/docs/api/reference` | docs | none | yes | generated operation index from openapi.yaml |
| `/docs/api.html`, `/docs/openapi.yaml` | docs | none | yes | Redoc page + downloadable spec (public/) |
| `/login` | app | fluidbox sso | **no** | unchanged fluidbox-SSO login; admin mode redirects to `/app` |
| `/callback` | app | — | no | WorkOS AuthKit callback (`handleAuth()`), only active in workos mode |
| `/app` | app | gated | **no** | Runs overview (old `/`) |
| `/app/agents`, `/app/agents/new` | app | gated | no | moved |
| `/app/automations`, `/app/automations/[id]` | app | gated | no | moved |
| `/app/capabilities` | app | gated | no | moved |
| `/app/governance`, `/app/governance/[name]` | app | gated | no | moved |
| `/app/integrations` | app | gated | no | moved |
| `/app/sessions/[id]` | app | gated | no | moved (run detail) |
| `/app/settings` | app | gated | no | moved |
| `/api/fluidbox/*` | app | gated | no | credential proxy; independent server-side session check |

Docs slugs (all real pages, no placeholders): `getting-started` (renamed from
`quickstart`), `concepts` (new), `agents` (new), `runs` (new), `policies`,
`approvals` (new), `triggers`, `governance`, `capabilities`, `docker` (new),
`kubernetes`, `security` (new), `authentication`, `runner-contract`; plus the
`api` overview + generated reference. New guides are authored in
`docs/guides/*.md` from repository facts (PLAN.md, CLAUDE.md invariants,
existing guides, deploy files) — `docs/` stays the **single source of truth**,
and `apps/web/scripts/sync-developer-docs.mjs` remains the one authoring
workflow (extended, see §5).

## 3. Authentication boundary

### Two orthogonal switches, both static deployment config

- `FLUIDBOX_WEB_MODE` = `admin` (default) | `sso` — **unchanged**: which
  credential the proxy presents to the control plane (operator token injected
  server-side, or fluidbox session-cookie passthrough).
- `FLUIDBOX_WEB_AUTH` = `none` (default) | `workos` — **new**: whether the web
  tier itself requires a WorkOS AuthKit session for `/app/*` and
  `/api/fluidbox/*`.

Valid combinations:

| WEB_MODE | WEB_AUTH | Posture |
| --- | --- | --- |
| admin | none | today's local/dev dashboard, byte-for-byte |
| admin | workos | **hosted single-tenant**: WorkOS authenticates the human; the proxy still speaks operator token to the control plane |
| sso | none | today's hosted multi-user posture (fluidbox OIDC login), unchanged |
| sso | workos | **refused at boot** (module-scope throw): two session systems on one origin is a footgun; multi-user identity is fluidbox SSO, which can federate to WorkOS as a per-org OIDC IdP instead |

That last row is the deliberate migration statement the goal asks for: existing
fluidbox SSO is preserved untouched; WorkOS AuthKit becomes the web-tier gate
for admin-credential deployments; full multi-user hosted keeps the control
plane's own identity (where WorkOS can serve as the upstream IdP per org).

### Fail-closed mechanics (workos mode)

- **Config**: `lib/web-auth.ts` (pure, unit-tested, same pattern as
  `proxy-auth.ts`). `FLUIDBOX_WEB_AUTH=workos` with any of `WORKOS_API_KEY`,
  `WORKOS_CLIENT_ID`, `WORKOS_COOKIE_PASSWORD`,
  `NEXT_PUBLIC_WORKOS_REDIRECT_URI` missing → **throw at module scope** (the
  app fails loudly; it never silently serves unprotected).
- **Navigation** (`proxy.ts`): compose the existing `gateDecision` with the
  AuthKit composable — `const { session, headers, authorizationUrl } = await
  authkit(request)`; an unauthenticated `/app*` navigation returns
  `handleAuthkitHeaders(request, headers, { redirect: authorizationUrl })`
  (the authorization URL carries the requested path, so the user returns to
  the deep link after AuthKit). All other responses flow through
  `handleAuthkitHeaders(request, headers)` so session refresh cookies
  propagate. The matcher **now includes `/api/fluidbox`** (so `withAuth()`
  works in the route handler); `gateDecision` explicitly passes `/api/*` —
  fetches are never redirected.
- **API** (`route.ts`): before forwarding, workos mode requires
  `const { user } = await withAuth()`; absent → `401 {"error":"unauthorized"}`.
  This is the independent server-side check the goal requires — middleware
  assists navigation UX; the route validates on every call.
- **Pages** (`app/app/layout.tsx`, server component): workos mode calls
  `withAuth({ ensureSignedIn: true })` — defense in depth for any document
  request that reaches the segment, and the source of the session UI (email +
  sign-out) passed to the client shell. `AuthKitProvider` mounts here (scoped
  to the `/app` subtree — public pages must not carry auth context; every
  `useAuth` consumer lives under `/app`).
- **Sign-in**: nav "Sign in"/"Get started" link to `/app` — the gate performs
  the AuthKit redirect dance (version-proof; no `getSignInUrl()` in render).
  `/sign-in` exists as a stable alias (route handler → redirect `/app`).
- **Sign-out**: POST **server action** calling `signOut({ returnTo: site })`
  — never a GET route (prefetch/CSRF-safe, per WorkOS guidance).
- **Sessions expire** upstream (AuthKit); an expired session fails `withAuth()`
  → 401 on API, redirect on navigation. Unauthorized API answers are JSON,
  never HTML.
- **Secrets**: `WORKOS_API_KEY` and `WORKOS_COOKIE_PASSWORD` are server-only
  (no `NEXT_PUBLIC_` prefix); the browser bundle check is part of verification.

In `none` mode nothing above executes — no AuthKit import runs, local dev is
unchanged.

### WorkOS environment contract (documented in `apps/web/.env.example`)

```
FLUIDBOX_WEB_AUTH=workos
WORKOS_API_KEY=sk_...            # server-only; WorkOS dashboard → API Keys
WORKOS_CLIENT_ID=client_...      # per environment (staging/production)
WORKOS_COOKIE_PASSWORD=...       # >=32 chars, openssl rand -base64 24
NEXT_PUBLIC_WORKOS_REDIRECT_URI=http://localhost:3000/callback
NEXT_PUBLIC_SITE_URL=http://localhost:3000   # metadataBase/canonicals
```

Redirect URIs registered per environment: dev `http://localhost:3000/callback`,
preview `https://<preview-host>/callback`, production
`https://<prod-host>/callback`; logout URIs point at the site root. Staging
(sandbox) is provisioned via the WorkOS MCP as part of this work; API key
creation is dashboard-only (documented human step if no key is available).

## 4. Redirect / migration plan

`next.config.ts` redirects (permanent), applied before public-file resolution:

| Old | New |
| --- | --- |
| `/agents`, `/agents/:path*` | `/app/agents…` |
| `/automations/:path*`, `/capabilities`, `/integrations`, `/settings` | `/app/…` |
| `/governance/:path*`, `/sessions/:path*` | `/app/…` |
| `/approvals` | `/app` (was `/`) |
| `/policies` | `/app/governance` |
| `/connections` | `/app/integrations` |
| `/triggers` | `/app/automations` |
| `/integrations?tab=store|bundles` | `/app/capabilities…` (query-conditioned, as today) |
| `/developer` | `/docs` |
| `/developer/reference` | `/docs/api/reference` |
| `/developer/quickstart` | `/docs/getting-started` |
| `/developer/:slug*` | `/docs/:slug*` |
| `/developer/api.html`, `/developer/openapi.yaml` | `/docs/…` |
| `/docs/quickstart` | `/docs/getting-started` |

Not redirectable: `/` itself (it *becomes* the homepage — old dashboard
bookmarks land on marketing one click from Sign in; internal deep links all
move). Non-web touchpoints updated: `run-agent.sh` watch URL →
`/app/sessions/{id}`; web-side post-login defaults `/` → `/app`
(`login/page.tsx`, `login-form.tsx`, `sanitizeNext` fallback, `to-app`
target); `apps/web/README.md` route map; root `README.md`; Helm
`NOTES.txt`/ingress comments (routing itself is a catch-all — functionally
untouched). The Rust control plane needs **no change** (its `redirect_to`
default only applies when the web layer omits the parameter, which it never
does after this change).

## 5. Docs platform

The `/developer` engine moves to `(site)/docs` and is upgraded in place:

- **Sync script stays the one authoring workflow** (`just docs-sync`), and now
  also emits: a **search index** (per-h2/h3 section: slug, title, anchor,
  plain text), **edit-on-GitHub source paths** per guide, `changelog.ts`
  parsed from `CHANGELOG.md`, and h3 anchors for deep TOCs. Generated modules
  remain checked in (web Docker build context is `apps/web` only — repo docs
  are not present at image build time; this constraint already shaped the
  engine).
- **Kept from the existing engine**: pure markdown parser + tests, shiki
  dual-theme highlighting at build, mermaid, copy buttons, TOC spy, prev/next,
  grouped rail. **Added**: full-text search dialog (⌘K, hand-rolled scorer,
  index lazy-loaded on first open), breadcrumbs with `BreadcrumbList` JSON-LD,
  per-page `generateMetadata` (title/description/canonical/OG), "Edit this
  page on GitHub" links, mobile docs nav.
- **`/docs/api`** is a real page (auth model, curl request/response examples
  sourced from the OpenAPI spec) linking the generated reference, the Redoc
  page, and the downloadable spec.

## 6. Marketing site

Distinct-but-coherent visual system: the existing Geist-layer tokens
(true-black dark, warm-paper light, `--ds-*` scales, 6/12px radii, Geist
Sans/Mono) are the foundation; marketing adds its own layout components
(`(site)/components/`) — header, footer, hero, a **governed-execution
timeline** rendered in the product's real event vocabulary
(`tool.requested → tool.decision → approval.decided → tool.brokered`), a
precise **architecture SVG** (harness in sandbox → internal gateway → policy
gate/ledger/orchestrator → LiteLLM → models; dashboard/CLI/API on `/v1`),
copyable command blocks reusing the docs `CodeBlock`, and an honest
open-source section (MIT, repo, self-host paths, CONTRIBUTING, ROADMAP,
good-first-issue link). Both themes; subtle motion only (CSS transitions,
`prefers-reduced-motion` respected); no gradients-for-gradients'-sake, no
fake logos/testimonials/metrics.

## 7. SEO

`metadataBase` from `NEXT_PUBLIC_SITE_URL`; per-page titles/descriptions/
canonicals; OG/Twitter cards with a committed `public/og.png` (regenerated
from a hidden, noindexed `/brand/og-card` page — documented workflow);
`app/sitemap.ts` (marketing + docs, generated slugs included);
`app/robots.ts` disallowing `/app`, `/api`, `/login`, `/callback`; JSON-LD
(`Organization` + `SoftwareApplication` on `/`, `TechArticle` +
`BreadcrumbList` on docs); `robots: { index: false }` metadata on the `/app`
layout and `/login`.

## 8. Verification plan

- **Unit** (vitest): reworked `auth-gate` decisions (`/app` scoping, `/api`
  pass, public paths), new `web-auth` config/combination matrix, markdown +
  search-index builders, redirect-map sanity.
- **Static**: `eslint`, `tsc --noEmit` (new `typecheck` script), `pnpm build`.
- **Route matrix** (`apps/web/scripts/verify-routes.mjs`, runs against a built
  `next start` in three env configurations): admin/none — every public route
  200, `/app` 200, `/login` → `/app`; workos (dummy key, real client id) —
  `/app` 307 → AuthKit authorize URL, `/api/fluidbox/*` 401 JSON, public
  routes 200 with **no** Set-Cookie/session artifacts; sso/none — `/app` →
  `/login?next=…`, docs/marketing pass.
- **Links**: `apps/web/scripts/check-links.mjs` crawls the running site
  (marketing + docs), fails on broken internal links/anchors.
- **Browser**: Playwright screenshots at 375/768/1440 (home, docs, dashboard),
  keyboard-nav pass, Lighthouse (home + `/docs`) targeting ≥90 across
  categories.
- **Live WorkOS round-trip** (scenario: signed-out `/app/runs` → AuthKit →
  back to the deep link): executed only if a real staging API key is
  available; otherwise the report states the exact human step (create a
  staging API key) — never a fabricated pass.
- **Rust untouched**: `cargo` suites are not in scope of this change; the web
  CI job (`pnpm build` + `pnpm test`) is the affected surface.

Evidence lands in `docs/reviews/2026-07-30-public-site/` (screenshots,
Lighthouse JSON, route-matrix output, final implementation report).
