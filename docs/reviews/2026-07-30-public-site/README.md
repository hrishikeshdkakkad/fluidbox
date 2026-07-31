# Public website, docs platform, and the WorkOS /app boundary — implementation report

**Date:** 2026-07-30 · **Branch:** `feat/developer-docs` · **Design:** `docs/plans/2026-07-30-public-site-and-auth-boundary-design.md`

## What shipped

One Next.js app (`apps/web`), three surfaces, one fail-closed boundary:

1. **Public marketing site** — `/`, `/product`, `/open-source`, `/security`, `/changelog` (generated from `CHANGELOG.md`), `/pricing` (open source + hosted early access; no invented prices). Hero = a governed-run ledger in the product's real event vocabulary; precise hand-drawn architecture SVG; honest copy throughout (the only numbers are machine-true).
2. **Public developer docs** — `/docs` (+14 statically generated guides, `/docs/api`, `/docs/api/reference`, Redoc page + downloadable spec). Sidebar IA, breadcrumbs, TOC scroll-spy, prev/next, ⌘K full-text search (generated per-section index, lazy chunk), copy buttons, shiki dual-theme highlighting, deep-linkable headings (GitHub anchor convention), edit-on-GitHub links, per-page metadata/canonicals, TechArticle + BreadcrumbList JSON-LD. `docs/` at the repo root stays the single source of truth via the extended sync script (`just docs-sync`); seven new guides authored (concepts, agents, runs, approvals, docker, security, api) and quickstart renamed getting-started.
3. **The application** — everything operational moved under `/app/*`, with WorkOS AuthKit as an optional web-tier gate (`FLUIDBOX_WEB_AUTH=workos`). Full runbook: `docs/hosted/web-authentication.md`; env contract: `apps/web/.env.example`.

## Architecture decisions

- **One app, route groups** — the credential boundary already lives in the server-side proxy; a second app would duplicate the seam, the Docker/Helm surface, and the design system for zero isolation gain. The Helm ingress is a `/` catch-all → zero chart changes.
- **Two orthogonal auth switches** — `FLUIDBOX_WEB_MODE` (which credential the proxy presents to the control plane; untouched) × `FLUIDBOX_WEB_AUTH` (whether the web tier demands a WorkOS session). `sso+workos` refuses to boot; WorkOS in multi-user deployments belongs behind fluidbox SSO as a per-org IdP. Existing fluidbox SSO is byte-for-byte preserved (config C of the route matrix).
- **Generated-module content pipeline kept** — the web Docker build context is `apps/web` alone, so repo docs/CHANGELOG reach the app only through checked-in generated modules; the sync script gained search-index/changelog/edit-path outputs rather than a second pipeline appearing.
- **AuthKitProvider scoped to `/app`** (not the root layout, deviating from the boilerplate): public pages must not mount auth context; every conceivable `useAuth` consumer is under `/app`. Session badge is server-fed (`withAuth` in the layout), sign-out is a POST server action.

## Route matrix (enforced by `apps/web/scripts/verify-routes.mjs`)

| Surface | Routes | Auth | Indexed |
| --- | --- | --- | --- |
| Marketing | `/`, `/product`, `/open-source`, `/security`, `/changelog`, `/pricing` | none | yes |
| Docs | `/docs`, `/docs/<slug>`×14, `/docs/api`, `/docs/api/reference`, `api.html`, `openapi.yaml` | none | yes |
| App | `/app`, `/app/{agents,automations,capabilities,governance,integrations,sessions/[id],settings}` | gated | no (noindex + robots) |
| API | `/api/fluidbox/*` | per-call `withAuth()` in workos mode | no |
| Auth legs | `/login`, `/callback`, `/sign-in`, `/sign-up` | — | no |

Redirects (permanent): every pre-split dashboard path → `/app/…` (including the 2026-07 IA moves retargeted), `/developer/*` → `/docs/*` (reference → `/docs/api/reference`, quickstart → getting-started), `/docs/quickstart` → `/docs/getting-started`. Not redirectable: `/` itself (it became the homepage). Non-web touchpoints updated: `run-agent.sh` watch URL, post-login defaults `/`→`/app`, READMEs.

## Authentication boundary (fail closed, proven)

- Misconfigured workos mode (missing env) → **every request 500s** naming the missing variables (verified live).
- `sso+workos` → module-scope refusal (unit-tested).
- Unauthenticated `/app` navigation → 307 to AuthKit authorize (real + dummy-credential configs).
- Unauthenticated `/api/fluidbox/*` → `401 {"error":"unauthorized"}` on every method, validated in the route handler **before any control-plane credential attaches** — never a redirect.
- `/app` layout re-validates per document request (`force-dynamic`, so runtime config governs — a none-mode build serving a workos deployment still enforces).

## Live WorkOS verification (real environment, no fabrication)

Environment: CLI-provisioned unclaimed sandbox (`workos env provision`), redirect URI + homepage URL registered via `workos config …`; verified password user created over the API; **test users deleted afterwards**. Credentials + claim token preserved in the gitignored `apps/web/.env.local` (commented block).

| # | Goal scenario | Result |
| --- | --- | --- |
| 1 | Signed-out visitor reads every marketing + docs page | ✅ route matrix (45 public-route assertions ×3 configs) |
| 2 | Signed-out `/app` → WorkOS | ✅ live 307 → `…authkit.app` hosted sign-in |
| 3 | Auth returns to the requested route | ✅ landed back on `/app` (Overview) after password sign-in |
| 4 | Signed-in user navigates the existing app | ✅ live dashboard rendered real agents/run history through the gated proxy |
| 5 | Sign-out invalidates pages + APIs | ✅ post-signout `/app` demands sign-in (IdP session revoked too); API 401 |
| 6 | Direct API without session rejected | ✅ `401 {"error":"unauthorized"}` (GET + POST) |
| 7 | Public pages receive no private data | ✅ 200s with no session cookies; public pages call no authed APIs by construction |
| 8 | No WorkOS secrets in browser bundles | ✅ grep of `.next/static`: key value 0, var names 0, `sk_` prefix 0 |
| 9 | Existing dashboard workflows function | ✅ live Overview with real control-plane data; unit suite green |
| 10 | Docs contain no dead links | ✅ crawler: 32 URLs, 0 broken links/anchors (fixed en route: GitHub-convention heading anchors) |

## Verification runs

- `pnpm test` — **101/101** (new: `web-auth` matrix, `/app`-scoped gate, slugify convention; all pre-existing suites green).
- `pnpm typecheck` (`tsc --noEmit`) — clean. `pnpm build` — clean; 31 routes (marketing + docs static/SSG, app dynamic).
- `pnpm lint` — **9 pre-existing errors** in dashboard components (react-hooks strictness: RunComposer, PolicyRulesEditor, PolicyVersionHistory, AppPicker, two detail pages), untouched by design (behavioral-risk refactors out of scope); 0 findings in code this work added; 2 pre-existing warnings fixed.
- `node scripts/verify-routes.mjs` — ALL PASS (3 configurations).
- `node scripts/check-links.mjs` — 0 broken.
- Lighthouse (`lighthouse-*.report.{json,html}` here): **home 97 / 96 / 100 / 100**, **/docs 93 / 96 / 100 / 100** (perf/a11y/best-practices/SEO). Residual a11y: shiki `github-light` token colors in code blocks.
- Responsive: 375/768/1440 screenshots here; body never scrolls horizontally (fixed: code-block overflow, grid min-width floors). Keyboard: first Tab = visible skip link; all interactive elements native; search dialog has listbox/combobox semantics + arrow/enter/escape.
- Themes: dark + light captures for home and docs.

## Files changed

123 files, +28.4k/−0.25k lines from `db19dba` (88 in `apps/web` — the developer-docs engine commit included). Commits: docs tree + engine · design doc · `/app` move · WorkOS gate · docs platform · marketing site · SEO · verification/evidence.

## Remaining limitations (honest)

1. **Docker workos images need `NEXT_PUBLIC_WORKOS_REDIRECT_URI` as a build arg** (SDK reads it via an inlined expression); everything else is runtime env. Documented in `.env.example` + runbook.
2. **Lint carries 9 pre-existing hooks-strictness errors** (list above) — a follow-up refactor, not shipped noise.
3. **Shiki light-theme token contrast** keeps a11y at 96, not 100.
4. **fennec Staging API key** was not mintable programmatically (dashboard-only). Live e2e used a provisioned env instead; to move to Staging: mint a key in the WorkOS dashboard and swap `WORKOS_API_KEY`/`WORKOS_CLIENT_ID` (its redirect/logout URIs are already registered).
5. The old `/` dashboard URL cannot redirect (it *is* the homepage now); operators bookmarking `/` land one click from Sign in.
6. `sso+workos` composition deliberately unsupported (design §3).

## Running it

```bash
# Local (public site + open dashboard, unchanged default)
just web                      # or: pnpm -C apps/web dev · dashboard at /app

# Local behind WorkOS: uncomment the WorkOS block in apps/web/.env.local
# (this session provisioned working sandbox credentials there), then
pnpm -C apps/web build && pnpm -C apps/web start

# Verification
pnpm -C apps/web test && pnpm -C apps/web typecheck && pnpm -C apps/web build
node apps/web/scripts/verify-routes.mjs
pnpm -C apps/web start & node apps/web/scripts/check-links.mjs http://127.0.0.1:3000

# Production: deploy/web.Dockerfile (build-arg note above) or the Helm chart
# (ingress already catch-all; set FLUIDBOX_WEB_AUTH + WORKOS_* via web.extraEnv).
```
