# fluidbox dashboard

The Next.js UI for the fluidbox control plane. **Presentation-only by hard constraint** — every decision (policy, approvals, budgets, run lifecycle) lives in the Rust API; this app renders state and forwards intents.

## How it talks to the control plane

The browser never holds credentials. All API traffic goes through the server-side proxy at [`app/api/fluidbox/[...path]/route.ts`](./app/api/fluidbox/%5B...path%5D/route.ts), which forwards to the Rust server and injects the admin token from the environment:

| Variable (in `apps/web/.env.local`) | Purpose |
|---|---|
| `FLUIDBOX_API_URL` | where the control plane listens (default `http://127.0.0.1:8787`) |
| `FLUIDBOX_ADMIN_TOKEN` | bearer token for `/v1`, injected server-side — must match the repo-root `.env` |

`.env.local` is gitignored and **written for you by `just setup`** (run from the repo root), which keeps the token in sync with `.env`. If the dashboard suddenly 401s on everything, the token has drifted — re-run `just setup`, or `just doctor` to confirm.

## Developing

Use **pnpm**, never npm (npm's ERESOLVE errors here are a red herring).

```bash
pnpm install       # just setup does this too
pnpm dev           # dashboard only — the control plane must already be running
just dev           # (from the repo root) gateway + server + dashboard together
```

Open <http://localhost:3000>. Top-level routes: Runs `/` (home, with the approvals attention strip), Agents `/agents`, Capabilities `/capabilities`, Integrations `/integrations`, Automations `/automations`, Settings — run detail lives at `/sessions/{id}`.

## Gotchas

- **Never run `pnpm build` while `pnpm dev` is serving** — it corrupts the dev `.next` cache (stale CSS). Typecheck with `npx tsc --noEmit` instead, or restart dev after building.
- Pages that read `useSearchParams` (the tabbed pages) must stay wrapped in `<Suspense>` or the static build fails.
- This Next.js version has breaking changes vs. its predecessors — check `node_modules/next/dist/docs/` before assuming an API (see [`AGENTS.md`](./AGENTS.md)).
- Capabilities (tools an agent calls in-run, permission-gated) and Integrations (platforms agents work *on*: repo cloning, webhooks, publishing) are **different concepts** even when the same service appears in both — don't merge the pages.
