#!/usr/bin/env node
// The public/private route matrix, asserted against a real `next start` in
// each deployment configuration. Run after `pnpm build`:
//
//   node scripts/verify-routes.mjs
//
// Three configurations:
//   A  admin + none    — local default: everything serves, /login → /app
//   B  admin + workos  — web-tier gate: /app redirects to AuthKit, the API
//                        proxy answers 401 JSON, public routes stay public
//   C  sso + none      — fluidbox SSO: /app navigations bounce to /login
//
// The control plane is deliberately NOT running: public pages must not need
// it, and the API assertions are about the WEB tier's own refusals. Dummy
// WorkOS values are used in B — the SDK builds its authorization URL locally,
// so the redirect proves the gate without any WorkOS account.

import { spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const PUBLIC_ROUTES = [
  "/",
  "/product",
  "/open-source",
  "/security",
  "/changelog",
  "/pricing",
  "/docs",
  "/docs/getting-started",
  "/docs/concepts",
  "/docs/api",
  "/docs/api/reference",
  "/robots.txt",
  "/sitemap.xml",
  "/og.png",
  "/docs/openapi.yaml",
];

const WORKOS_DUMMY = {
  FLUIDBOX_WEB_AUTH: "workos",
  WORKOS_API_KEY: "sk_test_dummy_key_for_route_matrix",
  WORKOS_CLIENT_ID: "client_01TESTTESTTESTTESTTESTTEST",
  WORKOS_COOKIE_PASSWORD: "route-matrix-dummy-password-32chars!!",
  NEXT_PUBLIC_WORKOS_REDIRECT_URI: "http://localhost:3211/callback",
};

let failures = 0;
const ok = (name, cond, extra = "") => {
  const mark = cond ? "ok " : "FAIL";
  if (!cond) failures += 1;
  console.log(`  ${mark}  ${name}${extra ? ` — ${extra}` : ""}`);
};

async function get(base, path) {
  const res = await fetch(`${base}${path}`, { redirect: "manual" });
  return { status: res.status, location: res.headers.get("location") ?? "", res };
}

async function startServer(port, env) {
  const child = spawn("pnpm", ["exec", "next", "start", "-p", String(port)], {
    env: { ...process.env, ...env, PORT: String(port) },
    stdio: ["ignore", "pipe", "pipe"],
  });
  let out = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (out += d));
  const base = `http://127.0.0.1:${port}`;
  for (let i = 0; i < 60; i++) {
    await sleep(500);
    try {
      await fetch(`${base}/robots.txt`);
      return { child, base, log: () => out };
    } catch {
      /* not up yet */
    }
  }
  child.kill("SIGKILL");
  throw new Error(`server on :${port} never came up\n${out}`);
}

async function stop(child) {
  child.kill("SIGTERM");
  await sleep(300);
  child.kill("SIGKILL");
  await sleep(200);
}

async function publicMatrix(base, label) {
  for (const path of PUBLIC_ROUTES) {
    const { status, res } = await get(base, path);
    const setCookie = res.headers.get("set-cookie") ?? "";
    ok(`${label} GET ${path} → 200, no session cookie`, status === 200 && !/wos-session|fbx_web/.test(setCookie), `got ${status}`);
  }
}

// ── A: admin + none ─────────────────────────────────────────────────────────
console.log("\nConfiguration A — FLUIDBOX_WEB_MODE=admin, FLUIDBOX_WEB_AUTH unset");
{
  const { child, base } = await startServer(3210, {});
  try {
    await publicMatrix(base, "A");
    let r = await get(base, "/app");
    ok("A GET /app → 200 (admin mode is open by design)", r.status === 200, `got ${r.status}`);
    r = await get(base, "/login");
    ok("A GET /login → redirect to /app", r.status >= 300 && r.status < 400 && r.location.includes("/app"), `${r.status} ${r.location}`);
    r = await get(base, "/agents");
    ok("A GET /agents → permanent redirect to /app/agents", r.status === 308 && r.location.includes("/app/agents"), `${r.status} ${r.location}`);
    r = await get(base, "/developer/quickstart");
    ok("A GET /developer/quickstart → /docs/getting-started", r.status === 308 && r.location.includes("/docs/getting-started"), `${r.status} ${r.location}`);
    r = await get(base, "/sessions/abc123");
    ok("A GET /sessions/{id} → /app/sessions/{id}", r.status === 308 && r.location.includes("/app/sessions/abc123"), `${r.status} ${r.location}`);
  } finally {
    await stop(child);
  }
}

// ── B: admin + workos ───────────────────────────────────────────────────────
console.log("\nConfiguration B — FLUIDBOX_WEB_AUTH=workos (dummy credentials)");
{
  const { child, base } = await startServer(3211, WORKOS_DUMMY);
  try {
    await publicMatrix(base, "B");
    let r = await get(base, "/app");
    ok(
      "B GET /app (signed out) → redirect into AuthKit authorize",
      r.status >= 300 && r.status < 400 && /authorize|authkit|workos/.test(r.location),
      `${r.status} ${r.location.slice(0, 90)}`
    );
    r = await get(base, "/app/sessions/deep123");
    ok("B deep link also gates", r.status >= 300 && r.status < 400 && /authorize|authkit|workos/.test(r.location), `${r.status}`);
    const api = await fetch(`${base}/api/fluidbox/approvals`, { redirect: "manual" });
    const body = await api.text();
    ok(
      "B GET /api/fluidbox/* (no session) → 401 JSON, never a redirect",
      api.status === 401 && body.includes("unauthorized"),
      `${api.status} ${body.slice(0, 60)}`
    );
    const post = await fetch(`${base}/api/fluidbox/sessions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
      redirect: "manual",
    });
    ok("B POST /api/fluidbox/* (no session) → 401", post.status === 401, `${post.status}`);
  } finally {
    await stop(child);
  }
}

// ── C: sso + none ───────────────────────────────────────────────────────────
console.log("\nConfiguration C — FLUIDBOX_WEB_MODE=sso");
{
  const { child, base } = await startServer(3212, { FLUIDBOX_WEB_MODE: "sso" });
  try {
    await publicMatrix(base, "C");
    let r = await get(base, "/app");
    ok("C GET /app (no session) → /login", r.status >= 300 && r.status < 400 && r.location.includes("/login"), `${r.status} ${r.location}`);
    r = await get(base, "/app/agents?x=1");
    ok(
      "C deep link carries next=",
      r.status >= 300 && r.status < 400 && r.location.includes("next=%2Fapp%2Fagents"),
      `${r.status} ${r.location}`
    );
    r = await get(base, "/login");
    ok("C GET /login → 200 (the form renders)", r.status === 200, `${r.status}`);
  } finally {
    await stop(child);
  }
}

console.log(failures === 0 ? "\nroute matrix: ALL PASS" : `\nroute matrix: ${failures} FAILURES`);
process.exit(failures === 0 ? 0 : 1);
