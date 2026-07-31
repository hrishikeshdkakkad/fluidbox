#!/usr/bin/env node
// Broken-link crawl of the PUBLIC surface. Run against a serving build:
//
//   node scripts/check-links.mjs http://127.0.0.1:3000
//
// Crawls same-origin pages reachable from the marketing + docs seeds, checks
// every internal href resolves (200), and validates in-page anchors (a
// #fragment must match an id on the target page). The auth surfaces (/app,
// /login, /api, /callback, /sign-*) are deliberately out of scope — they are
// not public, and the route matrix covers their behavior.

const BASE = process.argv[2] || "http://127.0.0.1:3000";
const SEEDS = ["/", "/product", "/open-source", "/security", "/changelog", "/pricing", "/docs"];
const SKIP = /^\/(app|api|login|callback|sign-in|sign-up|v1)(\/|$)/;

const queue = [...SEEDS];
const seen = new Set(queue);
const pages = new Map(); // path -> { ids: Set, links: [{href, from}] }
const broken = [];

function hrefsOf(html) {
  return [...html.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
}
function idsOf(html) {
  return new Set([...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
}

while (queue.length > 0) {
  const path = queue.shift();
  const res = await fetch(`${BASE}${path}`, { redirect: "follow" });
  if (!res.ok) {
    broken.push(`${path} → ${res.status}`);
    continue;
  }
  const type = res.headers.get("content-type") ?? "";
  if (!type.includes("text/html")) {
    pages.set(path, { ids: new Set(), links: [] });
    continue;
  }
  const html = await res.text();
  const links = [];
  for (const raw of hrefsOf(html)) {
    if (/^(https?:|mailto:|#$)/.test(raw)) continue;
    links.push(raw);
    const [p] = raw.split("#");
    if (p && p.startsWith("/") && !SKIP.test(p) && !seen.has(p)) {
      seen.add(p);
      queue.push(p);
    }
  }
  pages.set(path, { ids: idsOf(html), links });
  if (pages.size > 300) break; // runaway guard
}

// Second pass: anchors. "#x" targets the same page; "/p#x" targets page p.
for (const [path, { links }] of pages) {
  for (const raw of links) {
    const [p, frag] = raw.split("#");
    if (frag === undefined || frag === "") continue;
    const target = p === "" ? path : p;
    if (SKIP.test(target)) continue;
    const targetPage = pages.get(target);
    if (!targetPage) continue; // asset or non-HTML — status already checked
    if (!targetPage.ids.has(frag)) {
      broken.push(`${path} → ${raw} (no id "${frag}" on ${target})`);
    }
  }
}

console.log(`crawled ${pages.size} URLs from ${SEEDS.length} seeds`);
if (broken.length > 0) {
  console.log(`BROKEN (${broken.length}):`);
  for (const b of broken) console.log(`  ${b}`);
  process.exit(1);
}
console.log("no broken internal links or anchors");
