#!/usr/bin/env node
// Regenerates the dashboard's /developer content from docs/ at the repo root.
//
//   node scripts/sync-developer-docs.mjs          (or: just docs-sync)
//
// docs/ is the source of truth (authored for the Redocly toolchain and linted
// by `just docs-lint`); the dashboard renders a generated COPY so the web
// build stays self-contained — no fs reads at request time, no markdown
// dependency, no Redocly license. The generated module is checked in: a
// missing regeneration shows up as a diff, not as a broken page.
//
// Outputs:
//   app/developer/generated/content.ts    guide markdown as string exports
//   app/developer/generated/reference.ts  slim operation index from the spec
//   public/developer/openapi.yaml         the full spec, downloadable
//   public/developer/api.html             the full Redoc reference (schemas,
//                                         examples), one static self-contained
//                                         page served next to the app
//
// The in-app reference model stays slim (group → tag → operations with
// method/path/summary/description/security) — full request/response schemas
// render in api.html, which Redoc generates from the same bundle.

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Pinned: `latest` in a build path means a Redocly release can change lint
// results or the bundled output under us. Keep in sync with the justfile.
const REDOCLY = "@redocly/cli@2.41.2";

const webRoot = join(dirname(fileURLToPath(import.meta.url)), "..");
const repoRoot = join(webRoot, "..", "..");
const docsRoot = join(repoRoot, "docs");
const outDir = join(webRoot, "app", "developer", "generated");
const publicDir = join(webRoot, "public", "developer");

// ---------------------------------------------------------------- guides --
// Order here is presentation order on the hub. EVERY file in docs/guides/
// must be listed: guides cross-link each other by `<slug>.md`, and the
// MarkdownView href rewriter maps those onto /developer/<slug> routes — an
// unlisted guide turns each of those links into a 404 (a check below refuses).
const GUIDES = [
  { slug: "quickstart", file: "guides/quickstart.md", title: "Quickstart" },
  { slug: "authentication", file: "guides/authentication.md", title: "Authentication" },
  { slug: "governance", file: "guides/governance.md", title: "The permission gate" },
  { slug: "policies", file: "guides/policies.md", title: "Policies" },
  { slug: "capabilities", file: "guides/capabilities.md", title: "Capabilities" },
  { slug: "triggers", file: "guides/triggers.md", title: "Triggers & schedules" },
  { slug: "runner-contract", file: "guides/runner-contract.md", title: "Building a harness" },
  { slug: "kubernetes", file: "guides/kubernetes.md", title: "Kubernetes" },
];

// The hub card shows plain text, so inline markdown is stripped rather than
// rendered: keep the words, drop the markers.
const stripInline = (s) =>
  s
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*\s][^*]*)\*/g, "$1")
    .replace(/`([^`]*)`/g, "$1")
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1");

const guides = GUIDES.map(({ slug, file, title }) => {
  const md = readFileSync(join(docsRoot, file), "utf8");
  // Drop the H1 (the page renders its own header) and pull the first
  // paragraph as the hub-card blurb.
  const body = md.replace(/^#\s+.*\n+/, "");
  const firstPara = stripInline(body.split(/\n\n/)[0].replace(/\n/g, " ").trim());
  return { slug, title, blurb: firstPara, md: body };
});

// Refuse to generate a 404: every same-folder .md cross-link in a synced
// guide (or the hub's index.md) must resolve to a listed slug.
{
  const known = new Set(guides.map((g) => g.slug));
  const sources = [
    ...GUIDES.map((g) => ({ name: g.file, md: readFileSync(join(docsRoot, g.file), "utf8") })),
    { name: "index.md", md: readFileSync(join(docsRoot, "index.md"), "utf8") },
  ];
  for (const { name, md } of sources) {
    for (const m of md.matchAll(/\]\((?:\.\/)?(?:guides\/)?([a-z-]+)\.md(?:#[^)]*)?\)/g)) {
      if (!known.has(m[1])) {
        throw new Error(`${name} links to ${m[1]}.md, which is not in GUIDES — add it or the link 404s`);
      }
    }
  }
}

// The hub's "four planes" panel renders this section straight out of
// docs/index.md so the table exists in exactly one place. `---` rules delimit
// the sections there; the heading is dropped (the panel has its own title).
const indexMd = readFileSync(join(docsRoot, "index.md"), "utf8");
const planesHeading = "## The four planes";
const planesStart = indexMd.indexOf(planesHeading);
if (planesStart === -1) {
  throw new Error('docs/index.md no longer has a "## The four planes" section');
}
const planesRest = indexMd.slice(planesStart + planesHeading.length);
const planesEnd = planesRest.search(/\n---|\n## /);
const planesMd = (planesEnd === -1 ? planesRest : planesRest.slice(0, planesEnd)).trim();

// ------------------------------------------------------------- reference --
// Bundle the spec to JSON with the same CLI that lints it, so $refs resolve
// identically to the published reference.
const bundled = JSON.parse(
  execFileSync(
    "npx",
    ["--yes", REDOCLY, "bundle", "api/openapi.yaml", "--ext", "json"],
    { cwd: docsRoot, encoding: "utf8", maxBuffer: 64 * 1024 * 1024 }
  )
);

const tagMeta = new Map((bundled.tags ?? []).map((t) => [t.name, t.description ?? ""]));
const METHODS = ["get", "put", "post", "delete", "patch"];

const opsByTag = new Map();
for (const [path, item] of Object.entries(bundled.paths ?? {})) {
  for (const method of METHODS) {
    const op = item[method];
    if (!op) continue;
    const tag = op.tags?.[0] ?? "Other";
    if (!opsByTag.has(tag)) opsByTag.set(tag, []);
    // Operation-level security wins over the document default (adminToken).
    const security = (op.security ?? bundled.security ?? [])
      .flatMap((s) => Object.keys(s))
      .filter((v, i, a) => a.indexOf(v) === i);
    opsByTag.get(tag).push({
      id: op.operationId,
      method: method.toUpperCase(),
      path,
      summary: op.summary ?? "",
      description: op.description ?? "",
      security,
      public: (op.security ?? []).length === 0 && op.security !== undefined,
    });
  }
}

const groups = (bundled["x-tagGroups"] ?? []).map((g) => ({
  name: g.name,
  tags: g.tags
    .filter((t) => opsByTag.has(t))
    .map((t) => ({
      name: t,
      description: tagMeta.get(t) ?? "",
      operations: opsByTag.get(t),
    })),
}));

const opCount = [...opsByTag.values()].reduce((n, ops) => n + ops.length, 0);
const grouped = groups.flatMap((g) => g.tags).reduce((n, t) => n + t.operations.length, 0);
if (grouped !== opCount) {
  throw new Error(
    `tag groups cover ${grouped} of ${opCount} operations — a tag is missing from x-tagGroups`
  );
}

// ----------------------------------------------------------------- write --
mkdirSync(outDir, { recursive: true });
mkdirSync(publicDir, { recursive: true });

const banner = `// GENERATED by scripts/sync-developer-docs.mjs — do not edit.
// Source of truth: docs/ at the repo root. Regenerate with \`just docs-sync\`.
`;

writeFileSync(
  join(outDir, "content.ts"),
  `${banner}
export type Guide = { slug: string; title: string; blurb: string; md: string };

export const GUIDES: Guide[] = ${JSON.stringify(guides, null, 2)};

/** The "four planes" section of docs/index.md — intro, table, and the
 *  Kubernetes note — rendered verbatim on the developer hub. */
export const PLANES_MD: string = ${JSON.stringify(planesMd)};
`
);

writeFileSync(
  join(outDir, "reference.ts"),
  `${banner}
export type Operation = {
  id: string;
  method: string;
  path: string;
  summary: string;
  description: string;
  security: string[];
  public: boolean;
};
export type TagSection = { name: string; description: string; operations: Operation[] };
export type TagGroup = { name: string; tags: TagSection[] };

export const API_TITLE = ${JSON.stringify(bundled.info?.title ?? "API")};
export const API_VERSION = ${JSON.stringify(bundled.info?.version ?? "")};
export const OPERATION_COUNT = ${opCount};
export const GROUPS: TagGroup[] = ${JSON.stringify(groups, null, 2)};
`
);

copyFileSync(join(docsRoot, "api", "openapi.yaml"), join(publicDir, "openapi.yaml"));

// The full reference — request/response schemas, examples — as one static
// Redoc page. Served at /developer/api.html; the in-app browser links to it.
execFileSync(
  "npx",
  ["--yes", REDOCLY, "build-docs", "api/openapi.yaml", "-o", join(publicDir, "api.html")],
  { cwd: docsRoot, stdio: ["ignore", "inherit", "inherit"] }
);

console.log(
  `synced ${guides.length} guides, ${opCount} operations across ${groups.length} groups`
);
